#!/usr/bin/env python3
"""
Chainguard CVE Vulnerability Scanner and Reporter

This tool scans container images using Grype and generates an HTML report
comparing customer images with Chainguard alternatives.
"""

import argparse
import json
import subprocess
import sys
import os
from typing import Dict, List, Optional, Tuple, NamedTuple
import logging
from dataclasses import dataclass
from pathlib import Path
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityData:
    """Container for vulnerability scan results"""
    image_name: str
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    vulnerabilities: List[Dict]
    scan_successful: bool = True
    error_message: str = ""
    was_retried: bool = False
    original_image_name: str = ""

class ImagePair(NamedTuple):
    """Container for image pair data"""
    chainguard_image: str
    customer_image: str

@dataclass
class ScanResult:
    """Container for paired scan results"""
    image_pair: ImagePair
    chainguard_data: VulnerabilityData
    customer_data: VulnerabilityData
    scan_successful: bool = True
    error_message: str = ""

class CVEScanner:
    """Main CVE scanning and reporting class"""
    
    SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']
    CHAINGUARD_LOGO_URL = "Linky_White.png"
    
    def __init__(self):
        self.failed_scans = []
        self.failed_rows = []
        self._lock = threading.Lock()
        
    def check_grype_installation(self) -> bool:
        """Check if Grype is installed and accessible"""
        try:
            result = subprocess.run(['grype', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Grype version: {result.stdout.strip()}")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.error("Grype is not installed or not accessible. Please install Grype first.")
        return False
    
    def scan_image(self, image_name: str) -> VulnerabilityData:
        """Scan a single image with Grype and return vulnerability data"""
        return self._scan_image_with_retry(image_name, retry=True)
    
    def _scan_image_with_retry(self, image_name: str, retry: bool = True) -> VulnerabilityData:
        """Internal method to scan image with optional retry logic"""
        logger.info(f"Scanning image: {image_name}")
        original_image_name = image_name
        
        try:
            # Run grype scan with JSON output
            cmd = ['grype', '-o', 'json', image_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                # If scan failed and retry is enabled, try with :latest tag
                if retry and not image_name.endswith(':latest'):
                    logger.info(f"Initial scan failed for {image_name}, retrying with :latest tag")
                    # If image has no tag, add :latest; if it has a tag, replace with :latest
                    if ':' in image_name:
                        base_image = image_name.split(':')[0]
                        latest_image = f"{base_image}:latest"
                    else:
                        latest_image = f"{image_name}:latest"
                    retry_result = self._scan_image_with_retry(latest_image, retry=False)
                    
                    if retry_result.scan_successful:
                        logger.info(f"Retry successful for {latest_image}")
                        return VulnerabilityData(
                            image_name=retry_result.image_name,
                            total_vulnerabilities=retry_result.total_vulnerabilities,
                            severity_breakdown=retry_result.severity_breakdown,
                            vulnerabilities=retry_result.vulnerabilities,
                            scan_successful=True,
                            was_retried=True,
                            original_image_name=original_image_name
                        )
                
                error_msg = f"Grype scan failed for {image_name}: {result.stderr}"
                logger.error(error_msg)
                self.failed_scans.append(original_image_name)
                return VulnerabilityData(
                    image_name=image_name,
                    total_vulnerabilities=0,
                    severity_breakdown={},
                    vulnerabilities=[],
                    scan_successful=False,
                    error_message=error_msg,
                    original_image_name=original_image_name
                )
            
            # Parse JSON output
            scan_data = json.loads(result.stdout)
            vulnerabilities = scan_data.get('matches', [])
            
            # Count vulnerabilities by severity
            severity_breakdown = {severity: 0 for severity in self.SEVERITY_ORDER}
            for vuln in vulnerabilities:
                severity = vuln.get('vulnerability', {}).get('severity', 'Unknown')
                if severity in severity_breakdown:
                    severity_breakdown[severity] += 1
                else:
                    severity_breakdown['Unknown'] += 1
            
            total_vulns = sum(severity_breakdown.values())
            logger.info(f"Found {total_vulns} vulnerabilities in {image_name}")
            
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=total_vulns,
                severity_breakdown=severity_breakdown,
                vulnerabilities=vulnerabilities,
                original_image_name=original_image_name or image_name
            )
            
        except subprocess.TimeoutExpired:
            # If scan timed out and retry is enabled, try with :latest tag
            if retry and not image_name.endswith(':latest'):
                logger.info(f"Scan timeout for {image_name}, retrying with :latest tag")
                # If image has no tag, add :latest; if it has a tag, replace with :latest
                if ':' in image_name:
                    base_image = image_name.split(':')[0]
                    latest_image = f"{base_image}:latest"
                else:
                    latest_image = f"{image_name}:latest"
                retry_result = self._scan_image_with_retry(latest_image, retry=False)
                
                if retry_result.scan_successful:
                    logger.info(f"Retry successful for {latest_image}")
                    return VulnerabilityData(
                        image_name=retry_result.image_name,
                        total_vulnerabilities=retry_result.total_vulnerabilities,
                        severity_breakdown=retry_result.severity_breakdown,
                        vulnerabilities=retry_result.vulnerabilities,
                        scan_successful=True,
                        was_retried=True,
                        original_image_name=original_image_name
                    )
            
            error_msg = f"Scan timeout for {image_name}"
            logger.error(error_msg)
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=error_msg,
                original_image_name=original_image_name
            )
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse Grype output for {image_name}: {e}"
            logger.error(error_msg)
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=error_msg,
                original_image_name=original_image_name
            )
        except Exception as e:
            error_msg = f"Unexpected error scanning {image_name}: {e}"
            logger.error(error_msg)
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=error_msg,
                original_image_name=original_image_name
            )
    
    def scan_image_pair(self, image_pair: ImagePair) -> ScanResult:
        """Scan both images in a pair and return combined result"""
        logger.info(f"Scanning pair: {image_pair.chainguard_image} vs {image_pair.customer_image}")
        
        # Scan both images
        chainguard_result = self.scan_image(image_pair.chainguard_image)
        customer_result = self.scan_image(image_pair.customer_image)
        
        # Check if both scans were successful
        if not chainguard_result.scan_successful or not customer_result.scan_successful:
            error_messages = []
            if not chainguard_result.scan_successful:
                error_messages.append(f"Chainguard image failed: {chainguard_result.error_message}")
            if not customer_result.scan_successful:
                error_messages.append(f"Customer image failed: {customer_result.error_message}")
            
            error_msg = "; ".join(error_messages)
            
            with self._lock:
                self.failed_rows.append(f"{image_pair.chainguard_image} | {image_pair.customer_image}")
            
            logger.warning(f"Row failed - {error_msg}")
            
            return ScanResult(
                image_pair=image_pair,
                chainguard_data=chainguard_result,
                customer_data=customer_result,
                scan_successful=False,
                error_message=error_msg
            )
        
        logger.info(f"Row completed successfully: {chainguard_result.total_vulnerabilities} vs {customer_result.total_vulnerabilities} vulnerabilities")
        
        return ScanResult(
            image_pair=image_pair,
            chainguard_data=chainguard_result,
            customer_data=customer_result,
            scan_successful=True
        )
    
    def scan_image_pairs_parallel(self, image_pairs: List[ImagePair], max_workers: int = 4) -> List[ScanResult]:
        """Scan multiple image pairs in parallel"""
        logger.info(f"Scanning {len(image_pairs)} image pairs with {max_workers} workers")
        
        successful_results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan jobs
            future_to_pair = {
                executor.submit(self.scan_image_pair, pair): pair 
                for pair in image_pairs
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_pair):
                pair = future_to_pair[future]
                try:
                    result = future.result()
                    if result.scan_successful:
                        successful_results.append(result)
                    else:
                        logger.warning(f"Skipping failed row: {pair.chainguard_image} | {pair.customer_image}")
                except Exception as e:
                    error_msg = f"Unexpected error scanning pair {pair.chainguard_image} | {pair.customer_image}: {e}"
                    logger.error(error_msg)
                    with self._lock:
                        self.failed_rows.append(f"{pair.chainguard_image} | {pair.customer_image}")
        
        logger.info(f"Successfully scanned {len(successful_results)} of {len(image_pairs)} pairs")
        return successful_results
    
    def parse_image_pairs_from_file(self, file_path: str) -> List[ImagePair]:
        """Parse image pairs from a two-column file format (supports CSV and whitespace-separated)"""
        image_pairs = []
        
        # Determine if it's a CSV file
        is_csv = file_path.lower().endswith('.csv')
        
        with open(file_path, 'r') as f:
            if is_csv:
                # Parse as CSV
                csv_reader = csv.reader(f)
                for line_num, row in enumerate(csv_reader, 1):
                    # Skip empty rows
                    if not row or len(row) == 0:
                        continue
                    
                    # Skip header row if it contains common header keywords
                    if line_num == 1 and len(row) >= 2:
                        if any(keyword in str(row[0]).lower() for keyword in ['chainguard', 'customer', 'image']) or \
                           any(keyword in str(row[1]).lower() for keyword in ['chainguard', 'customer', 'image']):
                            continue
                    
                    # Skip comment rows (first cell starts with #)
                    if str(row[0]).strip().startswith('#'):
                        continue
                    
                    if len(row) < 2:
                        logger.warning(f"CSV row {line_num}: Expected at least 2 columns, got {len(row)}. Skipping.")
                        continue
                    
                    chainguard_image = str(row[0]).strip()
                    customer_image = str(row[1]).strip()
                    
                    if chainguard_image and customer_image:
                        image_pairs.append(ImagePair(chainguard_image, customer_image))
            else:
                # Parse as whitespace-separated format
                lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Skip header line if it contains common header keywords
                    if any(keyword in line.lower() for keyword in ['chainguard', 'customer', 'image']):
                        continue
                    
                    # Split by whitespace (tabs or multiple spaces)
                    parts = line.split()
                    
                    if len(parts) != 2:
                        logger.warning(f"Line {line_num}: Expected 2 columns, got {len(parts)}. Skipping: {line}")
                        continue
                    
                    chainguard_image, customer_image = parts
                    image_pairs.append(ImagePair(chainguard_image, customer_image))
        
        return image_pairs
    
    def find_chainguard_equivalent(self, customer_image: str) -> str:
        """Find the Chainguard equivalent for a customer image (legacy mode)"""
        # Simple mapping logic for legacy mode
        base_image = customer_image.split(':')[0].split('/')[-1]
        
        # Common Chainguard image mappings
        chainguard_mappings = {
            'nginx': 'cgr.dev/chainguard/nginx',
            'python': 'cgr.dev/chainguard/python',
            'node': 'cgr.dev/chainguard/node',
            'alpine': 'cgr.dev/chainguard/alpine-base',
            'ubuntu': 'cgr.dev/chainguard/alpine-base',
            'redis': 'cgr.dev/chainguard/redis',
            'postgres': 'cgr.dev/chainguard/postgres',
            'mysql': 'cgr.dev/chainguard/mysql',
            'golang': 'cgr.dev/chainguard/go',
            'java': 'cgr.dev/chainguard/jre',
            'openjdk': 'cgr.dev/chainguard/jre',
        }
        
        for key, chainguard_image in chainguard_mappings.items():
            if key in base_image.lower():
                return chainguard_image
        
        # Default fallback
        return f"cgr.dev/chainguard/{base_image}"
    
    def parse_source_input(self, source: str) -> Tuple[List[str], List[ImagePair]]:
        """Parse source input - returns (legacy_images, image_pairs)"""
        if os.path.isfile(source):
            # Try to parse as two-column format first
            try:
                image_pairs = self.parse_image_pairs_from_file(source)
                if image_pairs:
                    logger.info(f"Parsed {len(image_pairs)} image pairs from file")
                    return [], image_pairs
            except Exception as e:
                logger.warning(f"Failed to parse as image pairs, trying legacy format: {e}")
            
            # Fallback to legacy single-column format
            with open(source, 'r') as f:
                images = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return images, []
        else:
            # Single image or comma-separated list (legacy format)
            images = [img.strip() for img in source.split(',') if img.strip()]
            return images, []
    
    def load_exec_summary(self, exec_file: Optional[str], metrics: Dict = None, customer_name: Optional[str] = None) -> str:
        """Load and convert markdown executive summary to HTML with data interpolation"""
        if not exec_file or not os.path.isfile(exec_file):
            # Default summary with dynamic data if available
            if metrics:
                return f"""
                <h2>Executive Summary</h2>
                <p>This report compares the vulnerability exposure between your current container images 
                and Chainguard's hardened alternatives. Analysis of {metrics['images_scanned']} image pairs 
                shows a <strong>{metrics['reduction_percentage']}% overall CVE reduction</strong>, with 
                {metrics['total_reduction']} fewer vulnerabilities when using Chainguard images.</p>
                <p>Chainguard images are built with security-first principles, utilizing minimal base images 
                and eliminating unnecessary components to significantly reduce your attack surface.</p>
                """
            else:
                return """
                <h2>Executive Summary</h2>
                <p>This report compares the vulnerability exposure between your current container images 
                and Chainguard's hardened alternatives. Chainguard images are built with security-first 
                principles, utilizing minimal base images and eliminating unnecessary components to 
                significantly reduce your attack surface.</p>
                """
        
        try:
            with open(exec_file, 'r') as f:
                md_content = f.read()
            
            # Replace template variables if metrics are provided
            if metrics:
                md_content = self._interpolate_template_variables(md_content, metrics, customer_name)
            
            if MARKDOWN_AVAILABLE:
                return markdown.markdown(md_content)
            else:
                # Simple markdown to HTML conversion for basic functionality
                html_content = md_content
                html_content = re.sub(r'^# (.*)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'^## (.*)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'^### (.*)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
                html_content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html_content)
                html_content = re.sub(r'^- (.*)$', r'<li>\1</li>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'(<li>.*?</li>(?:\n<li>.*?</li>)*)', r'<ul>\1</ul>', html_content, flags=re.DOTALL)
                html_content = re.sub(r'\n\n', '</p><p>', html_content)
                html_content = f'<p>{html_content}</p>'
                # Fix paragraph tags around lists
                html_content = re.sub(r'<p>(<ul>.*?</ul>)</p>', r'\1', html_content, flags=re.DOTALL)
                return html_content
        except Exception as e:
            logger.warning(f"Failed to load executive summary: {e}")
            return "<p>Failed to load executive summary.</p>"
    
    def _interpolate_template_variables(self, content: str, metrics: Dict, customer_name: Optional[str] = None) -> str:
        """Replace template variables in content with actual metrics and customer info"""
        replacements = {
            '{{images_scanned}}': str(metrics['images_scanned']),
            '{{total_customer_vulns}}': str(metrics['total_customer_vulns']),
            '{{total_chainguard_vulns}}': str(metrics['total_chainguard_vulns']),
            '{{total_reduction}}': str(metrics['total_reduction']),
            '{{reduction_percentage}}': f"{metrics['reduction_percentage']}%",
            '{{average_reduction_per_image}}': f"{metrics['average_reduction_per_image']}%",
            '{{images_with_reduction}}': str(metrics['images_with_reduction']),
            '{{customer_name}}': customer_name or "Customer"
        }
        
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)
        
        return content
    
    def generate_html_report(self, scan_results: List[ScanResult], 
                           exec_file: Optional[str], output_file: str, 
                           appendix_file: Optional[str] = None, 
                           customer_name: Optional[str] = None):
        """Generate the HTML report"""
        logger.info("Generating HTML report...")
        
        # Calculate CVE reduction metrics
        metrics = self.calculate_cve_reduction_metrics(scan_results)
        
        # Load executive summary and appendix with metrics data
        exec_summary = self.load_exec_summary(exec_file, metrics, customer_name)
        appendix_content = self.load_appendix(appendix_file, metrics, customer_name)
        
        # Extract data from scan results
        customer_data = [result.customer_data for result in scan_results]
        chainguard_data = [result.chainguard_data for result in scan_results]
        
        # Calculate totals and summaries
        customer_total = sum(data.total_vulnerabilities for data in customer_data)
        chainguard_total = sum(data.total_vulnerabilities for data in chainguard_data)
        
        customer_summary = {severity: 0 for severity in self.SEVERITY_ORDER}
        chainguard_summary = {severity: 0 for severity in self.SEVERITY_ORDER}
        
        for data in customer_data:
            for severity, count in data.severity_breakdown.items():
                customer_summary[severity] += count
        
        for data in chainguard_data:
            for severity, count in data.severity_breakdown.items():
                chainguard_summary[severity] += count
        
        # Create image pairs for comparison table from scan results
        image_pairs = []
        for result in scan_results:
            image_pairs.append({
                'customer': result.customer_data,
                'chainguard': result.chainguard_data
            })
        
        # Embed CSS content directly
        css_content = self._get_embedded_css()
        
        # Generate HTML optimized for PDF conversion
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Chainguard Vulnerability Report</title>
    <style>
{css_content}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-section">
            <img class="header-logo" src="{self.CHAINGUARD_LOGO_URL}" alt="Chainguard Logo">
            <h1>Vulnerability Comparison Report</h1>
            <p>A comprehensive analysis comparing vulnerabilities in your container images versus Chainguard's hardened alternatives.</p>
        </div>

        <!-- Executive Summary -->
        <div class="image-comparison-section no-break">
            <h2>Executive Summary</h2>
            {exec_summary}
        </div>

        <!-- CVE Reduction Metrics -->
        <div class="image-comparison-section no-break">
            <h2>CVE Reduction Analysis</h2>
            <div style="text-align: center; margin-bottom: 30px;">
                <div class="total-box reduction-box" style="display: block; margin: 0 auto 20px auto; width: 300px;">
                    {metrics['reduction_percentage']}%
                    <span>CVE Reduction</span>
                </div>
                <p style="text-align: center; margin: 0; font-size: 16px; color: var(--cg-primary);"><strong>{metrics['total_reduction']}</strong> fewer vulnerabilities with Chainguard images</p>
            </div>
            
            <!-- Overview Section within CVE Reduction Analysis -->
            <div class="overview-grid" style="margin-top: 40px;">
                <!-- Customer Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Your Images</h2>
                        <div class="total-box customer-total">
                            {customer_total}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_boxes(customer_summary)}
                    </div>
                </div>

                <!-- Chainguard Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Chainguard Images</h2>
                        <div class="total-box chainguard-total">
                            {chainguard_total}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_boxes(chainguard_summary)}
                    </div>
                </div>
            </div>
        </div>

        <!-- Image Comparison Table -->
        <div class="image-comparison-section">
            <h2>Images Scanned</h2>
            <div class="image-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Your Image</th>
                            <th>Total Vulnerabilities</th>
                            <th>Chainguard Image</th>
                            <th>Total Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_comparison_table_rows(image_pairs)}
                    </tbody>
                </table>
            </div>
            <div class="table-legend">
                <div class="legend-section">
                    <p class="legend-note">
                        <span class="legend-icon">*</span>
                        Images marked with an asterisk were retried with the :latest tag after initial scan failure.
                    </p>
                </div>
            </div>
        </div>

        {self._generate_failed_scans_section()}
        
        <!-- Appendix Section -->
        <div class="appendix-content">
            <h2>Appendix</h2>
            {appendix_content}
            
            <!-- Footer integrated within appendix container -->
            <div class="footer">
                <p>This report is {customer_name or "Customer"} & Chainguard Confidential | Generated on {self._get_current_datetime()}</p>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        # Clean up chainguard-private references in the HTML content
        html_content = html_content.replace("chainguard-private", "chainguard")
        
        # Write HTML file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
    
    def _generate_severity_boxes(self, summary: Dict[str, int]) -> str:
        """Generate HTML for severity summary table"""
        rows = []
        for severity in self.SEVERITY_ORDER:
            count = summary.get(severity, 0)
            rows.append(f'''                                <tr>
                                    <td><span class="severity-indicator {severity.lower()}"></span>{severity}</td>
                                    <td class="severity-count">{count}</td>
                                </tr>''')
        
        table_html = f'''<table class="summary-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
{chr(10).join(rows)}
                            </tbody>
                        </table>'''
        return table_html
    
    def _generate_comparison_table_rows(self, image_pairs: List[Dict]) -> str:
        """Generate HTML table rows for image comparisons"""
        rows = []
        for pair in image_pairs:
            customer = pair['customer']
            chainguard = pair['chainguard']
            
            # Add asterisk for retried images
            customer_display_name = self._get_display_name(customer)
            chainguard_display_name = self._get_display_name(chainguard) if chainguard else "No corresponding image found"
            
            # Format vulnerability breakdowns
            customer_breakdown = self._format_vulnerability_breakdown(customer)
            chainguard_breakdown = self._format_vulnerability_breakdown(chainguard) if chainguard else "-"
            chainguard_class = "" if chainguard else ' class="no-match"'
            
            rows.append(f"""
                <tr class="image-comparison-row">
                    <td class="image-name-cell">
                        <code class="image-name">{customer_display_name}</code>
                    </td>
                    <td class="vulnerability-count">{customer_breakdown}</td>
                    <td class="image-name-cell{chainguard_class}">
                        {'<code class="image-name">' + chainguard_display_name + '</code>' if chainguard else '<span class="no-match">' + chainguard_display_name + '</span>'}
                    </td>
                    <td class="vulnerability-count{chainguard_class}">
                        {'<span class="no-match">' + str(chainguard_breakdown) + '</span>' if not chainguard else str(chainguard_breakdown)}
                    </td>
                </tr>
            """)
        return ''.join(rows)
    
    def _get_display_name(self, vuln_data: VulnerabilityData) -> str:
        """Get display name for image with asterisk if retried"""
        if vuln_data.was_retried:
            return f"{vuln_data.original_image_name}*"
        return vuln_data.image_name
    
    def _format_vulnerability_breakdown(self, vuln_data: VulnerabilityData) -> str:
        """Format vulnerability count as simple total number"""
        if not vuln_data.scan_successful:
            return "-"
        
        return str(vuln_data.total_vulnerabilities)
    
    def calculate_cve_reduction_metrics(self, scan_results: List[ScanResult]) -> Dict:
        """Calculate CVE reduction metrics from scan results"""
        if not scan_results:
            return {
                'total_customer_vulns': 0,
                'total_chainguard_vulns': 0,
                'total_reduction': 0,
                'reduction_percentage': 0.0,
                'average_reduction_per_image': 0.0,
                'images_with_reduction': 0,
                'images_scanned': 0
            }
        
        total_customer_vulns = sum(result.customer_data.total_vulnerabilities for result in scan_results)
        total_chainguard_vulns = sum(result.chainguard_data.total_vulnerabilities for result in scan_results)
        total_reduction = total_customer_vulns - total_chainguard_vulns
        
        # Calculate percentage reduction
        reduction_percentage = 0.0
        if total_customer_vulns > 0:
            reduction_percentage = (total_reduction / total_customer_vulns) * 100
        
        # Calculate per-image metrics
        images_with_reduction = 0
        total_image_reductions = 0
        
        for result in scan_results:
            customer_vulns = result.customer_data.total_vulnerabilities
            chainguard_vulns = result.chainguard_data.total_vulnerabilities
            
            if customer_vulns > chainguard_vulns:
                images_with_reduction += 1
                if customer_vulns > 0:
                    image_reduction_pct = ((customer_vulns - chainguard_vulns) / customer_vulns) * 100
                    total_image_reductions += image_reduction_pct
        
        average_reduction_per_image = 0.0
        if images_with_reduction > 0:
            average_reduction_per_image = total_image_reductions / images_with_reduction
        
        return {
            'total_customer_vulns': total_customer_vulns,
            'total_chainguard_vulns': total_chainguard_vulns,
            'total_reduction': total_reduction,
            'reduction_percentage': round(reduction_percentage, 1),
            'average_reduction_per_image': round(average_reduction_per_image, 1),
            'images_with_reduction': images_with_reduction,
            'images_scanned': len(scan_results)
        }
    
    def _generate_failed_scans_section(self) -> str:
        """Generate HTML section for failed scans - now returns empty string"""
        # Failed scans are now only reported in CLI output, not in HTML
        return ""
    
    def load_appendix(self, appendix_file: Optional[str], metrics: Dict = None, customer_name: Optional[str] = None) -> str:
        """Load and convert markdown appendix to HTML with data interpolation"""
        
        # Default appendix content with strategic continuation headers for page breaks
        default_content = """
                <div class="appendix-section">
                    <h3>Methodology</h3>
                    <p>This report was generated using the following methodology:</p>
                    <ul>
                        <li><strong>Scanning Tool:</strong> Grype vulnerability scanner</li>
                        <li><strong>Data Sources:</strong> National Vulnerability Database (NVD) and other security databases</li>
                        <li><strong>Image Analysis:</strong> Container images were scanned for known vulnerabilities</li>
                        <li><strong>Comparison:</strong> Customer images compared against Chainguard hardened alternatives</li>
                    </ul>
                </div>
                
                <!-- Strategic page break marker with continuation header -->
                <div class="appendix-page-break">
                    <h2 class="appendix-continuation">Appendix (continued)</h2>
                </div>
                
                <div class="appendix-section">
                    <h3>Severity Levels</h3>
                    <p>Vulnerabilities are classified using the following severity levels:</p>
                    <ul>
                        <li><strong>Critical:</strong> Vulnerabilities with CVSS scores of 9.0-10.0</li>
                        <li><strong>High:</strong> Vulnerabilities with CVSS scores of 7.0-8.9</li>
                        <li><strong>Medium:</strong> Vulnerabilities with CVSS scores of 4.0-6.9</li>
                        <li><strong>Low:</strong> Vulnerabilities with CVSS scores of 0.1-3.9</li>
                        <li><strong>Negligible:</strong> Vulnerabilities with minimal impact</li>
                        <li><strong>Unknown:</strong> Vulnerabilities without assigned severity scores</li>
                    </ul>
                </div>
                
                <div class="appendix-section">
                    <h3>About Chainguard Images</h3>
                    <p>Chainguard Images are container images built with security-first principles:</p>
                    <ul>
                        <li><strong>Minimal Base:</strong> Built on minimal base images to reduce attack surface</li>
                        <li><strong>Distroless:</strong> Contains only application dependencies, no package managers</li>
                        <li><strong>Regular Updates:</strong> Continuously updated with latest security patches</li>
                        <li><strong>Zero CVEs:</strong> Many images maintain zero known vulnerabilities</li>
                        <li><strong>SBOM Included:</strong> Software Bill of Materials for transparency</li>
                        <li><strong>Provenance Tracking:</strong> Complete software supply chain transparency with cryptographic attestations and verifiable build processes</li>
                    </ul>
                </div>"""
        
        if not appendix_file or not os.path.isfile(appendix_file):
            # Return only default content if no custom appendix
            return f"<div>{default_content}</div>"
        
        try:
            with open(appendix_file, 'r') as f:
                md_content = f.read()
            
            # Replace template variables if metrics are provided
            if metrics:
                md_content = self._interpolate_template_variables(md_content, metrics, customer_name)
            
            # Convert custom appendix content to HTML
            if MARKDOWN_AVAILABLE:
                custom_content = markdown.markdown(md_content)
            else:
                # Simple markdown to HTML conversion for basic functionality
                html_content = md_content
                html_content = re.sub(r'^# (.*)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'^## (.*)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'^### (.*)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
                html_content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html_content)
                html_content = re.sub(r'^- (.*)$', r'<li>\1</li>', html_content, flags=re.MULTILINE)
                html_content = re.sub(r'(<li>.*?</li>(?:\n<li>.*?</li>)*)', r'<ul>\1</ul>', html_content, flags=re.DOTALL)
                html_content = re.sub(r'\n\n', '</p><p>', html_content)
                html_content = f'<p>{html_content}</p>'
                # Fix paragraph tags around lists
                html_content = re.sub(r'<p>(<ul>.*?</ul>)</p>', r'\1', html_content, flags=re.DOTALL)
                custom_content = html_content
            
            # Combine custom content (above) with default content
            return f"<div>{custom_content}{default_content}</div>"
            
        except Exception as e:
            logger.warning(f"Failed to load custom appendix: {e}")
            return f"<div>{default_content}</div>"
    
    def _get_embedded_css(self) -> str:
        """Return embedded CSS content optimized for PDF conversion with Chainguard theme"""
        return """/* PDF-optimized styles with Chainguard branding */
@page {
    margin: 0.75in;
    size: A4;
}

@page appendix {
    margin: 0.75in 0.75in 0.75in 0.75in;
    size: A4;
    @top-center {
        content: "Appendix";
        font-size: 16px;
        font-weight: 600;
        color: #14003d;
        border-bottom: 2px solid #7545fb;
        padding-bottom: 8px;
        margin-bottom: 20px;
    }
}

@media print {
    body { -webkit-print-color-adjust: exact; color-adjust: exact; }
    .navbar { display: none; }
    .container { padding-top: 0; }
    
    /* Enhanced table page breaking for new structure */
    .image-table-container {
        page-break-inside: avoid;
        break-inside: avoid;
        box-shadow: 0 4px 8px rgba(20, 0, 61, 0.15);
    }
    
    .image-table-container table {
        page-break-inside: auto;
        border: 2px solid var(--cg-primary);
    }
    
    .image-table-container thead {
        display: table-header-group;
        page-break-after: avoid;
    }
    
    .image-table-container thead th {
        border-bottom: 3px solid var(--cg-primary);
    }
    
    .image-comparison-row {
        page-break-inside: avoid;
        break-inside: avoid;
        page-break-after: auto;
    }
    
    .image-table-container tbody td {
        page-break-inside: avoid;
        break-inside: avoid;
    }
    
    /* Enhanced badge visibility in PDF */
    .vuln-badge {
        border: 2px solid currentColor;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    
    /* Prevent orphaned text */
    p, li {
        orphans: 3;
        widows: 3;
    }
    
    /* Improve severity table for PDF */
    .summary-table {
        page-break-inside: avoid;
    }
    
    .severity-count {
        font-size: 12px;
        font-weight: 700;
    }
    
    .severity-indicator {
        width: 10px;
        height: 10px;
    }
}

/* Chainguard Brand Colors */
:root {
    --cg-primary: #14003d;        /* Deep purple - primary text/backgrounds */
    --cg-secondary: #3443f4;      /* Bright blue - secondary elements */
    --cg-accent: #7545fb;         /* Purple accent - highlights */
    --cg-success: #7af0fe;        /* Light cyan - success/positive */
    --cg-light: #d0cfee;          /* Light purple - subtle backgrounds */
    --cg-white: #ffffff;
    --cg-black: #000000;
    --cg-gray-light: #f8f9fc;
    --cg-gray-medium: #e5e7f0;
    --cg-gray-dark: #6b7280;
}

/* Base styles */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: var(--cg-white);
    color: var(--cg-primary);
    margin: 0;
    padding: 24px;
    line-height: 1.6;
    font-size: 13px;
    font-weight: 400;
}

.container {
    max-width: 100%;
    margin: 0;
    padding: 0;
}

/* Typography */
h1 {
    color: var(--cg-white);
    font-size: 28px;
    font-weight: 700;
    margin: 0 0 8px 0;
    text-align: center;
    letter-spacing: -0.025em;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

h2 {
    color: var(--cg-primary);
    font-size: 20px;
    font-weight: 600;
    margin: 32px 0 20px 0;
    text-align: left;
    border-bottom: 3px solid var(--cg-accent);
    padding-bottom: 8px;
    letter-spacing: -0.015em;
}

h3 {
    color: var(--cg-primary);
    font-size: 16px;
    font-weight: 600;
    margin: 24px 0 12px 0;
    border-bottom: 1px solid var(--cg-light);
    padding-bottom: 6px;
}

p {
    margin: 12px 0;
    line-height: 1.7;
    color: var(--cg-primary);
}

/* Code styling */
code {
    background-color: var(--cg-gray-light);
    color: var(--cg-secondary);
    padding: 3px 6px;
    border: 1px solid var(--cg-light);
    border-radius: 4px;
    font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", "Courier New", monospace;
    font-size: 12px;
    font-weight: 500;
}

/* Layout sections */
.header-section {
    text-align: center;
    margin-bottom: 0;
    border-bottom: 4px solid var(--cg-accent);
    padding: 20px 32px 20px 32px;
    background: #14003d;
    border-radius: 12px;
    box-shadow: 0 8px 16px -2px rgba(20, 0, 61, 0.15);
    position: relative;
    color: var(--cg-white);
}

.header-logo {
    position: absolute;
    top: 20px;
    left: 20px;
    width: 60px;
    height: auto;
    max-height: 45px;
}

.header-section p {
    font-size: 14px;
    color: var(--cg-light);
    margin-top: 8px;
    font-weight: 400;
    opacity: 0.95;
}

.overview-grid {
    display: table;
    width: 100%;
    margin-bottom: 40px;
    border-spacing: 20px;
    table-layout: fixed;
}

.summary-column {
    display: table-cell;
    width: 50%;
    vertical-align: top;
    padding: 0;
}

.summary-column-content {
    background: var(--cg-white);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    min-height: 400px;
}

.summary-column h2 {
    text-align: center;
    font-size: 18px;
    margin-bottom: 24px;
    color: var(--cg-primary);
}

/* Total boxes with enhanced Chainguard styling */
.total-box {
    padding: 24px;
    border: 2px solid var(--cg-light);
    text-align: center;
    font-size: 36px;
    font-weight: 700;
    margin-bottom: 24px;
    background: var(--cg-white);
    border-radius: 8px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    flex-shrink: 0;
}

.total-box span {
    display: block;
    font-size: 13px;
    font-weight: 500;
    margin-top: 8px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.customer-total {
    background: linear-gradient(135deg, #f8f9fc 0%, #e5e7f0 100%);
    border-color: #d0cfee;
    color: #14003d;
}

.chainguard-total {
    background: linear-gradient(135deg, #7af0fe 0%, #a7f3d0 100%);
    border-color: #7af0fe;
    color: var(--cg-primary);
}

.reduction-box {
    background: linear-gradient(135deg, var(--cg-success) 0%, #a7f3d0 100%);
    border-color: #7af0fe;
    color: var(--cg-primary);
    font-size: 40px;
}

/* Summary table styling */
.summary-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    border-radius: 6px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(20, 0, 61, 0.08);
}

.summary-table th,
.summary-table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--cg-light);
    font-size: 13px;
}

.summary-table th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 11px;
}

.summary-table tbody tr:nth-child(even) {
    background-color: var(--cg-gray-light);
}

.severity-count {
    font-weight: 700;
    font-size: 14px;
    color: var(--cg-primary);
}

.severity-indicator {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 2px;
    margin-right: 8px;
    vertical-align: middle;
}

/* Severity indicator colors */
.severity-indicator.critical { 
    background: #dc2626;
}
.severity-indicator.high { 
    background: #ea580c;
}
.severity-indicator.medium { 
    background: #d97706;
}
.severity-indicator.low { 
    background: var(--cg-secondary);
}
.severity-indicator.negligible { 
    background: var(--cg-gray-dark);
}
.severity-indicator.unknown { 
    background: #9ca3af;
}

/* Enhanced sections */
.image-comparison-section {
    margin-top: 40px;
    margin-bottom: 40px;
    padding: 20px;
    border: 2px solid var(--cg-light);
    background: var(--cg-white);
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    page-break-inside: avoid;
    page-break-before: avoid;
}

.image-comparison-section h2 {
    margin-top: 0;
    color: var(--cg-primary);
    page-break-after: avoid;
}

/* Make first section directly adjacent to header */
.header-section + .image-comparison-section {
    margin-top: 0 !important;
    page-break-before: avoid !important;
    break-before: avoid !important;
}


/* CVE Reduction Analysis */
.overview-grid .summary-column h3 {
    text-align: center;
    margin-bottom: 24px;
    font-size: 16px;
    color: var(--cg-primary);
}

.reduction-stats {
    display: table;
    width: 100%;
    margin: 24px 0;
    border-spacing: 8px;
    height: 120px;
}

.reduction-stat {
    display: table-cell;
    text-align: center;
    padding: 24px 16px;
    background: var(--cg-gray-light);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    width: 50%;
    vertical-align: middle;
    height: 120px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
}

.single-reduction-stat {
    text-align: center;
    padding: 24px;
    background: var(--cg-gray-light);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    margin-bottom: 24px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    flex-shrink: 0;
}

.reduction-stat-value {
    font-size: 40px;
    font-weight: 700;
    color: var(--cg-primary);
    display: block;
    margin-bottom: 8px;
    line-height: 1;
}

.reduction-stat-label {
    font-size: 13px;
    color: var(--cg-gray-dark);
    display: block;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
}

/* Enhanced Professional table styling */
.image-table-container {
    width: 100%;
    overflow: visible;
    margin: 30px 0;
    page-break-inside: avoid;
    break-inside: avoid;
    border-radius: 12px;
    box-shadow: 0 8px 16px -4px rgba(20, 0, 61, 0.12);
    background: var(--cg-white);
}

.image-table-container table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    border-radius: 12px;
    overflow: hidden;
    table-layout: fixed;
    page-break-inside: auto;
    border: 2px solid var(--cg-light);
}

.image-table-container th,
.image-table-container td {
    padding: 16px 12px;
    border-bottom: 1px solid var(--cg-gray-medium);
    text-align: center;
    font-size: 12px;
    vertical-align: middle;
    word-wrap: break-word;
    overflow-wrap: break-word;
    page-break-inside: avoid;
    break-inside: avoid;
    line-height: 1.5;
}

.image-table-container thead th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    page-break-after: avoid;
    border-bottom: 3px solid var(--cg-accent);
}

.image-table-container tbody tr {
    page-break-inside: avoid;
    break-inside: avoid;
    page-break-after: auto;
    transition: background-color 0.2s ease;
}

.image-table-container tbody tr:nth-child(even) {
    background-color: var(--cg-gray-light);
}

.image-table-container tbody tr:nth-child(odd) {
    background-color: var(--cg-white);
}

.image-table-container tbody tr:hover {
    background-color: rgba(116, 69, 251, 0.08);
}

/* Simplified table cell styling */
.image-name {
    font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", "Courier New", monospace;
    font-size: 11px;
    font-weight: 600;
    color: var(--cg-primary);
    background: rgba(255, 255, 255, 0.8);
    padding: 4px 8px;
    border-radius: 6px;
    border: 1px solid var(--cg-light);
}

.image-name-cell {
    width: 40%;
}

.breakdown-cell {
    width: 10%;
}

.vulnerability-count {
    font-weight: 700;
    font-size: 14px;
    color: var(--cg-primary);
    text-align: center;
}

.no-match {
    color: var(--cg-gray-dark);
    font-style: italic;
    font-weight: 500;
}

/* Enhanced vulnerability breakdown styling */
.vuln-breakdown-container {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    justify-content: center;
    align-items: center;
    padding: 2px;
}

.vuln-badge {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 3px 6px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border: 1px solid transparent;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.vuln-code {
    font-weight: 700;
    opacity: 0.9;
}

.vuln-count {
    font-weight: 800;
    font-size: 11px;
}

/* Severity-specific badge colors */
.vuln-critical {
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: white;
    border-color: #b91c1c;
}

.vuln-high {
    background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
    color: white;
    border-color: #dc2626;
}

.vuln-medium {
    background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
    color: white;
    border-color: #c2410c;
}

.vuln-low {
    background: linear-gradient(135deg, var(--cg-secondary) 0%, #1e40af 100%);
    color: white;
    border-color: #2563eb;
}

.vuln-negligible {
    background: linear-gradient(135deg, var(--cg-gray-dark) 0%, #4b5563 100%);
    color: white;
    border-color: #6b7280;
}

.vuln-unknown {
    background: linear-gradient(135deg, #9ca3af 0%, #6b7280 100%);
    color: white;
    border-color: #9ca3af;
}

.vuln-clean {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border-color: #10b981;
    font-weight: 700;
}

.breakdown-error {
    color: var(--cg-gray-dark);
    font-style: italic;
    font-weight: 500;
}

/* Enhanced table legend styling */
.table-legend {
    margin: 20px 0;
    padding: 20px;
    background: linear-gradient(135deg, rgba(208, 207, 238, 0.2) 0%, rgba(229, 231, 240, 0.2) 100%);
    border-radius: 12px;
    border: 2px solid var(--cg-light);
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.legend-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.legend-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--cg-primary);
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.legend-note {
    margin: 0;
    font-size: 12px;
    color: var(--cg-gray-dark);
    display: flex;
    align-items: center;
    gap: 8px;
}

.legend-icon {
    background: var(--cg-accent);
    color: white;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
}

.legend-badges, .legend-indicators {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
    margin-top: 8px;
}

.legend-badge {
    transform: scale(0.9);
}

.legend-text {
    font-size: 12px;
    color: var(--cg-primary);
    font-weight: 500;
    margin-right: 16px;
}

/* Print optimization for legend */
@media print {
    .table-legend {
        page-break-inside: avoid;
        break-inside: avoid;
        border: 2px solid var(--cg-primary);
        box-shadow: 0 2px 4px rgba(20, 0, 61, 0.1);
    }
    
    .legend-badges, .legend-indicators {
        gap: 8px;
    }
    
    .legend-text {
        margin-right: 12px;
    }
}

/* Enhanced Appendix with better page break handling */
.appendix-content {
    text-align: left;
    padding: 24px;
    background: var(--cg-gray-light);
    border-radius: 8px;
    border: 2px solid var(--cg-light);
    page-break-before: always;
}

.appendix-content h2 {
    page-break-after: avoid;
    margin-top: 0 !important;
    margin-bottom: 20px;
}

.appendix-content h3 {
    font-size: 16px;
    margin-top: 28px;
    color: var(--cg-primary);
    border-bottom-color: var(--cg-accent);
    page-break-after: avoid;
    page-break-before: auto;
}

.appendix-content ul {
    margin: 16px 0;
    padding-left: 24px;
    page-break-inside: auto;
}

.appendix-content li {
    margin-bottom: 8px;
    line-height: 1.6;
    font-size: 12px;
    color: var(--cg-primary);
    page-break-inside: avoid;
}

.appendix-content p {
    orphans: 2;
    widows: 2;
    page-break-inside: auto;
}

.appendix-content strong {
    color: var(--cg-accent);
    font-weight: 600;
}

/* Appendix section grouping for better page breaks */
.appendix-section {
    page-break-inside: avoid;
    margin-bottom: 32px;
}

.appendix-section:last-child {
    margin-bottom: 0;
}

@media print {
    .appendix-content {
        page-break-before: always;
        break-before: always;
        background: transparent;
        border: none;
        border-radius: 0;
        box-shadow: none;
        page: appendix;
        page-break-inside: auto;
        break-inside: auto;
    }
    
    .appendix-content h3 {
        page-break-after: avoid;
        break-after: avoid;
        page-break-before: auto;
        break-before: auto;
    }
    
    .appendix-content ul {
        page-break-inside: auto;
        break-inside: auto;
    }
    
    .appendix-content li {
        page-break-inside: avoid;
        break-inside: avoid;
        orphans: 2;
        widows: 2;
    }
    
    .appendix-content p {
        orphans: 2;
        widows: 2;
        page-break-inside: auto;
        break-inside: auto;
    }
    
    .appendix-section {
        page-break-inside: avoid;
        break-inside: avoid;
    }
    
    /* Strategic page break with continuation header */
    .appendix-page-break {
        page-break-before: always;
        break-before: always;
        margin-top: 0;
        padding-top: 0;
    }
    
    .appendix-continuation {
        color: var(--cg-primary);
        font-size: 20px;
        font-weight: 600;
        margin: 0 0 20px 0 !important;
        text-align: left;
        border-bottom: 3px solid var(--cg-accent);
        padding-bottom: 8px;
        letter-spacing: -0.015em;
        page-break-after: avoid;
    }
    
    /* Chrome PDF export specific footer behavior - now inside appendix */
    .appendix-content .footer {
        page-break-before: avoid;
        break-before: avoid;
        page-break-inside: avoid;
        break-inside: avoid;
        margin-top: 30px;
        border-radius: 8px;
        background: var(--cg-white);
        border: 2px solid var(--cg-light);
    }
}

/* Professional Footer */
.footer {
    text-align: center;
    margin-top: 40px;
    padding: 20px;
    font-size: 11px;
    color: var(--cg-gray-dark);
    border-top: 2px solid var(--cg-light);
    background: var(--cg-gray-light);
    border-radius: 0 0 8px 8px;
    font-weight: 500;
    page-break-before: avoid;
    page-break-inside: avoid;
}

/* Navbar - hidden in print */
.navbar {
    display: none;
}

/* Utility classes */
.no-break {
    page-break-inside: avoid;
}

/* Additional professional touches */
strong {
    color: var(--cg-primary);
    font-weight: 600;
}

em {
    color: var(--cg-accent);
    font-style: normal;
    font-weight: 500;
}

/* Small caps for labels */
.label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
    color: var(--cg-gray-dark);
}"""
    
    def _get_current_datetime(self) -> str:
        """Get current datetime formatted string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    parser = argparse.ArgumentParser(
        description="Chainguard CVE Vulnerability Scanner and Reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # CSV format (recommended for performance):
  %(prog)s -s image_pairs.csv -o report.html -e summary.md --max-workers 8
  
  # Two-column whitespace-separated format:
  %(prog)s -s image_pairs.txt -o report.html
  
  # Legacy single image:
  %(prog)s -s nginx:latest -o report.html
  
  # Legacy comma-separated images:
  %(prog)s -s "nginx:latest,python:3.9" -o report.html

File Formats:
  CSV: Chainguard_Image,Customer_Image
  Whitespace: Chainguard_Image    Customer_Image
  
Performance:
  Use --max-workers to control parallel scanning (default: 4)
  Rows with any failed scans are excluded from results
        """
    )
    
    parser.add_argument('-s', '--source', required=True,
                       help='Source: two-column file (Chainguard Customer), single image, comma-separated list, or single-column file')
    parser.add_argument('-o', '--output', required=True,
                       help='Output HTML file path')
    parser.add_argument('-e', '--exec-summary', 
                       help='Optional markdown file for executive summary')
    parser.add_argument('-a', '--appendix', 
                       help='Optional markdown file for appendix content')
    parser.add_argument('--max-workers', type=int, default=4,
                       help='Maximum number of parallel scanning threads (default: 4)')
    parser.add_argument('--timeout-per-image', type=int, default=300,
                       help='Timeout in seconds per image scan (default: 300)')
    parser.add_argument('-c', '--customer-name', 
                       help='Customer name for report footer (default: "Customer")')
    
    args = parser.parse_args()
    
    scanner = CVEScanner()
    
    # Check if Grype is installed
    if not scanner.check_grype_installation():
        sys.exit(1)
    
    # Parse source input - handle both new and legacy formats
    try:
        legacy_images, image_pairs = scanner.parse_source_input(args.source)
        
        if image_pairs:
            # New two-column format - use parallel scanning
            logger.info(f"Using two-column format with {len(image_pairs)} image pairs")
            scan_results = scanner.scan_image_pairs_parallel(image_pairs, args.max_workers)
        elif legacy_images:
            # Legacy format - convert to pairs and scan
            logger.info(f"Using legacy format with {len(legacy_images)} images")
            legacy_pairs = []
            for customer_image in legacy_images:
                chainguard_image = scanner.find_chainguard_equivalent(customer_image)
                legacy_pairs.append(ImagePair(chainguard_image, customer_image))
            scan_results = scanner.scan_image_pairs_parallel(legacy_pairs, args.max_workers)
        else:
            logger.error("No valid images found in source")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Failed to parse source input: {e}")
        sys.exit(1)
    
    # Generate report (exec summary and appendix loaded inside with metrics)
    scanner.generate_html_report(scan_results, args.exec_summary, args.output, args.appendix, args.customer_name)
    
    # Report failed scans and rows
    if scanner.failed_rows:
        logger.warning(f"Failed to scan {len(scanner.failed_rows)} rows (excluded from results):")
        for row in scanner.failed_rows:
            logger.warning(f"  - {row}")
    
    if scanner.failed_scans:
        logger.warning(f"Individual failed scans: {len(scanner.failed_scans)} images:")
        for image in scanner.failed_scans:
            logger.warning(f"  - {image}")
    
    logger.info(f"Scan complete! Successfully processed {len(scan_results)} image pairs.")

if __name__ == "__main__":
    main()