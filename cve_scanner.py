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
from typing import Dict, List, Optional, NamedTuple
import logging
from dataclasses import dataclass
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

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
    CHAINGUARD_LOGO_URL = f"file://{os.path.abspath('Linky_White.png')}"
    
    def __init__(self, platform=None):
        self.failed_scans = []
        self.failed_rows = []
        self._lock = threading.Lock()
        self.platform = platform
        
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
            cmd = ['grype', '-o', 'json']
            if self.platform:
                cmd.extend(['--platform', self.platform])
            cmd.append(image_name)
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
        """Parse image pairs from a CSV file format"""
        image_pairs = []
        
        # Only accept CSV files
        if not file_path.lower().endswith('.csv'):
            logger.error(f"Only CSV files are supported. Got: {file_path}")
            return []
        
        with open(file_path, 'r') as f:
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
        
        return image_pairs
    
    
    def parse_source_input(self, source: str) -> List[ImagePair]:
        """Parse source input - returns image_pairs from CSV file"""
        if os.path.isfile(source):
            # Parse as CSV format
            image_pairs = self.parse_image_pairs_from_file(source)
            if image_pairs:
                logger.info(f"Parsed {len(image_pairs)} image pairs from CSV file")
                return image_pairs
            else:
                logger.error(f"No valid image pairs found in CSV file: {source}")
                return []
        else:
            logger.error(f"Source must be a CSV file path: {source}")
            return []
    
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
        
        # Generate HTML optimized for PDF conversion matching sample-customer.html structure exactly
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
    <!-- Cover Page -->
    <div class="cover">
        <img class="cover-logo" src="{self.CHAINGUARD_LOGO_URL}" alt="Chainguard Logo">
        <h1>Vulnerability Comparison Report</h1>
        <p class="subtitle">An analysis comparing known vulnerabilities in your container images versus Chainguard's hardened, minimal, low to zero CVE alternative.</p>
    </div>

    <!-- Executive Summary -->
    <section class="executive-summary">
        <h2>Executive Summary</h2>
        
        <p>This report compares the vulnerability exposure between your current container images and Chainguard's hardened alternatives. Analysis of <strong>{metrics['images_scanned']} image pairs</strong> shows a <strong>{metrics['reduction_percentage']}% overall CVE reduction</strong>, with <strong>{metrics['total_reduction']} fewer vulnerabilities</strong> when using Chainguard images.</p>
        
        <div class="metric-box reduction">
            <span class="metric-value">{metrics['reduction_percentage']}%</span>
            <span class="metric-label">CVE Reduction</span>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-box customer">
                <span class="metric-value">{customer_total:,}</span>
                <span class="metric-label">Your Images – Total CVEs</span>
                
                <table class="severity-table">
                    <thead>
                        <tr><th>Severity</th><th>Count</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Critical</td><td class="vuln-critical">{customer_summary.get('Critical', 0)}</td></tr>
                        <tr><td>High</td><td class="vuln-high">{customer_summary.get('High', 0)}</td></tr>
                        <tr><td>Medium</td><td class="vuln-medium">{customer_summary.get('Medium', 0)}</td></tr>
                        <tr><td>Low</td><td class="vuln-low">{customer_summary.get('Low', 0)}</td></tr>
                        <tr><td>Negligible</td><td class="vuln-negligible">{customer_summary.get('Negligible', 0)}</td></tr>
                        <tr><td>Unknown</td><td class="vuln-negligible">{customer_summary.get('Unknown', 0)}</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="metric-box chainguard">
                <span class="metric-value">{chainguard_total}</span>
                <span class="metric-label">Chainguard Images – Total CVEs</span>
                
                <table class="severity-table">
                    <thead>
                        <tr><th>Severity</th><th>Count</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Critical</td><td class="vuln-critical">{chainguard_summary.get('Critical', 0)}</td></tr>
                        <tr><td>High</td><td class="vuln-high">{chainguard_summary.get('High', 0)}</td></tr>
                        <tr><td>Medium</td><td class="vuln-medium">{chainguard_summary.get('Medium', 0)}</td></tr>
                        <tr><td>Low</td><td class="vuln-low">{chainguard_summary.get('Low', 0)}</td></tr>
                        <tr><td>Negligible</td><td class="vuln-negligible">{chainguard_summary.get('Negligible', 0)}</td></tr>
                        <tr><td>Unknown</td><td class="vuln-negligible">{chainguard_summary.get('Unknown', 0)}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div style="clear: both;"></div>
        
        <p>Chainguard images are built with security-first principles, are built from source and eliminate unnecessary components to significantly reduce your attack surface.</p>
    </section>

    <!-- Images Scanned -->
    <section class="page-break">
        <h2>Image Comparison</h2>
        
        <div class="legend" style="text-align: center;">
            <strong>Vulnerability Severity Legend:</strong>&nbsp;&nbsp;&nbsp;
            <span class="legend-item"><span class="legend-badge vuln-critical">C</span>Critical</span>
            <span class="legend-item"><span class="legend-badge vuln-high">H</span>High</span>
            <span class="legend-item"><span class="legend-badge vuln-medium">M</span>Medium</span>
            <span class="legend-item"><span class="legend-badge vuln-low">L</span>Low</span>
            <span class="legend-item"><span class="legend-badge vuln-negligible">N</span>Negligible</span>
            <span class="legend-item"><span class="legend-badge vuln-unknown">U</span>Unknown</span>
        </div>
        
        <table class="comparison-table">
            <colgroup>
                <col style="width: 20%;">    <!-- Your Image -->
                <col style="width: 6%;">     <!-- Total -->
                <col style="width: 4%;">     <!-- C -->
                <col style="width: 4%;">     <!-- H -->
                <col style="width: 4%;">     <!-- M -->
                <col style="width: 4%;">     <!-- L -->
                <col style="width: 4%;">     <!-- N -->
                <col style="width: 4%;">     <!-- U -->
                <col style="width: 20%;">    <!-- Chainguard Image - IDENTICAL -->
                <col style="width: 6%;">     <!-- Total -->
                <col style="width: 4%;">     <!-- C -->
                <col style="width: 4%;">     <!-- H -->
                <col style="width: 4%;">     <!-- M -->
                <col style="width: 4%;">     <!-- L -->
                <col style="width: 4%;">     <!-- N -->
                <col style="width: 4%;">     <!-- U -->
            </colgroup>
            <thead>
                <tr>
                    <th rowspan="2">Your Image</th>
                    <th colspan="7">Vulnerabilities</th>
                    <th rowspan="2">Chainguard Image</th>
                    <th colspan="7">Vulnerabilities</th>
                </tr>
                <tr>
                    <th>Total</th>
                    <th>C</th>
                    <th>H</th>
                    <th>M</th>
                    <th>L</th>
                    <th>N</th>
                    <th>U</th>
                    <th>Total</th>
                    <th>C</th>
                    <th>H</th>
                    <th>M</th>
                    <th>L</th>
                    <th>N</th>
                    <th>U</th>
                </tr>
            </thead>
            <tbody>
                {self._generate_comparison_table_rows(image_pairs)}
            </tbody>
        </table>
    </section>

    <!-- Appendix -->
    <section class="appendix">
        <h2>Appendix</h2>
        
        <h3>Methodology</h3>
        <p>This report was generated using the following methodology:</p>
        <ul>
            <li><strong>Scanning Tool:</strong> Grype vulnerability scanner</li>
            <li><strong>Data Sources:</strong> National Vulnerability Database (NVD) and other security databases</li>
            <li><strong>Image Analysis:</strong> Container images were scanned for known vulnerabilities</li>
            <li><strong>Comparison:</strong> Customer images compared against Chainguard hardened alternatives</li>
        </ul>
        
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
        
        <h3>About Chainguard Images</h3>
        <p>Chainguard Images are container images built with security-first principles:</p>
        <ul>
            <li><strong>Minimal Base:</strong> Built on minimal base images to reduce attack surface</li>
            <li><strong>Distroless:</strong> Contains only application dependencies, no package managers</li>
            <li><strong>Regular Updates:</strong> Continuously updated with latest security patches</li>
            <li><strong>Zero CVEs:</strong> Many images maintain zero known vulnerabilities</li>
            <li><strong>SBOM Included:</strong> Software Bill of Materials for transparency</li>
            <li><strong>Provenance Tracking:</strong> Complete software supply chain transparency</li>
        </ul>
    </section>
</body>
</html>"""
        
        # Clean up chainguard image references - remove registry path from cgr.dev images
        import re
        # Replace cgr.dev/chainguard-private/imagename:tag with just imagename:tag
        html_content = re.sub(r'cgr\.dev/chainguard-private/([^<\s]+)', r'\1', html_content)
        # Replace cgr.dev/chainguard/imagename:tag with just imagename:tag  
        html_content = re.sub(r'cgr\.dev/chainguard/([^<\s]+)', r'\1', html_content)
        # Replace cgr.dev/cg/imagename:tag with just imagename:tag
        html_content = re.sub(r'cgr\.dev/cg/([^<\s]+)', r'\1', html_content)
        
        # Determine output format based on file extension
        if output_file.endswith('.pdf'):
            return self._generate_pdf_report(html_content, output_file)
        else:
            # Write HTML file
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_file}")
    
    def _generate_pdf_report(self, html_content: str, output_file: str) -> bool:
        """Generate PDF report using WeasyPrint"""
        if not WEASYPRINT_AVAILABLE:
            logger.error("WeasyPrint not available. Install with: pip install weasyprint")
            logger.info("Falling back to HTML output...")
            html_file = output_file.replace('.pdf', '.html')
            with open(html_file, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {html_file}")
            return False
        
        try:
            logger.info("Generating PDF report with WeasyPrint...")
            
            # Create WeasyPrint CSS for enhanced PDF rendering
            pdf_css = CSS(string=self._get_weasyprint_css())
            
            # Generate PDF from HTML
            html_doc = HTML(string=html_content)
            html_doc.write_pdf(output_file, stylesheets=[pdf_css])
            
            logger.info(f"PDF report generated successfully: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            logger.info("Falling back to HTML output...")
            html_file = output_file.replace('.pdf', '.html')
            with open(html_file, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {html_file}")
            return False
    
    def _get_weasyprint_css(self) -> str:
        """Get enhanced CSS optimized for WeasyPrint PDF rendering"""
        return """
        /* WeasyPrint-optimized CSS for professional PDF output */
        @page {
            size: A4;
            margin: 0.6in 0.4in;
            @top-center {
                content: "Chainguard Vulnerability Report";
                font-size: 10px;
                color: #7545fb;
                padding-bottom: 8px;
                border-bottom: 1px solid #e5e5e5;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9px;
                color: #666;
                padding-top: 8px;
                border-top: 1px solid #e5e5e5;
            }
        }
        
        /* Force table section to separate page */
        .images-scanned-section {
            page-break-before: always;
            page-break-after: always;
        }
        
        /* Force appendix to separate page */  
        .appendix-content {
            page-break-before: always;
        }
        
        /* Enhanced table rendering for WeasyPrint */
        .image-table-container table {
            width: 100%;
            border-collapse: collapse;
            font-size: 8px;
        }
        
        .image-table-container th,
        .image-table-container td {
            border: 1px solid #ddd;
            padding: 4px 3px;
            font-size: 8px;
            text-align: center;
        }
        
        .image-name-row .image-name-cell {
            padding: 6px 8px;
            font-size: 9px;
            font-weight: 700;
            background-color: #f8f9ff;
            text-align: center;
        }
        
        .vulnerability-count-row .vulnerability-count {
            font-weight: 800;
            font-size: 9px;
            background-color: #f0f0f8;
        }
        
        .vulnerability-count-row .severity-count {
            font-size: 8px;
            font-weight: 600;
        }
        
        /* Critical and High severity highlighting */
        .vulnerability-count-row .severity-count:nth-child(3),
        .vulnerability-count-row .severity-count:nth-child(10) {
            color: #dc2626;
            font-weight: 800;
        }
        
        .vulnerability-count-row .severity-count:nth-child(4),
        .vulnerability-count-row .severity-count:nth-child(11) {
            color: #ea580c;
            font-weight: 800;
        }
        
        /* Preserve colors in PDF */
        * {
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }
        """
    
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
        """Generate HTML table rows with simplified structure and Unknown columns"""
        rows = []
        
        # Calculate totals for footer row
        customer_totals = {'total': 0, 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
        chainguard_totals = {'total': 0, 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
        
        for pair in image_pairs:
            customer = pair['customer']
            chainguard = pair['chainguard']
            
            # Format display names with line breaks
            customer_name = self._get_display_name(customer)
            chainguard_name = self._get_display_name(chainguard) if chainguard else "No match"
            
            # Split at colon for two-line display
            customer_parts = customer_name.split(':')
            customer_formatted = f"{customer_parts[0]}<br><span class=\"image-tag\">:{customer_parts[1]}</span>" if len(customer_parts) > 1 else customer_name
            
            if chainguard:
                chainguard_parts = chainguard_name.split(':')
                chainguard_formatted = f"{chainguard_parts[0]}<br><span class=\"image-tag\">:{chainguard_parts[1]}</span>" if len(chainguard_parts) > 1 else chainguard_name
            else:
                chainguard_formatted = '<span class="no-match">No match</span>'
            
            # Get vulnerability counts
            customer_total = customer.total_vulnerabilities if customer.scan_successful else 0
            customer_counts = self._get_severity_counts_with_unknown(customer)
            
            chainguard_total = chainguard.total_vulnerabilities if chainguard and chainguard.scan_successful else 0
            chainguard_counts = self._get_severity_counts_with_unknown(chainguard) if chainguard else {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
            
            # Add to totals
            customer_totals['total'] += customer_total
            chainguard_totals['total'] += chainguard_total
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']:
                customer_totals[severity] += customer_counts.get(severity, 0)
                chainguard_totals[severity] += chainguard_counts.get(severity, 0)
            
            # Generate single row with all data
            rows.append(f"""                <tr>
                    <td class="image-name">{customer_formatted}</td>
                    <td class="vuln-count">{customer_total}</td>
                    <td class="vuln-critical">{customer_counts.get('Critical', 0)}</td>
                    <td class="vuln-high">{customer_counts.get('High', 0)}</td>
                    <td class="vuln-medium">{customer_counts.get('Medium', 0)}</td>
                    <td class="vuln-low">{customer_counts.get('Low', 0)}</td>
                    <td class="vuln-negligible">{customer_counts.get('Negligible', 0)}</td>
                    <td class="vuln-unknown">{customer_counts.get('Unknown', 0)}</td>
                    <td class="image-name">{chainguard_formatted}</td>
                    <td class="vuln-count">{chainguard_total}</td>
                    <td class="vuln-critical">{chainguard_counts.get('Critical', 0)}</td>
                    <td class="vuln-high">{chainguard_counts.get('High', 0)}</td>
                    <td class="vuln-medium">{chainguard_counts.get('Medium', 0)}</td>
                    <td class="vuln-low">{chainguard_counts.get('Low', 0)}</td>
                    <td class="vuln-negligible">{chainguard_counts.get('Negligible', 0)}</td>
                    <td class="vuln-unknown">{chainguard_counts.get('Unknown', 0)}</td>
                </tr>""")
        
        # Add totals footer row
        rows.append(f"""            </tbody>
            <tfoot>
                <tr style="background: var(--cg-primary); color: var(--cg-white); font-weight: 700;">
                    <td class="image-name" style="color: var(--cg-white); border: none;">TOTALS</td>
                    <td class="vuln-count" style="border: none;">{customer_totals['total']:,}</td>
                    <td class="vuln-critical" style="border: none;">{customer_totals['Critical']}</td>
                    <td class="vuln-high" style="border: none;">{customer_totals['High']}</td>
                    <td class="vuln-medium" style="border: none;">{customer_totals['Medium']}</td>
                    <td class="vuln-low" style="border: none;">{customer_totals['Low']}</td>
                    <td class="vuln-negligible" style="border: none;">{customer_totals['Negligible']:,}</td>
                    <td class="vuln-unknown" style="border: none;">{customer_totals['Unknown']}</td>
                    <td class="image-name" style="color: var(--cg-white); border: none;">TOTALS</td>
                    <td class="vuln-count" style="border: none;">{chainguard_totals['total']}</td>
                    <td class="vuln-critical" style="border: none;">{chainguard_totals['Critical']}</td>
                    <td class="vuln-high" style="border: none;">{chainguard_totals['High']}</td>
                    <td class="vuln-medium" style="border: none;">{chainguard_totals['Medium']}</td>
                    <td class="vuln-low" style="border: none;">{chainguard_totals['Low']}</td>
                    <td class="vuln-negligible" style="border: none;">{chainguard_totals['Negligible']}</td>
                    <td class="vuln-unknown" style="border: none;">{chainguard_totals['Unknown']}</td>
                </tr>
            </tfoot>""")
        
        return ''.join(rows)
    
    def _get_severity_counts_with_unknown(self, vuln_data: VulnerabilityData) -> Dict[str, int]:
        """Get individual severity counts including Unknown for a vulnerability data object"""
        if not vuln_data or not vuln_data.scan_successful:
            return {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
        
        # Return the severity breakdown, ensuring all severity levels including Unknown are present
        counts = {severity: vuln_data.severity_breakdown.get(severity, 0) for severity in self.SEVERITY_ORDER}
        counts['Unknown'] = vuln_data.severity_breakdown.get('Unknown', 0)
        return counts

    def _get_severity_counts(self, vuln_data: VulnerabilityData) -> Dict[str, int]:
        """Get individual severity counts for a vulnerability data object"""
        if not vuln_data or not vuln_data.scan_successful:
            return {severity: 0 for severity in self.SEVERITY_ORDER}
        
        # Return the severity breakdown, ensuring all severity levels are present
        counts = {severity: 0 for severity in self.SEVERITY_ORDER}
        counts.update(vuln_data.severity_breakdown)
        return counts
    
    def _get_display_name(self, vuln_data: VulnerabilityData) -> str:
        """Get display name for image with asterisk if retried"""
        if vuln_data.was_retried:
            return f"{vuln_data.original_image_name}*"
        return vuln_data.image_name
    
    def _format_vulnerability_breakdown(self, vuln_data: VulnerabilityData) -> str:
        """Format vulnerability count with small severity breakdown badges"""
        if not vuln_data.scan_successful:
            return '<span class="breakdown-error">Scan Failed</span>'
        
        if vuln_data.total_vulnerabilities == 0:
            return '<div class="vuln-breakdown-container"><span class="vuln-badge vuln-clean">Clean</span></div>'
        
        # Create small badges for each severity with count > 0
        badges = []
        
        for severity in self.SEVERITY_ORDER:
            count = vuln_data.severity_breakdown.get(severity, 0)
            if count > 0:
                severity_class = severity.lower()
                badges.append(f'<span class="vuln-badge vuln-{severity_class}">{count}</span>')
        
        if not badges:
            return '<div class="vuln-breakdown-container"><span class="vuln-badge vuln-clean">Clean</span></div>'
        
        return f'<div class="vuln-breakdown-container">{"".join(badges)}</div>'
    
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
    
    def _generate_vulnerability_legend(self) -> str:
        """Generate HTML for vulnerability severity color legend"""
        return """
            <div class="vulnerability-legend">
                <h3>Vulnerability Severity Legend</h3>
                <div class="legend-items">
                    <div class="legend-item">
                        <span class="vuln-badge vuln-critical legend-badge">C</span>
                        <span class="legend-label">Critical</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-high legend-badge">H</span>
                        <span class="legend-label">High</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-medium legend-badge">M</span>
                        <span class="legend-label">Medium</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-low legend-badge">L</span>
                        <span class="legend-label">Low</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-negligible legend-badge">N</span>
                        <span class="legend-label">Negligible</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-unknown legend-badge">U</span>
                        <span class="legend-label">Unknown</span>
                    </div>
                </div>
            </div>
        """
    
    
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
        return """/* WeasyPrint-optimized CSS with clean structure */

/* Page setup */
@page {
    size: A4;
    margin: 0.6in;
    
    @top-center {
        content: none;
    }
    
    @bottom-center {
        content: "This report is Customer & Chainguard Confidential | Generated on 2025-08-15";
        font-family: "Helvetica Neue", Arial, sans-serif;
        font-size: 9px;
        color: #6b7280;
        border: none;
    }
}

@page:first {
    @top-center { content: none; }
}

/* Chainguard Brand Colors */
:root {
    --cg-primary: #14003d;
    --cg-secondary: #3443f4;
    --cg-accent: #7545fb;
    --cg-success: #7af0fe;
    --cg-light: #d0cfee;
    --cg-gray-light: #f8f9fc;
    --cg-gray-medium: #e5e7f0;
    --cg-gray-dark: #6b7280;
    --cg-white: #ffffff;
}

/* Base typography */
body {
    font-family: "Helvetica Neue", Arial, sans-serif;
    font-size: 11px;
    line-height: 1.5;
    color: var(--cg-primary);
    margin: 0;
    padding: 0;
}

/* Headings */
h1 {
    color: var(--cg-white);
    font-size: 24px;
    font-weight: 700;
    text-align: left;
    margin: 8px 0 10px 0;
    letter-spacing: -0.5px;
}

h2 {
    color: var(--cg-primary);
    font-size: 18px;
    font-weight: 600;
    margin: 30px 0 15px 0;
    border-bottom: 2px solid var(--cg-accent);
    padding-bottom: 5px;
}

h3 {
    color: var(--cg-primary);
    font-size: 14px;
    font-weight: 600;
    margin: 20px 0 10px 0;
}

p {
    margin: 10px 0;
    text-align: left;
}

/* Cover page */
.cover {
    text-align: left;
    padding: 30px 40px 25px 115px;
    background: var(--cg-primary);
    color: var(--cg-white);
    border-radius: 8px;
    margin-bottom: 30px;
    page-break-after: avoid;
    position: relative;
}

.cover-logo {
    position: absolute;
    top: 38px;
    left: 35px;
    width: 45px;
    height: auto;
    max-height: 35px;
}

.cover .subtitle {
    font-size: 14px;
    margin-top: 15px;
    opacity: 0.9;
    font-weight: 400;
    text-align: left;
}

/* Executive Summary */
.executive-summary {
    page-break-inside: avoid;
    page-break-after: always;
    margin-bottom: 30px;
    font-size: 13px;
}

.metrics-grid {
    display: block;
    margin: 20px 0;
    clear: both;
}

.metrics-grid::after {
    content: "";
    display: table;
    clear: both;
}

.metric-box {
    width: 48%;
    margin: 0 0 20px 0;
    padding: 15px;
    text-align: center;
    border: 2px solid var(--cg-light);
    border-radius: 6px;
    float: left;
    box-sizing: border-box;
}

.metric-box.customer {
    background: var(--cg-light);
    border-color: var(--cg-light);
    margin-right: 4%;
}

.metric-box.chainguard {
    background: var(--cg-light);
    border-color: var(--cg-light);
}

.metric-box.reduction {
    background: var(--cg-light);
    border-color: var(--cg-light);
    width: 100%;
    margin: 15px 0;
    float: none;
    clear: both;
}

.metric-value {
    font-size: 32px;
    font-weight: 700;
    color: var(--cg-primary);
    display: block;
    margin-bottom: 5px;
}

.metric-label {
    font-size: 13px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--cg-primary);
}

/* Simple severity breakdown table */
.severity-table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 11px;
}

.severity-table th,
.severity-table td {
    padding: 6px 8px;
    text-align: left;
    border-bottom: 1px solid var(--cg-gray-medium);
}

.severity-table th {
    border-bottom: none;
}

.severity-table th:nth-child(2),
.severity-table td:nth-child(2) {
    text-align: right;
    width: 15%;
    font-weight: bold;
}

.severity-table th:nth-child(1),
.severity-table td:nth-child(1) {
    width: 85%;
}

.severity-table th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
}

.severity-table tbody tr:nth-child(odd) {
    background: var(--cg-gray-medium);
}

.severity-table tbody tr:nth-child(even) {
    background: var(--cg-gray-light);
}

/* Main comparison table - simplified */
.comparison-table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    font-size: 10px;
    page-break-inside: auto;
    table-layout: fixed;
}

.comparison-table th,
.comparison-table td {
    padding: 8px 6px;
    border: 1px solid var(--cg-gray-medium);
    text-align: center;
    vertical-align: middle;
}

.comparison-table th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    font-size: 9px;
    text-transform: uppercase;
}

.comparison-table thead th {
    page-break-after: avoid;
}

.comparison-table tbody tr {
    page-break-inside: avoid;
}

.comparison-table tbody tr:nth-child(even) {
    background: var(--cg-gray-light);
}

.image-name {
    font-family: "Helvetica Neue", Arial, sans-serif;
    font-size: 9px;
    font-weight: 600;
    color: var(--cg-primary);
    text-align: left;
    padding: 8px;
    word-wrap: break-word;
    overflow-wrap: break-word;
    hyphens: auto;
}

.image-tag {
    font-style: italic;
    color: var(--cg-gray-dark);
    font-weight: 400;
}

.vuln-count {
    font-weight: 700;
    font-size: 11px;
}

.vuln-critical { color: var(--cg-primary); }
.vuln-high { color: var(--cg-primary); }
.vuln-medium { color: var(--cg-primary); }
.vuln-low { color: var(--cg-primary); }
.vuln-negligible { color: var(--cg-primary); }
.vuln-unknown { color: var(--cg-primary); }

/* Page breaks */
.page-break {
    page-break-before: always;
}

/* Appendix */
.appendix {
    page-break-before: always;
    font-size: 12px;
}

.appendix h2 {
    font-size: 16px;
    margin-top: 0;
}

.appendix h3 {
    font-size: 12px;
}

.appendix ul {
    margin: 10px 0;
    padding-left: 20px;
}

.appendix li {
    margin-bottom: 5px;
}

/* Legend */
.legend {
    margin: 15px 0;
    padding: 10px;
    background: var(--cg-gray-light);
    border-radius: 4px;
    font-size: 11px;
}

.legend-item {
    display: inline-block;
    margin-right: 15px;
    margin-bottom: 5px;
    white-space: nowrap;
}

.legend-badge {
    display: inline-block;
    padding: 2px 4px;
    border-radius: 2px;
    font-weight: 600;
    margin-right: 4px;
    font-size: 9px;
    background: var(--cg-gray-light);
    color: var(--cg-primary);
    border: 1px solid var(--cg-gray-medium);
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
  # CSV format:
  %(prog)s -s image_pairs.csv -o report.html -e summary.md --max-workers 8
  
  # With custom appendix and customer name:
  %(prog)s -s image_pairs.csv -o report.html -e summary.md -a appendix.md -c "Customer Name"
  
  # With specific platform:
  %(prog)s -s image_pairs.csv -o report.html --platform linux/amd64

File Format:
  CSV: Chainguard_Image,Customer_Image
  
Performance:
  Use --max-workers to control parallel scanning (default: 4)
  Rows with any failed scans are excluded from results
        """
    )
    
    parser.add_argument('-s', '--source', required=True,
                       help='Source: CSV file with Chainguard and Customer image pairs')
    parser.add_argument('-o', '--output', required=True,
                       help='Output file path (HTML or PDF based on extension, e.g., report.pdf)')
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
    parser.add_argument('--platform', 
                       help='Platform to use for Grype scans (e.g., "linux/amd64", "linux/arm64")')
    
    args = parser.parse_args()
    
    scanner = CVEScanner(platform=args.platform)
    
    # Check if Grype is installed
    if not scanner.check_grype_installation():
        sys.exit(1)
    
    # Parse source input
    try:
        image_pairs = scanner.parse_source_input(args.source)
        
        if image_pairs:
            # CSV format - use parallel scanning
            logger.info(f"Using CSV format with {len(image_pairs)} image pairs")
            scan_results = scanner.scan_image_pairs_parallel(image_pairs, args.max_workers)
        else:
            logger.error("No valid image pairs found in source")
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