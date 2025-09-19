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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import threading
import hashlib
import time
import requests
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
    
    def __init__(self, platform=None, cache_dir=".cache", cache_ttl_hours=24, timeout_per_image=300, check_fresh_images=True):
        self.failed_scans = []
        self.failed_rows = []
        self._lock = threading.Lock()
        self.platform = platform
        self.cache_dir = Path(cache_dir)
        self.cache_ttl_hours = cache_ttl_hours
        self.timeout_per_image = timeout_per_image
        self.check_fresh_images = check_fresh_images
        self.cache_file = self.cache_dir / "scan_cache.json"
        self.completed_pairs = 0
        self.total_pairs = 0
        # Add semaphore to limit concurrent Grype scans (max 2 concurrent)
        self._grype_semaphore = threading.Semaphore(2)
        self._setup_cache()
    
    def _setup_cache(self):
        """Initialize cache directory and file"""
        self.cache_dir.mkdir(exist_ok=True)
        if not self.cache_file.exists():
            self._save_cache({})
    
    def _load_cache(self) -> Dict:
        """Load cache from file"""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_cache(self, cache_data: Dict):
        """Save cache to file"""
        with open(self.cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
    
    def _get_remote_digest(self, image_name: str) -> Optional[str]:
        """Get remote image digest via registry API (fast, no pull required)"""
        try:
            # Parse image components
            registry = "registry-1.docker.io"
            namespace = "library"
            repo_tag = image_name

            # Handle different image name formats
            if '/' in image_name:
                if image_name.count('/') == 1:
                    # user/repo:tag format
                    namespace, repo_tag = image_name.split('/', 1)
                elif image_name.count('/') >= 2:
                    # registry.com/user/repo:tag format
                    parts = image_name.split('/', 2)
                    if '.' in parts[0] or ':' in parts[0]:
                        registry = parts[0]
                        if len(parts) > 2:
                            namespace, repo_tag = parts[1], parts[2]
                        else:
                            namespace, repo_tag = "library", parts[1]
                    else:
                        namespace, repo_tag = parts[0], parts[1]

            # Split repo and tag
            if ':' in repo_tag:
                repo, tag = repo_tag.rsplit(':', 1)
            else:
                repo, tag = repo_tag, "latest"

            # Handle Docker Hub API specifics
            if registry == "registry-1.docker.io":
                if namespace == "library":
                    url = f"https://registry-1.docker.io/v2/library/{repo}/manifests/{tag}"
                else:
                    url = f"https://registry-1.docker.io/v2/{namespace}/{repo}/manifests/{tag}"
            else:
                url = f"https://{registry}/v2/{namespace}/{repo}/manifests/{tag}"

            # Make API request
            headers = {
                'Accept': 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'
            }

            response = requests.head(url, headers=headers, timeout=10)

            if response.status_code == 200:
                digest = response.headers.get('Docker-Content-Digest')
                if digest:
                    logger.debug(f"Remote digest for {image_name}: {digest}")
                    return digest

        except Exception as e:
            logger.debug(f"Could not get remote digest for {image_name}: {e}")

        return None

    def _get_local_digest(self, image_name: str) -> Optional[str]:
        """Get local image digest without pulling"""
        for cmd in ['docker', 'podman']:
            try:
                result = subprocess.run([cmd, 'inspect', '--format={{.RepoDigests}}', image_name],
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    digest_info = result.stdout.strip()
                    # Extract SHA256 digest from format like [registry/image@sha256:...]
                    if '@sha256:' in digest_info:
                        digest = digest_info.split('@sha256:')[1].split(']')[0].split()[0]
                        return f"sha256:{digest}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def _ensure_fresh_image(self, image_name: str) -> bool:
        """Ensure we have the latest version of the image. Returns True if image was updated."""
        try:
            # Get remote digest first (fast API call)
            remote_digest = self._get_remote_digest(image_name)
            if not remote_digest:
                logger.debug(f"Could not get remote digest for {image_name}, skipping freshness check")
                return False

            # Get local digest
            local_digest = self._get_local_digest(image_name)

            # If no local image or digests differ, pull the image
            if not local_digest or local_digest != remote_digest:
                logger.info(f"Pulling fresh version of {image_name} (remote digest: {remote_digest[:19]}...)")
                for cmd in ['docker', 'podman']:
                    try:
                        pull_result = subprocess.run([cmd, 'pull', image_name],
                                                   capture_output=True, text=True, timeout=300)
                        if pull_result.returncode == 0:
                            logger.debug(f"Successfully pulled {image_name}")
                            return True
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue

                logger.warning(f"Failed to pull {image_name}")
                return False
            else:
                logger.debug(f"Local image {image_name} is up to date")
                return False

        except Exception as e:
            logger.debug(f"Error ensuring fresh image for {image_name}: {e}")
            return False

    def _get_image_digest(self, image_name: str, ensure_fresh: bool = None) -> Optional[str]:
        """Get image digest, optionally ensuring we have the latest version"""
        if ensure_fresh is None:
            ensure_fresh = self.check_fresh_images

        if ensure_fresh:
            self._ensure_fresh_image(image_name)

        # Now get the local digest (after potential pull)
        local_digest = self._get_local_digest(image_name)
        if local_digest:
            return local_digest

        # Fallback: try to pull if we don't have local digest
        for cmd in ['docker', 'podman']:
            try:
                logger.info(f"No digest found for {image_name}, attempting to pull...")
                pull_result = subprocess.run([cmd, 'pull', image_name],
                                           capture_output=True, text=True, timeout=300)
                if pull_result.returncode == 0:
                    # Try inspect again
                    result = subprocess.run([cmd, 'inspect', '--format={{.RepoDigests}}', image_name],
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0 and '@sha256:' in result.stdout:
                        digest_info = result.stdout.strip()
                        digest = digest_info.split('@sha256:')[1].split(']')[0].split()[0]
                        return f"sha256:{digest}"
                # Fallback: use image ID as identifier
                id_result = subprocess.run([cmd, 'inspect', '--format={{.Id}}', image_name],
                                         capture_output=True, text=True, timeout=30)
                if id_result.returncode == 0:
                    return id_result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Fallback: create a hash from image name and current time (not ideal but better than nothing)
        logger.debug(f"Could not get digest for {image_name}, using fallback hash (docker/podman not available or image not accessible)")
        return hashlib.sha256(f"{image_name}:{int(time.time() / 3600)}".encode()).hexdigest()[:16]
    
    def _get_cache_key(self, image_name: str, digest: str) -> str:
        """Generate cache key from image name and digest"""
        platform_suffix = f"_{self.platform}" if self.platform else ""
        return f"{image_name}#{digest}{platform_suffix}"
    
    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """Check if cache entry is still valid based on TTL"""
        if 'timestamp' not in cache_entry:
            return False
        cache_age_hours = (time.time() - cache_entry['timestamp']) / 3600
        return cache_age_hours < self.cache_ttl_hours
    
    def _get_cached_scan_result(self, image_name: str) -> Optional[VulnerabilityData]:
        """Get cached scan result if available and valid"""
        digest = self._get_image_digest(image_name)
        if not digest:
            return None
        
        cache_key = self._get_cache_key(image_name, digest)
        cache_data = self._load_cache()
        
        if cache_key in cache_data and self._is_cache_valid(cache_data[cache_key]):
            logger.info(f"Using cached scan result for {image_name}")
            cached = cache_data[cache_key]
            return VulnerabilityData(
                image_name=cached['image_name'],
                total_vulnerabilities=cached['total_vulnerabilities'],
                severity_breakdown=cached['severity_breakdown'],
                vulnerabilities=cached['vulnerabilities'],
                scan_successful=cached['scan_successful'],
                error_message=cached.get('error_message', ''),
                was_retried=cached.get('was_retried', False),
                original_image_name=cached.get('original_image_name', cached['image_name'])
            )
        return None
    
    def _cache_scan_result(self, image_name: str, vuln_data: VulnerabilityData):
        """Cache scan result with image digest"""
        digest = self._get_image_digest(image_name)
        if not digest:
            return
        
        cache_key = self._get_cache_key(image_name, digest)
        cache_data = self._load_cache()
        
        cache_entry = {
            'image_name': vuln_data.image_name,
            'total_vulnerabilities': vuln_data.total_vulnerabilities,
            'severity_breakdown': vuln_data.severity_breakdown,
            'vulnerabilities': vuln_data.vulnerabilities,
            'scan_successful': vuln_data.scan_successful,
            'error_message': vuln_data.error_message,
            'was_retried': vuln_data.was_retried,
            'original_image_name': vuln_data.original_image_name,
            'timestamp': time.time(),
            'digest': digest
        }
        
        cache_data[cache_key] = cache_entry
        self._save_cache(cache_data)
        logger.info(f"Cached scan result for {image_name} (digest: {digest[:16]}...)")
        
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
        # Check cache first
        cached_result = self._get_cached_scan_result(image_name)
        if cached_result:
            return cached_result
        
        # No cache hit, perform actual scan
        result = self._scan_image_with_retry(image_name, retry=True)
        
        # Cache the result if scan was successful
        if result.scan_successful:
            self._cache_scan_result(image_name, result)
        
        return result
    
    def _categorize_scan_error(self, error_output: str, image_name: str) -> Tuple[str, str]:
        """Categorize scan errors and return user-friendly error type and message"""
        error_lower = error_output.lower()
        
        # Authentication/Access errors
        if any(phrase in error_lower for phrase in [
            'authentication required', 'unauthorized', 'access denied', 
            'pull access denied', 'docker login', 'requested access to the resource is denied'
        ]):
            return "ACCESS_DENIED", f"Access denied for '{image_name}'. This image may be private or require authentication."
        
        # Image not found errors
        if any(phrase in error_lower for phrase in [
            'repository does not exist', 'not found', 'no such image', 
            'manifest unknown', 'image not found', 'does not exist'
        ]):
            return "IMAGE_NOT_FOUND", f"Image '{image_name}' not found. Please verify the image name and tag are correct."
        
        # Network/connectivity errors
        if any(phrase in error_lower for phrase in [
            'network', 'timeout', 'connection', 'dial tcp', 'no route to host',
            'temporary failure in name resolution'
        ]):
            return "NETWORK_ERROR", f"Network error accessing '{image_name}'. Check your internet connection."
        
        # Registry/service unavailable errors
        if any(phrase in error_lower for phrase in [
            'service unavailable', 'registry unavailable', 'server error',
            'internal server error', 'bad gateway'
        ]):
            return "REGISTRY_ERROR", f"Registry error for '{image_name}'. The image registry may be temporarily unavailable."
        
        # Platform/architecture mismatch
        if any(phrase in error_lower for phrase in [
            'no matching manifest', 'platform', 'architecture', 'unsupported platform'
        ]):
            platform_info = f" (platform: {self.platform})" if self.platform else ""
            return "PLATFORM_ERROR", f"Platform mismatch for '{image_name}'{platform_info}. Image may not be available for this architecture."
        
        # Grype-specific errors
        if any(phrase in error_lower for phrase in [
            'failed to catalog', 'grype', 'syft'
        ]):
            return "SCAN_ERROR", f"Grype failed to scan '{image_name}'. The image format may be unsupported."
        
        # Generic/unknown error
        return "UNKNOWN_ERROR", f"Unknown error scanning '{image_name}'. See logs for details."
    
    def _scan_image_with_retry(self, image_name: str, retry: bool = True) -> VulnerabilityData:
        """Internal method to scan image with optional retry logic"""
        logger.info(f"Scanning image: {image_name}")
        original_image_name = image_name
        
        try:
            # Run grype scan with JSON output (limit concurrent scans)
            with self._grype_semaphore:
                cmd = ['grype', '-o', 'json']
                if self.platform:
                    cmd.extend(['--platform', self.platform])
                cmd.append(image_name)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_per_image)
            
            if result.returncode != 0:
                # If scan failed and retry is enabled, try fallback strategies
                if retry:
                    # Log initial failure as warning (not error yet)
                    error_type, user_friendly_msg = self._categorize_scan_error(result.stderr, image_name)
                    logger.warning(f"[{error_type}] Initial scan failed for {image_name}, trying fallback strategies...")
                    
                    # Strategy 1: Try with :latest tag if not already using it (skip for digest-based images)
                    if not image_name.endswith(':latest') and '@sha256:' not in image_name:
                        logger.info(f"Retrying {image_name} with :latest tag")
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
                    
                    # Strategy 2: Try mirror.gcr.io fallback for Docker Hub images
                    mirror_image = self._try_mirror_gcr_fallback(original_image_name)
                    if mirror_image:
                        logger.info(f"Trying mirror.gcr.io fallback for {original_image_name} -> {mirror_image}")
                        mirror_result = self._scan_image_with_retry(mirror_image, retry=False)
                        
                        if mirror_result.scan_successful:
                            logger.info(f"Mirror.gcr.io fallback successful for {mirror_image}")
                            return VulnerabilityData(
                                image_name=mirror_result.image_name,
                                total_vulnerabilities=mirror_result.total_vulnerabilities,
                                severity_breakdown=mirror_result.severity_breakdown,
                                vulnerabilities=mirror_result.vulnerabilities,
                                scan_successful=True,
                                was_retried=True,
                                original_image_name=original_image_name
                            )
                
                # All fallback strategies failed - log as final ERROR
                error_type, user_friendly_msg = self._categorize_scan_error(result.stderr, image_name)
                logger.error(f"[{error_type}] All retry attempts failed for {image_name}: {user_friendly_msg}")
                # Log detailed error for debugging
                if result.stderr.strip():
                    logger.debug(f"Detailed error for {image_name}: {result.stderr}")
                self.failed_scans.append(original_image_name)
                return VulnerabilityData(
                    image_name=image_name,
                    total_vulnerabilities=0,
                    severity_breakdown={},
                    vulnerabilities=[],
                    scan_successful=False,
                    error_message=user_friendly_msg,
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
            # If scan timed out and retry is enabled, try fallback strategies
            if retry:
                logger.warning(f"[TIMEOUT] Initial scan timeout for {image_name}, trying fallback strategies...")
                
                # Strategy 1: Try with :latest tag if not already using it (skip for digest-based images)
                if not image_name.endswith(':latest') and '@sha256:' not in image_name:
                    logger.info(f"Retrying {image_name} with :latest tag after timeout")
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
                
                # Strategy 2: Try mirror.gcr.io fallback for Docker Hub images
                mirror_image = self._try_mirror_gcr_fallback(original_image_name)
                if mirror_image:
                    logger.info(f"Trying mirror.gcr.io fallback after timeout for {original_image_name} -> {mirror_image}")
                    mirror_result = self._scan_image_with_retry(mirror_image, retry=False)
                    
                    if mirror_result.scan_successful:
                        logger.info(f"Mirror.gcr.io fallback successful for {mirror_image}")
                        return VulnerabilityData(
                            image_name=mirror_result.image_name,
                            total_vulnerabilities=mirror_result.total_vulnerabilities,
                            severity_breakdown=mirror_result.severity_breakdown,
                            vulnerabilities=mirror_result.vulnerabilities,
                            scan_successful=True,
                            was_retried=True,
                            original_image_name=original_image_name
                        )
            
            user_friendly_msg = f"Scan timeout for '{image_name}'. The image may be very large or the network connection is slow."
            logger.error(f"[TIMEOUT] All retry attempts failed for {image_name}: {user_friendly_msg}")
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=user_friendly_msg,
                original_image_name=original_image_name
            )
        except json.JSONDecodeError as e:
            user_friendly_msg = f"Failed to parse scan results for '{image_name}'. The scan output may be corrupted."
            logger.error(f"[PARSE_ERROR] {user_friendly_msg}")
            logger.debug(f"JSON decode error for {image_name}: {e}")
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=user_friendly_msg,
                original_image_name=original_image_name
            )
        except Exception as e:
            user_friendly_msg = f"Unexpected error scanning '{image_name}'. Check the image name and try again."
            logger.error(f"[UNEXPECTED_ERROR] {user_friendly_msg}")
            logger.debug(f"Unexpected error details for {image_name}: {e}")
            self.failed_scans.append(original_image_name)
            return VulnerabilityData(
                image_name=image_name,
                total_vulnerabilities=0,
                severity_breakdown={},
                vulnerabilities=[],
                scan_successful=False,
                error_message=user_friendly_msg,
                original_image_name=original_image_name
            )
    
    def scan_image_pair(self, image_pair: ImagePair) -> ScanResult:
        """Scan both images in a pair and return combined result"""
        # Get current progress for logging
        with self._lock:
            current_progress = f"[{self.completed_pairs + 1}/{self.total_pairs}]"
        
        logger.info(f"{current_progress} Scanning pair: {image_pair.chainguard_image} vs {image_pair.customer_image}")
        
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
                self.completed_pairs += 1
                progress = f"[{self.completed_pairs}/{self.total_pairs}]"
            
            logger.warning(f"{progress} Row failed - {error_msg}")
            
            return ScanResult(
                image_pair=image_pair,
                chainguard_data=chainguard_result,
                customer_data=customer_result,
                scan_successful=False,
                error_message=error_msg
            )
        
        # Update progress counter
        with self._lock:
            self.completed_pairs += 1
            progress = f"[{self.completed_pairs}/{self.total_pairs}]"
        
        logger.info(f"{progress} Row completed successfully: {chainguard_result.total_vulnerabilities} vs {customer_result.total_vulnerabilities} vulnerabilities")
        
        return ScanResult(
            image_pair=image_pair,
            chainguard_data=chainguard_result,
            customer_data=customer_result,
            scan_successful=True
        )
    
    def scan_image_pairs_parallel(self, image_pairs: List[ImagePair], max_workers: int = 4) -> List[ScanResult]:
        """Scan multiple image pairs in parallel"""
        self.total_pairs = len(image_pairs)
        self.completed_pairs = 0
        logger.info(f"Scanning {len(image_pairs)} image pairs with {max_workers} workers")
        
        successful_results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan jobs
            future_to_pair = {
                executor.submit(self.scan_image_pair, pair): pair 
                for pair in image_pairs
            }
            
            # Collect results as they complete, with timeout to prevent indefinite hanging
            # Use a reasonable timeout that allows for parallel processing
            # Assume worst case: all jobs run serially with 2x timeout plus buffer
            total_timeout = min((self.timeout_per_image * 2 + 60) * len(image_pairs) // max_workers, 3600)  # Cap at 1 hour
            try:
                for future in as_completed(future_to_pair, timeout=total_timeout):
                    pair = future_to_pair[future]
                    try:
                        result = future.result()
                        if result.scan_successful:
                            successful_results.append(result)
                        else:
                            logger.warning(f"Skipping failed row: {pair.chainguard_image} | {pair.customer_image}")
                    except Exception as e:
                        with self._lock:
                            self.completed_pairs += 1
                            progress = f"[{self.completed_pairs}/{self.total_pairs}]"
                            self.failed_rows.append(f"{pair.chainguard_image} | {pair.customer_image}")
                        
                        error_msg = f"Unexpected error scanning pair {pair.chainguard_image} | {pair.customer_image}: {e}"
                        logger.error(f"{progress} {error_msg}")
            except TimeoutError:
                logger.error(f"Timeout waiting for {len(future_to_pair)} scanning jobs to complete after {total_timeout} seconds")
                # Cancel any remaining futures and mark them as failed
                for future, pair in future_to_pair.items():
                    if not future.done():
                        future.cancel()
                        with self._lock:
                            self.failed_rows.append(f"{pair.chainguard_image} | {pair.customer_image}")
                        logger.warning(f"Cancelled stuck scan job: {pair.chainguard_image} | {pair.customer_image}")
        
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
            rows = list(csv_reader)
            
            if not rows:
                logger.error("CSV file is empty")
                return []
            
            # Determine if first row is a header and column order
            first_row = rows[0]
            if len(first_row) < 2:
                logger.error("CSV must have at least 2 columns")
                return []
            
            col1 = str(first_row[0]).strip().lower()
            col2 = str(first_row[1]).strip().lower()
            
            # Check if first row is a header
            header_keywords = ['customer_image', 'chainguard_image', 'image_name', 'customer image', 'chainguard image']
            is_header = any(keyword in col1 for keyword in header_keywords) or \
                       any(keyword in col2 for keyword in header_keywords)
            
            # Determine column order
            customer_first = True  # Default assumption
            if is_header:
                # Use header to determine column order
                if 'chainguard' in col1 or ('customer' in col2 and 'chainguard' not in col2):
                    customer_first = False
                data_start = 1  # Skip header row
            else:
                # No header - use heuristics to detect column order
                # Chainguard images typically start with cgr.dev
                if first_row[0].strip().startswith('cgr.dev') and not first_row[1].strip().startswith('cgr.dev'):
                    customer_first = False
                elif first_row[1].strip().startswith('cgr.dev') and not first_row[0].strip().startswith('cgr.dev'):
                    customer_first = True
                # If both or neither start with cgr.dev, stick with default (customer first)
                data_start = 0  # Process all rows as data
            
            logger.info(f"Parsing CSV with column order: {'customer, chainguard' if customer_first else 'chainguard, customer'}")
            
            # Process data rows
            for line_num, row in enumerate(rows[data_start:], data_start + 1):
                # Skip empty rows
                if not row or len(row) == 0:
                    continue
                
                # Skip comment rows (first cell starts with #)
                if str(row[0]).strip().startswith('#'):
                    continue
                
                if len(row) < 2:
                    logger.warning(f"CSV row {line_num}: Expected at least 2 columns, got {len(row)}. Skipping.")
                    continue
                
                # Assign columns based on detected order
                if customer_first:
                    customer_image = str(row[0]).strip()
                    chainguard_image = str(row[1]).strip()
                else:
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
                and Chainguard's hardened alternatives. Analysis of {self._format_number(metrics['images_scanned'])} image pairs 
                shows a <strong>{metrics['reduction_percentage']}% overall CVE reduction</strong>, with 
                {self._format_number(metrics['total_reduction'])} fewer vulnerabilities when using Chainguard images.</p>
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
            '{{images_scanned}}': self._format_number(metrics['images_scanned']),
            '{{total_customer_vulns}}': self._format_number(metrics['total_customer_vulns']),
            '{{total_chainguard_vulns}}': self._format_number(metrics['total_chainguard_vulns']),
            '{{total_reduction}}': self._format_number(metrics['total_reduction']),
            '{{reduction_percentage}}': f"{metrics['reduction_percentage']}%",
            '{{average_reduction_per_image}}': f"{metrics['average_reduction_per_image']}%",
            '{{images_with_reduction}}': self._format_number(metrics['images_with_reduction']),
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
        <div class="image-comparison-section no-break cve-reduction-section">
            <h2>CVE Reduction Analysis</h2>
            <div style="text-align: center; margin-bottom: 30px;">
                <div class="total-box reduction-box" style="display: block; margin: 0 auto 20px auto; width: 300px;">
                    {metrics['reduction_percentage']}%
                    <span>CVE Reduction</span>
                </div>
                <p style="text-align: center; margin: 0; font-size: 16px; color: var(--cg-primary);"><strong>{self._format_number(metrics['total_reduction'])}</strong> fewer vulnerabilities with Chainguard images</p>
            </div>
            
            <!-- Overview Section within CVE Reduction Analysis -->
            <div class="overview-grid" style="margin-top: 40px;">
                <!-- Customer Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Your Images</h2>
                        <div class="total-box customer-total">
                            {self._format_number(customer_total)}
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
                            {self._format_number(chainguard_total)}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_boxes(chainguard_summary)}
                    </div>
                </div>
            </div>
        </div>

        <!-- Image Comparison Table -->
        <div class="images-scanned-section">
            <h2>Images Scanned</h2>
            {self._generate_vulnerability_legend()}
            <div class="image-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Your Image</th>
                            <th>Total Vulnerabilities</th>
                            <th>Chainguard Image <span style="font-size: 0.8em; font-weight: normal;">(cgr.dev)</span></th>
                            <th>Total Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_comparison_table_rows(image_pairs)}
                    </tbody>
                </table>
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
        
        # Clean up chainguard image references - remove registry path from cgr.dev images
        import re
        # Replace cgr.dev/chainguard-private/imagename:tag with just imagename:tag
        html_content = re.sub(r'cgr\.dev/chainguard-private/([^<\s]+)', r'\1', html_content)
        # Replace cgr.dev/chainguard/imagename:tag with just imagename:tag  
        html_content = re.sub(r'cgr\.dev/chainguard/([^<\s]+)', r'\1', html_content)
        # Replace cgr.dev/cg/imagename:tag with just imagename:tag
        html_content = re.sub(r'cgr\.dev/cg/([^<\s]+)', r'\1', html_content)
        
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
                                    <td class="severity-count">{self._format_number(count)}</td>
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
                badges.append(f'<span class="vuln-badge vuln-{severity_class}">{self._format_number(count)}</span>')
        
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
                    <div class="legend-item">
                        <span class="vuln-badge vuln-clean legend-badge">Clean</span>
                        <span class="legend-label">No Vulnerabilities</span>
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
        border: 1px solid currentColor !important;
        box-shadow: none !important;
        font-size: 10px !important;
        padding: 1px 3px !important;
        min-width: 16px !important;
        line-height: 1 !important;
        flex-shrink: 0 !important;
    }
    
    .vuln-breakdown-container {
        gap: 1px !important;
        padding: 2px !important;
        flex-wrap: nowrap !important;
        white-space: nowrap !important;
    }
    
    .vuln-code {
        font-size: 7px !important;
    }
    
    .vuln-count {
        font-size: 8px !important;
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
        width: 16px;
        height: 16px;
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
    width: 18px;
    height: 18px;
    border-radius: 3px;
    margin-right: 8px;
    vertical-align: middle;
}

/* Severity indicator colors with new color scheme */
.severity-indicator.critical { 
    background: #f2e4f8;
    color: #82349d;
    border: 1px solid #c08ad5;
}
.severity-indicator.high { 
    background: #fbe7e8;
    color: #98362e;
    border: 1px solid #ee7f78;
}
.severity-indicator.medium { 
    background: #fcebcc;
    color: #a1531e;
    border: 1px solid #f3ad56;
}
.severity-indicator.low { 
    background: #fefad3;
    color: #76651d;
    border: 1px solid #f7d959;
}
.severity-indicator.negligible { 
    background: #e8ecef;
    color: #4d5b6a;
    border: 1px solid #b8c2ca;
}
.severity-indicator.unknown { 
    background: #ffffff;
    color: #4d5b6a;
    border: 1px solid #b8c2ca;
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

/* CVE Reduction section should start on new page */
.cve-reduction-section {
    page-break-before: always;
}

/* Images Scanned section - keep everything together */
.images-scanned-section {
    margin-top: 40px;
    margin-bottom: 40px;
    padding: 20px;
    border: 2px solid var(--cg-light);
    background: var(--cg-white);
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    page-break-inside: avoid;
}

.images-scanned-section h2 {
    page-break-after: avoid;
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
    page-break-before: avoid;
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
    text-align: left;
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
    text-align: left;
}

.no-match {
    color: var(--cg-gray-dark);
    font-style: italic;
    font-weight: 500;
}

/* Enhanced vulnerability breakdown styling for table cells */
.vuln-breakdown-container {
    display: flex;
    flex-wrap: wrap;
    gap: 2px;
    justify-content: flex-start;
    align-items: center;
    padding: 4px 2px;
    line-height: 1.2;
}

.vuln-badge {
    display: inline-flex;
    align-items: center;
    gap: 1px;
    padding: 3px 4px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    border: 1px solid;
    white-space: nowrap;
    min-width: 20px;
    justify-content: center;
    line-height: 1;
}

.vuln-code {
    font-weight: 700;
    opacity: 0.9;
    font-size: 8px;
}

.vuln-count {
    font-weight: 800;
    font-size: 9px;
    margin-left: 1px;
}

/* Severity-specific badge colors with new color scheme */
.vuln-critical {
    background: #f2e4f8;
    color: #82349d;
    border-color: #c08ad5;
}

.vuln-high {
    background: #fbe7e8;
    color: #98362e;
    border-color: #ee7f78;
}

.vuln-medium {
    background: #fcebcc;
    color: #a1531e;
    border-color: #f3ad56;
}

.vuln-low {
    background: #fefad3;
    color: #76651d;
    border-color: #f7d959;
}

.vuln-negligible {
    background: #e8ecef;
    color: #4d5b6a;
    border-color: #b8c2ca;
}

.vuln-unknown {
    background: #ffffff;
    color: #4d5b6a;
    border-color: #b8c2ca;
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
}

/* Vulnerability legend styling */
.vulnerability-legend {
    margin: 20px 0 30px 0;
    padding: 16px 20px;
    background: var(--cg-gray-light);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    page-break-inside: avoid;
    page-break-after: avoid;
}

.vulnerability-legend h3 {
    margin: 0 0 12px 0;
    font-size: 14px;
    font-weight: 600;
    color: var(--cg-primary);
    border: none;
    padding: 0;
    text-align: left;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    justify-content: flex-start;
    align-items: center;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
}

.legend-badge {
    transform: scale(1.1);
}

.legend-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--cg-primary);
}

@media print {
    .vulnerability-legend {
        page-break-inside: avoid;
        page-break-after: avoid;
        break-inside: avoid;
        break-after: avoid;
        margin: 15px 0 20px 0;
        padding: 12px 16px;
    }
    
    .legend-items {
        gap: 12px;
    }
    
    .legend-item {
        gap: 4px;
    }
    
    .legend-badge {
        transform: scale(1.0);
    }
    
    .legend-label {
        font-size: 11px;
    }
}

"""
    
    def _get_current_datetime(self) -> str:
        """Get current datetime formatted string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _format_number(self, number: int) -> str:
        """Format number with comma separators for readability"""
        return f"{number:,}"
    
    def _has_registry_prefix(self, image_name: str) -> bool:
        """Check if image name has a registry prefix (not Docker Hub default)"""
        # Docker Hub images can be:
        # - library/image:tag (official images)
        # - username/image:tag (user images)
        # - image:tag (shorthand for library/image:tag)
        
        # If it contains a '.' or ':' before the first '/', it likely has a registry
        if '/' in image_name:
            registry_part = image_name.split('/')[0]
            # Check if registry part contains a dot (domain) or port
            if '.' in registry_part or ':' in registry_part:
                return True
        
        return False
    
    def _try_mirror_gcr_fallback(self, image_name: str) -> Optional[str]:
        """Try to create a mirror.gcr.io fallback for Docker Hub images"""
        if self._has_registry_prefix(image_name):
            return None  # Already has registry prefix
        
        # For Docker Hub images without explicit registry, try mirror.gcr.io
        if '/' not in image_name:
            # Single name image (e.g., "ubuntu:20.04" -> "mirror.gcr.io/library/ubuntu:20.04")
            return f"mirror.gcr.io/library/{image_name}"
        else:
            # User/org image (e.g., "user/repo:tag" -> "mirror.gcr.io/user/repo:tag")
            return f"mirror.gcr.io/{image_name}"
    
    def _analyze_failed_scans(self) -> Dict[str, List[str]]:
        """Analyze failed scans and categorize them by error type"""
        error_categories = {
            "ACCESS_DENIED": [],
            "IMAGE_NOT_FOUND": [],
            "NETWORK_ERROR": [],
            "REGISTRY_ERROR": [],
            "PLATFORM_ERROR": [],
            "SCAN_ERROR": [],
            "TIMEOUT": [],
            "PARSE_ERROR": [],
            "UNEXPECTED_ERROR": [],
            "UNKNOWN_ERROR": []
        }
        
        # This would need to be enhanced to track error types per image
        # For now, return empty categories
        return error_categories
    
    def print_failure_summary(self):
        """Print a summary of failed scans by category"""
        if not self.failed_scans and not self.failed_rows:
            return
        
        logger.info("=" * 60)
        logger.info("SCAN FAILURE SUMMARY")
        logger.info("=" * 60)
        
        if self.failed_rows:
            logger.warning(f"Failed to scan {len(self.failed_rows)} image pairs (excluded from results):")
            for i, row in enumerate(self.failed_rows, 1):
                logger.warning(f"  {i}. {row}")
            logger.info("")
        
        if self.failed_scans:
            logger.warning(f"Individual image scan failures: {len(self.failed_scans)}")
            for i, image in enumerate(self.failed_scans, 1):
                logger.warning(f"  {i}. {image}")
            logger.info("")
        
        # Provide helpful suggestions
        logger.info("TROUBLESHOOTING TIPS:")
        logger.info("• For ACCESS_DENIED errors: Check if images are private and require authentication")
        logger.info("• For IMAGE_NOT_FOUND errors: Verify image names and tags are correct")
        logger.info("• For NETWORK_ERROR: Check internet connection and registry accessibility")
        logger.info("• For TIMEOUT errors: Try increasing --timeout-per-image or check network speed")
        logger.info("• Use --platform flag if images are not available for your architecture")
        logger.info("• Docker Hub rate limits: The tool automatically tries mirror.gcr.io as fallback")
        logger.info("=" * 60)
    
    def write_failed_pairs_csv(self, output_file: str):
        """Write failed image pairs to a CSV file for retry/debugging"""
        if not self.failed_rows:
            logger.info("No failed image pairs to write.")
            return
        
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Customer_Image', 'Chainguard_Image'])
                
                # Parse and write failed rows
                for failed_row in self.failed_rows:
                    # Failed rows are stored as "chainguard_image | customer_image" format
                    if ' | ' in failed_row:
                        chainguard_img, customer_img = failed_row.split(' | ', 1)
                        # Write in the correct order: customer first, then chainguard
                        writer.writerow([customer_img.strip(), chainguard_img.strip()])
                    else:
                        # Fallback for unexpected format
                        writer.writerow([failed_row, ''])
            
            logger.info(f"Failed image pairs written to: {output_file}")
            logger.info(f"Total failed pairs: {len(self.failed_rows)}")
            
        except Exception as e:
            logger.error(f"Failed to write failed pairs CSV: {e}")

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
  
  # With cache control:
  %(prog)s -s image_pairs.csv -o report.html --cache-ttl 48 --cache-dir ./my_cache
  
  # With failed pairs output:
  %(prog)s -s image_pairs.csv -o report.html --failed-pairs-output failed_images.csv

File Format:
  CSV: Customer_Image,Chainguard_Image
  
Performance:
  Use --max-workers to control parallel scanning (default: 4)
  Rows with any failed scans are excluded from results
  
Caching:
  Scan results are cached using image digests for 24 hours by default
  Use --no-cache to disable caching or --clear-cache to start fresh

Registry Fallback:
  Docker Hub images automatically fallback to mirror.gcr.io on failure
  This helps with rate limits and connectivity issues
        """
    )
    
    parser.add_argument('-s', '--source', required=True,
                       help='Source: CSV file with Chainguard and Customer image pairs')
    parser.add_argument('-o', '--output', required=True,
                       help='Output HTML file path')
    parser.add_argument('-e', '--exec-summary', 
                       help='Optional markdown file for executive summary')
    parser.add_argument('-a', '--appendix', 
                       help='Optional markdown file for appendix content')
    parser.add_argument('--max-workers', type=int, default=4,
                       help='Maximum number of parallel scanning threads (default: 4)')
    parser.add_argument('--timeout-per-image', type=int, default=300,
                       help='Timeout in seconds per Grype vulnerability scan (default: 300)')
    parser.add_argument('-c', '--customer-name', 
                       help='Customer name for report footer (default: "Customer")')
    parser.add_argument('--platform', 
                       help='Platform to use for Grype scans (e.g., "linux/amd64", "linux/arm64")')
    parser.add_argument('--cache-dir', default='.cache',
                       help='Directory to store scan cache (default: .cache)')
    parser.add_argument('--cache-ttl', type=int, default=24,
                       help='Cache TTL in hours (default: 24)')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable caching and rescan all images')
    parser.add_argument('--clear-cache', action='store_true',
                       help='Clear existing cache before starting')
    parser.add_argument('--no-fresh-check', action='store_true',
                       help='Skip checking for fresh image versions (faster but may use stale images)')
    parser.add_argument('--failed-pairs-output', 
                       help='Output CSV file path for failed image pairs')
    
    args = parser.parse_args()
    
    # Initialize scanner with cache settings
    cache_ttl = 0 if args.no_cache else args.cache_ttl
    scanner = CVEScanner(
        platform=args.platform,
        cache_dir=args.cache_dir,
        cache_ttl_hours=cache_ttl,
        timeout_per_image=args.timeout_per_image,
        check_fresh_images=not args.no_fresh_check
    )
    
    # Handle cache clearing
    if args.clear_cache:
        logger.info("Clearing existing cache...")
        if scanner.cache_file.exists():
            scanner.cache_file.unlink()
            scanner._setup_cache()
        logger.info("Cache cleared.")
    
    if args.no_cache:
        logger.info("Cache disabled - all images will be rescanned")
    
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
    
    # Print detailed failure summary with troubleshooting tips
    scanner.print_failure_summary()
    
    # Write failed pairs to CSV if requested
    if args.failed_pairs_output and scanner.failed_rows:
        scanner.write_failed_pairs_csv(args.failed_pairs_output)
    
    # Final success message
    total_pairs = len(scan_results) + len(scanner.failed_rows)
    success_rate = (len(scan_results) / total_pairs * 100) if total_pairs > 0 else 0
    logger.info(f"Scan complete! Successfully processed {len(scan_results)} of {total_pairs} image pairs ({success_rate:.1f}% success rate).")

if __name__ == "__main__":
    main()