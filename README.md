# Chainguard CVE Vulnerability Scanner

A Python tool that demonstrates Chainguard's value proposition by scanning container images for CVE vulnerabilities and generating professional HTML reports comparing customer images with Chainguard alternatives.

## Features

- **CVE Vulnerability Scanning**: Uses Grype to scan container images for vulnerabilities
- **Chainguard Comparison**: Automatically finds and scans corresponding Chainguard images
- **Professional HTML Reporting**: Generates PDF-optimized HTML reports with Chainguard branding
- **Intelligent Caching**: Digest-based caching system to avoid re-scanning identical images
- **Registry Fallback**: Automatic fallback to mirror.gcr.io for Docker Hub connectivity issues
- **Executive Summary**: Supports custom markdown executive summaries with template variables
- **Custom Appendix**: Add organization-specific content to reports with `-a` flag
- **Progress Tracking**: Provides detailed scan progress and error reporting
- **Flexible Input**: Accepts CSV file inputs
- **PDF-Optimized Styling**: Clean layout designed for professional PDF conversion

## Requirements

- Python 3.6+
- [Grype](https://github.com/anchore/grype) vulnerability scanner
- Optional: `markdown` Python package for enhanced markdown support

## Installation

1. Install Grype:
   ```bash
   # macOS
   brew install anchore/grype/grype
   
   # Linux
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
   ```

2. Install Python dependencies (optional):
   ```bash
   pip install -r requirements.txt
   ```

## Usage

The tool supports CSV format with **parallel scanning** for improved performance:
**NOTE** Print the output HTML to pdf via your web browser. **Ensure no margins!**

```bash
# CSV format (best performance with parallel scanning)
python3 cve_scanner.py -s sample.csv -o report.html -e sample-exec-summary.md --max-workers 8

# With custom appendix
python3 cve_scanner.py -s sample.csv -o report.html -e sample-exec-summary.md -a sample-appendix.md

# With customer name for branding
python3 cve_scanner.py -s sample.csv -o report.html -c "Sample Customer"

# With caching options
python3 cve_scanner.py -s sample.csv -o report.html --cache-ttl 48 --cache-dir ./my_cache

# Disable caching for fresh scans
python3 cve_scanner.py -s sample.csv -o report.html --no-cache

# Clear existing cache and start fresh
python3 cve_scanner.py -s sample.csv -o report.html --clear-cache

# Generate a CSV of failed image pairs for retry/analysis
python3 cve_scanner.py -s sample.csv -o report.html --failed-pairs-output failed_images.csv

# Complete example with all options
python3 cve_scanner.py -s sample.csv -o sample-customer.html -e sample-exec-summary.md -a sample-appendix.md -c "Sample Customer" --max-workers 2 --cache-ttl 24 --failed-pairs-output failed.csv

```

**CSV Format (Recommended):**
```csv
Customer_Image,Chainguard_Image
prom/prometheus:latest, cgr.dev/chainguard-private/prometheus
openjdk:21,cgr.dev/chainguard-private/jdk:openjdk-21
nginx,cgr.dev/chainguard-private/nginx
logstash:7.17.0,cgr.dev/chainguard-private/logstash:7
```



### Command Line Options

**Required:**
- `-s, --source`: Source images (required)
  - **CSV file**: `image_pairs.csv`
- `-o, --output`: Output HTML file path (required)

**Optional:**
- `-e, --exec-summary`: Optional markdown file for executive summary
- `-a, --appendix`: Optional markdown file for custom appendix content (appears above methodology)
- `-c, --customer-name`: Customer name for report footer (default: "Customer")
- `--max-workers`: Number of parallel scanning threads (default: 4)
- `--timeout-per-image`: Timeout in seconds per image scan (default: 300)
- `--platform`: Platform to use for Grype scans (e.g., "linux/amd64", "linux/arm64")

**Caching Options:**
- `--cache-dir`: Directory to store scan cache (default: .cache)
- `--cache-ttl`: Cache TTL in hours (default: 24)
- `--no-cache`: Disable caching and rescan all images
- `--clear-cache`: Clear existing cache before starting

**Output Options:**
- `--failed-pairs-output`: Output CSV file path for failed image pairs


## Sample Files

- `sample.csv`: Example CSV format file with image pairs
- `sample-exec-summary.md`: Example executive summary with template variables
- `sample-appendix.md`: Comprehensive appendix with methodology and best practices

## Performance Features

- **Parallel Scanning**: Uses multi-threading to scan multiple images simultaneously
- **Intelligent Caching**: Digest-based caching avoids re-scanning identical images
- **Row-Level Validation**: If any image in a row fails to scan, the entire row is excluded from results
- **Multi-Tier Retry Logic**: 
  - First retry with `:latest` tag
  - Then fallback to `mirror.gcr.io` for Docker Hub images
- **Configurable Workers**: Control parallelism with `--max-workers` (default: 4)
- **Progress Tracking**: Real-time feedback on scan progress and failures
- **Performance Gain**: Typically 3-5x faster than sequential scanning, even faster with cache hits

## Caching System

The tool includes a sophisticated caching system to dramatically improve performance on repeated scans:

### How It Works
- **Image Digest Verification**: Uses Docker/Podman to get the actual SHA256 digest of images
- **Cache Key Generation**: Creates unique cache keys combining image name, digest, and platform
- **Automatic Cache Management**: Stores successful scan results in JSON format with timestamps
- **TTL-Based Expiration**: Cached results expire after 24 hours by default (configurable)

### Benefits
- **Skip Identical Scans**: If the same image (by digest) was scanned recently, use cached results
- **Platform Awareness**: Different cache entries for different platforms (linux/amd64, linux/arm64, etc.)
- **Tag-Independent**: Even if tags change, identical image content uses cached results
- **Significant Speed Improvements**: Cached scans return instantly vs. minutes for fresh scans

### Cache Management
```bash
# Use custom cache directory and TTL
python3 cve_scanner.py -s sample.csv -o report.html --cache-dir /path/to/cache --cache-ttl 48

# Disable caching completely
python3 cve_scanner.py -s sample.csv -o report.html --no-cache

# Clear existing cache and start fresh
python3 cve_scanner.py -s sample.csv -o report.html --clear-cache
```

### Cache Location
- **Default**: `.cache/scan_cache.json` in the current directory
- **Customizable**: Use `--cache-dir` to specify a different location
- **Portable**: Cache files can be shared between team members or CI/CD systems

## Registry Fallback System

The tool automatically handles Docker Hub connectivity issues and rate limiting:

### How It Works
- **Docker Hub Detection**: Identifies images without explicit registry prefixes
- **Automatic Fallback**: If Docker Hub scan fails, tries `mirror.gcr.io` equivalent
- **Smart Mapping**: 
  - `ubuntu:20.04` → `mirror.gcr.io/library/ubuntu:20.04`
  - `user/repo:tag` → `mirror.gcr.io/user/repo:tag`
- **Transparent Operation**: Uses mirror results but maintains original image names in reports

### Benefits
- **Improved Success Rates**: Handles Docker Hub rate limits and outages
- **No Configuration Required**: Automatically attempts fallback on failures
- **Maintains Accuracy**: Original image names preserved in all reports and logs
- **Comprehensive Coverage**: Works with both official and user images

### Retry Strategy
1. **Initial Scan**: Try original image name
2. **Tag Retry**: If fails, try with `:latest` tag (existing behavior)
3. **Registry Fallback**: If still fails and it's a Docker Hub image, try `mirror.gcr.io`
4. **Detailed Logging**: Clear messages about each retry attempt

## Failed Pairs Output

The tool can generate a CSV file containing all image pairs that failed to scan:

### Usage
```bash
# Generate failed pairs CSV
python3 cve_scanner.py -s input.csv -o report.html --failed-pairs-output failed_images.csv

# Use failed pairs as input for retry
python3 cve_scanner.py -s failed_images.csv -o retry_report.html
```

### CSV Format
The failed pairs CSV uses the same format as input files:
```csv
Customer_Image,Chainguard_Image
bibinwilson/docker-kubectl-dig:0.2,cgr.dev/chainguard-private/kubectl
some/failing-image:tag,cgr.dev/chainguard-private/alternative
```

### Benefits
- **Easy Retry**: Use the generated CSV as input for subsequent scan attempts
- **Failure Analysis**: Analyze patterns in failed images (authentication, network, etc.)
- **Debugging**: Clear list of specific image pairs that need attention
- **CI/CD Integration**: Automate handling of scan failures in pipelines
- **Incremental Processing**: Focus re-scanning efforts on previously failed images

### When Files Are Generated
- Only created when `--failed-pairs-output` flag is provided
- Only generated if there are actually failed pairs
- Includes all pairs where either customer or Chainguard image failed to scan

## Report Features

The generated HTML report includes:

1. **Professional Header**: Chainguard-branded banner with 3D Linky mascot
2. **Executive Summary**: Customizable markdown content with dynamic data interpolation
3. **CVE Reduction Analysis**: Prominent display of percentage reduction and impact metrics
4. **Integrated Overview**: Customer vs Chainguard images within the same section
5. **Detailed Table**: Image-by-image vulnerability counts with retry indicators
6. **Comprehensive Appendix**: 
   - Custom content (when using `-a` flag) appears first
   - Standard methodology and severity classifications
   - About Chainguard Images (including provenance tracking)
   - Report generation details
7. **PDF-Optimized Styling**: Clean table-based layouts for reliable PDF conversion
8. **Structured Severity Display**: Professional table format with color-coded severity indicators for improved readability
9. **Professional Branding**: Elegant Chainguard theme with proper spacing and typography

## PDF Conversion

The HTML reports are specifically optimized for PDF conversion:

- **Table-based layouts** instead of flexbox for better PDF compatibility
- **Structured severity tables** with proper headers and color-coded indicators
- **Fixed table layouts** prevent content overflow
- **Page break controls** to avoid section splitting
- **Professional color scheme** using Chainguard brand colors
- **Consistent typography** and spacing throughout
- **White bounding boxes** for clear section separation

## Custom Appendix

Use the `-a` flag to add organization-specific content to your reports:

```bash
python3 cve_scanner.py -s sample.csv -o report.html -a sample-appendix.md
```

The appendix structure will be:
1. **Your custom content** (from markdown file)
2. **Methodology** (standard)
3. **Severity Levels** (standard)
4. **About Chainguard Images** (standard, with provenance info)
5. **Report Generation** (standard)

## Customer Branding

Use the `-c` flag to customize the report footer with your organization's name for professional branding:

```bash
python3 cve_scanner.py -s sample.csv -o report.html -c "Your Organization"
```

This will generate a footer that reads: `"This report is Your Organization & Chainguard Confidential | Generated on [timestamp]"`

**Benefits:**
- **Professional appearance** for client-facing reports
- **Brand consistency** across vulnerability assessments
- **Customizable footers** for different business units or customers
- **Default fallback** to "Customer" if no name is specified

## Retry Logic

When an image scan fails, the tool automatically:
1. Retries the scan using the `:latest` tag (if no tag was specified)
2. Marks successful retries with an asterisk (*) in the report
3. If both attempts fail, excludes the entire row from results
4. Reports all failures in CLI output for debugging

## Executive Summary Template Variables

The executive summary and appendix markdown files can use template variables that are automatically replaced with scan results and customer information:

**Scan Metrics:**
- `{{images_scanned}}`: Number of image pairs successfully scanned
- `{{total_customer_vulns}}`: Total vulnerabilities in customer images
- `{{total_chainguard_vulns}}`: Total vulnerabilities in Chainguard images  
- `{{total_reduction}}`: Absolute number of vulnerabilities eliminated
- `{{reduction_percentage}}`: Percentage CVE reduction (with % symbol)
- `{{average_reduction_per_image}}`: Average % reduction per improved image
- `{{images_with_reduction}}`: Number of images showing improvement

**Customer Information:**
- `{{customer_name}}`: Customer name from `-c` parameter (defaults to "Customer")

**Example Usage:**
```markdown
# Security Vulnerability Assessment for {{customer_name}}

This comprehensive vulnerability assessment demonstrates the challenges that {{customer_name}} faces in managing CVEs at scale. Analysis of {{images_scanned}} images shows **{{reduction_percentage}} CVE reduction**, eliminating {{total_reduction}} vulnerabilities across your infrastructure.

{{customer_name}} is not alone in this challenge, however this report shows the significant security advantages of migrating to Chainguard's hardened alternatives.
```

## CVE Reduction Metrics

The tool automatically calculates and displays:
- **Overall reduction percentage**: Total CVEs eliminated across all images
- **Per-image average**: Average reduction for images that showed improvement
- **Impact summary**: Visual breakdown of total vulnerabilities before/after
- **Success rate**: How many images benefited from Chainguard alternatives


## Customer Objectives

This tool helps achieve:

- **Reduce CVE exposure** in container images
- **Mature DevSecOps practices** through automated security scanning
- **Verify and trust OSS images/packages** with comprehensive vulnerability reporting
- **Reduce toil** from platform, security & developer teams
- **Generate professional reports** for executive stakeholders

## Troubleshooting

1. **Grype not found**: Ensure Grype is installed and in your PATH
2. **Image not found**: Check image names and registry access
   - The tool automatically tries `mirror.gcr.io` fallback for Docker Hub images
3. **Scan timeouts**: Large images may take time; the tool has a 5-minute timeout per image
   - Use `--timeout-per-image` to increase timeout if needed
4. **Failed scans**: Check the CLI output for detailed error information
   - Tool provides categorized error messages (ACCESS_DENIED, IMAGE_NOT_FOUND, etc.)
   - Use `--failed-pairs-output failed.csv` to generate a list of failed pairs for retry
5. **Cache issues**: 
   - Use `--clear-cache` to start fresh if cache seems corrupted
   - Use `--no-cache` to bypass caching entirely
6. **Docker/Podman not available**: Cache will use fallback hashing (less optimal but functional)
7. **Retry failed scans**: Use the failed pairs CSV as input for subsequent runs
8. **PDF conversion issues**: The HTML is optimized for PDF - use tools like Puppeteer, wkhtmltopdf, or Chrome's print-to-PDF

## Example Output

The tool generates a professional HTML report showing:
- Executive summary with business impact calculations
- CVE reduction analysis with prominent metrics
- Total vulnerability counts for each image set
- **Severity breakdown in professional table format** with color-coded indicators (Critical, High, Medium, Low, Negligible, Unknown)
- Side-by-side comparison table
- Comprehensive appendix with methodology
- Chainguard branding and elegant styling optimized for PDF conversion
