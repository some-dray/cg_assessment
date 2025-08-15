# Chainguard CVE Vulnerability Scanner

A Python tool that demonstrates Chainguard's value proposition by scanning container images for CVE vulnerabilities and generating professional HTML reports comparing customer images with Chainguard alternatives.

## Features

- **CVE Vulnerability Scanning**: Uses Grype to scan container images for vulnerabilities
- **Chainguard Comparison**: Automatically finds and scans corresponding Chainguard images
- **Professional HTML Reporting**: Generates PDF-optimized HTML reports with Chainguard branding
- **Executive Summary**: Supports custom markdown executive summaries with template variables
- **Custom Appendix**: Add organization-specific content to reports with `-a` flag
- **Progress Tracking**: Provides detailed scan progress and error reporting
- **Flexible Input**: Accepts CSV file inputs
- **PDF-Optimized Styling**: Clean layout designed for professional PDF conversion

## Requirements

- Python 3.6+
- [Grype](https://github.com/anchore/grype) vulnerability scanner
- Optional: `markdown` Python package for enhanced markdown support
- Optional: `weasyprint` Python package for PDF generation

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
   
   # For PDF generation:
   pip install weasyprint
   ```

## Usage

The tool supports CSV format with **parallel scanning** for improved performance:

```bash
# CSV format (best performance with parallel scanning)
python3 cve_scanner.py -s sample.csv -o report.html -e sample-exec-summary.md --max-workers 8

# Generate PDF directly:
python3 cve_scanner.py -s sample.csv -o report.pdf --timeout-per-image 1200 -c "Your Company"

# With custom appendix
python3 cve_scanner.py -s sample.csv -o report.html -e sample-exec-summary.md -a sample-appendix.md

# With customer name for branding
python3 cve_scanner.py -s sample.csv -o report.html -c "Sample Customer"

# Complete example with all options
python3 cve_scanner.py -s sample.csv -o sample-customer.html -e sample-exec-summary.md -a sample-appendix.md -c "Sample Customer" --max-workers 2

```

**CSV Format (Recommended):**
```csv
Chainguard_Image,Customer_Image
cgr.dev/chainguard-private/jdk:openjdk-21,alpine/java:21
cgr.dev/chainguard-private/nginx:1,hijaak/nginx:v1
cgr.dev/chainguard-private/logstash:7,logstash:7.17.0
```



### Command Line Options

- `-s, --source`: Source images (required)
  - **CSV file**: `image_pairs.csv`
- `-o, --output`: Output file path (required) - supports `.html` or `.pdf` extensions
- `-e, --exec-summary`: Optional markdown file for executive summary
- `-a, --appendix`: Optional markdown file for custom appendix content (appears above methodology)
- `-c, --customer-name`: Customer name for report footer (default: "Customer")
- `--max-workers`: Number of parallel scanning threads (default: 4)
- `--timeout-per-image`: Timeout in seconds per image scan (default: 300)

### File Format

**CSV Format:**
```csv
Chainguard_Image,Customer_Image
cgr.dev/chainguard/nginx:latest,nginx:latest
cgr.dev/chainguard/python:latest,python:3.9
cgr.dev/chainguard/node:latest,node:16-alpine
```



## Sample Files

- `sample.csv`: Example CSV format file with image pairs
- `sample-exec-summary.md`: Example executive summary with template variables
- `sample-appendix.md`: Comprehensive appendix with methodology and best practices

## Performance Features

- **Parallel Scanning**: Uses multi-threading to scan multiple images simultaneously
- **Row-Level Validation**: If any image in a row fails to scan, the entire row is excluded from results
- **Auto-Retry Logic**: Failed scans are automatically retried with `:latest` tag
- **Configurable Workers**: Control parallelism with `--max-workers` (default: 4)
- **Progress Tracking**: Real-time feedback on scan progress and failures
- **Performance Gain**: Typically 3-5x faster than sequential scanning

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

## PDF Generation

The tool supports direct PDF generation using WeasyPrint:

```bash
# Generate PDF directly
python3 cve_scanner.py -s sample.csv -o report.pdf -c "Your Company"

# HTML output (for manual PDF conversion)
python3 cve_scanner.py -s sample.csv -o report.html -c "Your Company"
```

**PDF Features:**
- **Direct PDF generation** using WeasyPrint when output ends in `.pdf`
- **Professional styling** optimized for PDF rendering
- **Page break controls** to avoid section splitting
- **Clean headers and footers** with proper spacing
- **Table-based layouts** for reliable PDF compatibility
- **Fallback to HTML** if WeasyPrint is not available

**Manual PDF Conversion:**
The HTML reports are also optimized for manual PDF conversion using tools like:
- Chrome/Firefox print-to-PDF
- wkhtmltopdf
- Puppeteer

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
3. **Scan timeouts**: Large images may take time; the tool has a 5-minute timeout per image
4. **Failed scans**: Check the CLI output for detailed error information
5. **PDF conversion issues**: The HTML is optimized for PDF - use tools like Puppeteer, wkhtmltopdf, or Chrome's print-to-PDF

## Example Output

The tool generates a professional HTML report showing:
- Executive summary with business impact calculations
- CVE reduction analysis with prominent metrics
- Total vulnerability counts for each image set
- **Severity breakdown in professional table format** with color-coded indicators (Critical, High, Medium, Low, Negligible, Unknown)
- Side-by-side comparison table
- Comprehensive appendix with methodology
- Chainguard branding and elegant styling optimized for PDF conversion
