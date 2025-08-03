### {{customer_name}} Specific Logic/Assumptions

- {{customer_name}} provided **{{images_scanned}} images**
- If the upstream software was EOL we mapped to :latest in Chainguard image
- Grype is leveraged as the scanner tool to scan both the {{customer_name}} provided image as well as the Chainguard image
- If a scan with grype failed on any image, it attempted a tag for re-scanning which is represented with a *
- If the above logic fails, the entire row will fail and is not included in the report. This is to ensure 1:1 comparison. Eg: some Customer images are behind a paywall or simply not available in the public registry
- CVE cost figure based on: Average 1hr to resolve a single CVE (including business process). An engineer wage of $75 per hour multiplied by # of CVE's
