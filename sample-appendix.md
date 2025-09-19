### {{customer_name}} Specific Logic/Assumptions

- Grype is leveraged as the scanner tool to scan both the {{customer_name}} provided image as well as the Chainguard image
- Any images/repos not found in Chainguard images was excluded from this report. It's meant to represent a sample only, not 100% complete representation of the {{customer_name}} environment. 
- Any image tag that failed to pull, we tried the :latest tag. If that succeeded it is marked with an * in the above comparison. 