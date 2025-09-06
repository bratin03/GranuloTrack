# CVE Testing

JavaScript proof of concept for CVE-2019-5782 vulnerability testing.

## How to Run

```bash
# Install vulnerable Chrome version
sudo dpkg -i google-chrome-71.0.3578.80_amd64.deb
sudo apt-get install -f

# Test vulnerability
# Open POC.html in vulnerable Chrome browser
# Note: Chrome 71.0.3578.80 may not work on newer Ubuntu systems
```

## Description
- **POC.html**: HTML wrapper for vulnerability testing
- **POC.js**: JavaScript proof of concept for CVE-2019-5782
- **google-chrome-71.0.3578.80_amd64.deb**: Vulnerable Chrome version for testing