# WAFHUNTER - Advanced Web Application Firewall Detection Tool

<img src="https://github.com/MrpasswordTz/WAFHUNTER/blob/main/logo/wafLogo.jpg" alt="WAFHUNTER Logo" width="200" height="100">

[![Version](https://img.shields.io/badge/version-3.0-blue.svg)](https://github.com/MrpasswordTz/WAFHUNTER)
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Author](https://img.shields.io/badge/author-MrpasswordTz-orange.svg)](https://github.com/MrpasswordTz)

## 🚀 Overview

WAFHUNTER is a professional-grade Web Application Firewall (WAF) detection tool designed for penetration testers, security researchers, and cybersecurity professionals. It provides advanced detection capabilities, bypass techniques, and comprehensive reporting features.

## ✨ Features

### 🔍 Advanced Detection
- **Multi-method Detection**: Header analysis, content analysis, response code analysis, and advanced payload testing
- **Version Detection**: Identify specific WAF versions and configurations
- **Confidence Scoring**: Provides confidence levels for detection accuracy
- **Stealth Mode**: Reduce detection risk with advanced evasion techniques

### 🛡️ Comprehensive WAF Support
- **100+ WAF Signatures**: Support for major WAFs including Cloudflare, AWS WAF, Imperva, F5 BIG-IP, and more
- **Real-time Updates**: Regularly updated signature database
- **Custom Signatures**: Support for custom WAF signatures

### 🎯 Professional Features
- **Multi-threaded Scanning**: Concurrent scanning of multiple targets
- **Multiple Output Formats**: JSON, XML, HTML, and text reports
- **Configuration Management**: YAML/JSON configuration files
- **Plugin System**: Extensible architecture for custom modules
- **Comprehensive Logging**: Detailed logging for audit trails

### 🔧 Advanced Bypass Techniques
- **Encoding Evasion**: URL encoding, Unicode, Base64, Hex, HTML entities, UTF-7/16/32, Octal, Binary, ROT13, Hash obfuscation
- **Case Variations**: Mixed case, lowercase, uppercase, title case, alternating case, random case
- **Whitespace Manipulation**: Tab, newline, carriage return, multiple spaces, zero-width spaces, non-breaking spaces, vertical tab, form feed
- **Unicode Evasion**: Fullwidth characters, zero-width characters, homoglyph substitution, Unicode normalization, RTL override, combining characters, mathematical alphanumeric, emoji substitution
- **Protocol Evasion**: HTTP/2 multiplexing, HTTP/3 QUIC, TLS version manipulation, TLS fingerprint spoofing, HTTP pipelining, request smuggling, response splitting, WebSocket protocol
- **Header Manipulation**: Custom User-Agent, header ordering, duplication, case variation, IP spoofing, referer spoofing, origin spoofing, host injection, cookie manipulation
- **Timing Evasion**: Request spacing, burst requests, random timing, Slowloris attack, RUDY attack, time-based evasion, session puzzling, clock skew exploitation
- **Obfuscation**: String concatenation, comment injection, JavaScript/CSS/HTML obfuscation, SQL comment obfuscation, polymorphic code, dead code injection, code reordering
- **Parameter Pollution**: Duplicate parameters, parameter order variation, array parameter injection, JSON/XML parameter pollution, HTTP parameter contamination
- **Chunked Encoding**: Chunked transfer encoding, chunk size manipulation, chunk boundary obfuscation, chunked encoding bypass
- **Attack-Specific Evasion**: SQL injection evasion, XSS evasion, command injection evasion
- **Advanced Evasion**: Machine learning evasion, behavioral analysis bypass, fingerprint spoofing, CAPTCHA bypass, JavaScript challenge bypass, cookie challenge bypass, IP rotation, User-Agent rotation

## 📋 Requirements

- Python 3.7 or higher
- Required packages (see requirements.txt)

## 🚀 Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/MrpasswordTz/WAFHUNTER.git
cd WAFHUNTER

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x wafhunter.py

# Verify installation
python3 wafhunter.py --help

# Test the enhanced bypass techniques
python3 demo_bypass.py
```

### Docker Installation
```bash
# Build Docker image
docker build -t wafhunter .

# Run WAFHUNTER
docker run -it wafhunter python3 wafhunter.py example.com
```

## 📖 Usage

### Basic Usage

```bash
# Basic WAF detection
python3 wafhunter.py example.com

# Multiple targets
python3 wafhunter.py example.com target.com victim.com

# Custom port and protocol
python3 wafhunter.py example.com --port 8080 --protocol https
```

### Advanced Usage

```bash
# Stealth mode scanning
python3 wafhunter.py example.com --stealth

# High concurrency scanning
python3 wafhunter.py example.com --concurrency 20

# Generate detailed report
python3 wafhunter.py example.com --report json --output report.json

# Verbose logging
python3 wafhunter.py example.com --verbose --log-file scan.log

# Custom configuration
python3 wafhunter.py example.com --config custom_config.json
```

### Professional Examples

```bash
# Government/Enterprise scanning
python3 wafhunter.py target.gov --stealth --concurrency 5 --timeout 30 --report json

# Penetration testing
python3 wafhunter.py target.com --stealth --verbose --log-file pentest.log

# Security assessment
python3 wafhunter.py target.com --report html --output security_report.html

# Custom headers and User-Agent
python3 wafhunter.py target.com --user-agent "CustomBot/1.0" --headers '{"X-Custom": "value"}'
```

## 🔧 Configuration

### Configuration File (config.json)
```json
{
  "default_settings": {
    "timeout": 10,
    "max_retries": 3,
    "concurrency": 5,
    "stealth_mode": false
  },
  "waf_signatures": {
    "enable_version_detection": true,
    "enable_bypass_suggestions": true,
    "confidence_threshold": 0.6
  },
  "stealth": {
    "randomize_user_agents": true,
    "randomize_request_timing": true,
    "max_requests_per_second": 2
  }
}
```

## 📊 Output Formats

### JSON Report
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00",
    "total_hosts": 3,
    "waf_detected": 2,
    "stealth_mode": false
  },
  "results": [
    {
      "host": "example.com",
      "waf_detected": true,
      "waf_name": "Cloudflare",
      "waf_version": "2023.12.1",
      "confidence": 0.95,
      "detection_method": "Header Analysis",
      "bypass_techniques": ["Use different User-Agent", "Try HTTP/2 requests"]
    }
  ]
}
```

### HTML Report
Generates a professional HTML report with:
- Executive summary
- Detailed findings
- Bypass recommendations
- Technical details
- Visual indicators

## 🛠️ Advanced Features

### Plugin System
```python
# Custom plugin example
from plugins.bypass_techniques import BypassTechniques

bypass = BypassTechniques()
techniques = bypass.get_bypass_techniques("Cloudflare")
evaded_payloads = bypass.generate_evasion_payloads("' OR '1'='1", "Cloudflare")
```

### Stealth Mode
- Randomized User-Agent strings
- Request timing variation
- Header manipulation
- Protocol evasion
- Reduced detection signatures

### Bypass Techniques
- **Encoding**: URL, Unicode, Base64, Hex
- **Case Variations**: Mixed, lower, upper case
- **Whitespace**: Tab, newline, multiple spaces
- **Unicode**: Fullwidth, zero-width, homoglyphs
- **Protocol**: HTTP/2, HTTP/3, TLS variations
- **Timing**: Request spacing, burst patterns

## 🔍 Detection Methods

### 1. Header Analysis
- Server headers
- Security headers
- WAF-specific headers
- Version information

### 2. Content Analysis
- Response body patterns
- Error messages
- Challenge pages
- Blocking messages

### 3. Response Code Analysis
- HTTP status codes
- Error patterns
- Redirect behaviors
- Timeout patterns

### 4. Advanced Detection
- Payload testing
- Timing analysis
- Protocol fuzzing
- Behavioral analysis

## 📈 Performance

- **Concurrent Scanning**: Up to 50 concurrent threads
- **Memory Efficient**: Optimized for large-scale scanning
- **Fast Detection**: Average detection time < 2 seconds
- **Low Resource Usage**: Minimal CPU and memory footprint

## 🔒 Security Considerations

- **Legal Compliance**: Only use on authorized targets
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **Stealth Mode**: Reduce detection and blocking
- **Audit Logging**: Comprehensive logging for compliance

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/MrpasswordTz/WAFHUNTER.git
cd WAFHUNTER

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 wafhunter.py
```

## 📝 Changelog

### Version 3.0 (Current)
- Complete rewrite with professional features
- Advanced detection methods
- Plugin system
- Multiple output formats
- Stealth mode
- Bypass techniques
- Version detection
- Comprehensive logging

### Version 2.0
- Basic WAF detection
- Multi-threaded scanning
- Simple CLI interface

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 👥 Authors

- **MrpasswordTz** - *Initial work* - [GitHub](https://github.com/MrpasswordTz)
- **WAFHUNTER Team** - *Professional Edition* - [GitHub](https://github.com/MrpasswordTz/WAFHUNTER)

## 🙏 Acknowledgments

- Security community for WAF signatures
- Penetration testing community for feedback
- Open source contributors

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/MrpasswordTz/WAFHUNTER/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MrpasswordTz/WAFHUNTER/discussions)
- **Email**: support@wafhunter.com

## 🚀 Enhanced Bypass Techniques Integration

### What Was Added

Your enhanced bypass techniques have been successfully integrated, providing **126+ advanced bypass techniques** across **14 categories**:

#### 🔧 Technique Categories

1. **Encoding Evasion** (16 techniques)
   - URL encoding (single, double, triple), Partial URL encoding
   - Unicode, Hex, Base64, Base64 URL encoding
   - HTML entity encoding, UTF-7/16/32 encoding
   - Octal, Binary, ROT13 encoding, MD5/SHA1 hash obfuscation

2. **Case Variations** (6 techniques)
   - Mixed case, lowercase, uppercase, title case, alternating case, random case

3. **Whitespace Manipulation** (10 techniques)
   - Tab, newline, carriage return, multiple spaces, zero-width spaces
   - Non-breaking spaces, vertical tab, form feed, mixed whitespace

4. **Unicode Evasion** (8 techniques)
   - Fullwidth characters, zero-width characters, homoglyph substitution
   - Unicode normalization, RTL override, combining characters
   - Mathematical alphanumeric, emoji substitution

5. **Protocol Evasion** (10 techniques)
   - HTTP/2 multiplexing, HTTP/3 QUIC, TLS version manipulation
   - TLS fingerprint spoofing, HTTP pipelining, request smuggling
   - Response splitting, WebSocket protocol, IP protocol switching

6. **Header Manipulation** (14 techniques)
   - Custom User-Agent, header ordering, duplication, case variation
   - IP spoofing (X-Forwarded-For, X-Real-IP), Referer/Origin spoofing
   - Host injection, cookie manipulation, content-type spoofing

7. **Timing Evasion** (8 techniques)
   - Request spacing, burst requests, random timing, Slowloris attack
   - RUDY attack, time-based evasion, session puzzling, clock skew exploitation

8. **Obfuscation** (9 techniques)
   - String concatenation, comment injection, JavaScript/CSS/HTML obfuscation
   - SQL comment obfuscation, polymorphic code, dead code injection, code reordering

9. **Parameter Pollution** (6 techniques)
   - Duplicate parameters, parameter order variation, array parameter injection
   - JSON/XML parameter pollution, HTTP parameter contamination

10. **Chunked Encoding** (4 techniques)
    - Chunked transfer encoding, chunk size manipulation
    - Chunk boundary obfuscation, chunked encoding bypass

11. **SQL Injection Evasion** (8 techniques)
    - SQL comment bypass, keyword obfuscation, hex encoding
    - Time-based blind, boolean-based blind, stacked queries
    - UNION bypass, error-based injection

12. **XSS Evasion** (8 techniques)
    - Event handler bypass, JavaScript URI bypass, SVG bypass
    - Data URI bypass, template literal bypass, Unicode bypass
    - DOM-based bypass, mutation-based bypass

13. **Command Injection Evasion** (8 techniques)
    - Semicolon, pipe, backtick injection, dollar syntax
    - Newline injection, AND/OR operators, subshell injection

14. **Advanced Evasion** (10 techniques)
    - Machine learning evasion, behavioral analysis bypass
    - Fingerprint spoofing, CAPTCHA bypass, JavaScript challenge bypass
    - Cookie challenge bypass, IP rotation, User-Agent rotation

### 📊 Integration Statistics

- **Total Techniques**: 126+ bypass techniques (vs 7 in original)
- **Categories**: 14 technique categories (vs 7 in original)
- **WAF Support**: Enhanced support for 100+ WAFs
- **Test Coverage**: 9 comprehensive test cases
- **Backward Compatibility**: 100% maintained

### 🎯 Usage Examples

```python
from plugins.bypass_techniques import BypassTechniques

# Initialize enhanced bypass techniques
bypass = BypassTechniques()

# Get techniques for specific WAF
techniques = bypass.get_bypass_techniques("Cloudflare")
print(f"Cloudflare: {len(techniques)} techniques available")

# Apply specific technique
evaded = bypass.apply_technique("SELECT * FROM users", "URL Encoding")
print(f"URL Encoded: {evaded}")

# Generate multiple evasion payloads
payloads = bypass.generate_evasion_payloads("test' OR '1'='1", "ModSecurity")
for i, payload in enumerate(payloads[:5], 1):
    print(f"{i}. {payload}")

# Test different attack vectors
sql_payloads = bypass.generate_evasion_payloads("' OR '1'='1", "AWS WAF")
xss_payloads = bypass.generate_evasion_payloads("alert(1)", "Cloudflare")
```

### 🚀 Demo Script

Run the demo to see all techniques in action:

```bash
python3 demo_bypass.py
```

This will demonstrate:
- All 14 technique categories
- WAF-specific technique recommendations
- Payload generation for different attack types
- Real-world evasion examples

### 🔒 Security Features

- **Legal Use Only**: Only use on authorized targets
- **Rate Limiting**: Built-in protection against abuse
- **Stealth Mode**: Advanced evasion techniques
- **Audit Logging**: Comprehensive logging for compliance
- **Professional Grade**: Suitable for enterprise and government use

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=MrpasswordTz/WAFHUNTER&type=Date)](https://star-history.com/#MrpasswordTz/WAFHUNTER&Date)

---

**WAFHUNTER Enhanced Edition - Powered by Advanced Bypass Techniques**

**Made with ❤️ by the WAFHUNTER Team**