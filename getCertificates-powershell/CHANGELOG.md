# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-01

### Added
- Initial release of PowerShell certificate scanner
- Support for single domain and batch file processing
- Certificate information extraction:
  - Common Name (CN)
  - Subject Alternative Names (SAN)
  - Serial Number
  - SHA1 Thumbprint
  - Expiration Date
  - IP Address resolution
- Proxy certificate detection with configurable CA name
- Automatic date-based CSV file naming (DDMMYY format)
- Comprehensive logging with rotation
- Retry logic for transient failures
- Progress reporting for batch operations
- Certificate expiration warnings
- Statistics and reporting
- IPv4 and IPv6 address support
- Port specification support
- Input validation and error handling
- DNS caching for performance
- Resource management and proper disposal
- Comment-based help for all functions
- Support for comment lines in domain files

### Fixed
- Fixed variable scope issues from Python version
- Fixed inconsistent return types
- Fixed CSV data consistency (always 8 fields)
- Fixed input validation for ports and addresses
- Fixed IPv6 address parsing
- Fixed error handling gaps

### Security
- Input sanitization and path validation
- Configurable certificate validation
- Secure error message handling

### Performance
- DNS result caching
- Efficient resource disposal
- Optimized certificate parsing

### Documentation
- Comprehensive README with examples
- Comment-based help for all functions
- Usage examples and troubleshooting guide

