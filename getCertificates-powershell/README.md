# Get-Certificates PowerShell Script

A PowerShell script to query SSL/TLS certificates from domains and extract certificate information including Common Name, Subject Alternative Names, Serial Number, Thumbprint, Expiration Date, and IP addresses.

## Features

- Query single domains or process files containing multiple domains
- Extract comprehensive certificate information
- Detect proxy certificates (Prisma, Zscaler, etc.)
- Automatic date-based CSV file naming
- Retry logic for transient failures
- Progress reporting for batch processing
- Comprehensive logging with rotation
- Certificate expiration warnings
- Statistics and reporting

## Requirements

- **PowerShell**: 5.1+ (PowerShell 7+ recommended)
- **.NET**: Framework 4.5+ or .NET Core/.NET 5+
- **No external modules required** - uses built-in .NET classes

## Installation

1. Clone or download this repository
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Single Domain

```powershell
.\Get-Certificates.ps1 -Single "example.com"
```

### Multiple Domains from File

```powershell
.\Get-Certificates.ps1 -DomainFile "domains.txt" -Output "results"
```

### With Proxy Detection

```powershell
.\Get-Certificates.ps1 -Single "example.com" -ProxyCaName "Prisma"
```

### Advanced Options

```powershell
.\Get-Certificates.ps1 `
    -DomainFile "domains.txt" `
    -Output "results" `
    -ProxyCaName "Zscaler" `
    -Timeout 10 `
    -RetryCount 2 `
    -ExpirationWarningDays 30 `
    -LogPath "custom.log" `
    -LogLevel "Info"
```

## Parameters

### Required Parameters

- **`-DomainFile`** or **`-Single`**: One of these must be specified
  - `-DomainFile`: Path to file containing domains (one per line)
  - `-Single`: Single domain to query

### Optional Parameters

- **`-Output`**: Base filename for CSV output. Date will be appended automatically (e.g., `results-010124.csv`)
- **`-ProxyCaName`**: CA name to detect proxy certificates (e.g., "Prisma", "Zscaler", "Palo Alto")
- **`-Timeout`**: Connection timeout in seconds (default: 5)
- **`-RetryCount`**: Number of retry attempts for transient failures (default: 0)
- **`-ThrottleLimit`**: Maximum concurrent connections (default: CPU count, PowerShell 7+)
- **`-LogPath`**: Path to log file (default: "DEBUG.log")
- **`-LogLevel`**: Minimum log level - Debug, Info, Warning, Error (default: Debug)
- **`-ExpirationWarningDays`**: Days before expiration to flag certificates (default: 30)
- **`-SkipCertificateValidation`**: Skip certificate validation (default: $true)

## Input File Format

The domain file should contain one domain per line. Comments (lines starting with `#`) are ignored.

Example `domains.txt`:
```
# Production domains
example.com
test.example.com
example.com:8443
[2001:db8::1]:443
192.168.1.1
```

### Supported Formats

- Hostnames: `example.com`
- Hostnames with port: `example.com:8443`
- IPv4 addresses: `192.168.1.1`
- IPv4 with port: `192.168.1.1:443`
- IPv6 addresses: `2001:db8::1`
- IPv6 with port: `[2001:db8::1]:443`

**Note**: Do not include protocol prefixes (http://, https://) in the input.

## Output

### CSV File

The script generates a CSV file with the following columns:

- **Hostname**: The input domain/hostname
- **IP Address**: Resolved IP address(es) (comma-separated if multiple)
- **Port**: Port number used
- **Common Name**: Certificate Common Name (CN)
- **Expiration Date**: Formatted expiration date
- **Serial Number**: Certificate serial number (or "PROXY CERT" if detected)
- **Thumbprint (SHA1)**: SHA1 thumbprint (or "PROXY CERT" if detected)
- **SAN**: Subject Alternative Names

### File Naming

CSV files are automatically named with the current date appended:
- If `-Output "domains"` is specified → `domains-010124.csv`
- If `-Output` is not specified → `certificates-010124.csv`
- Format: `{filename}-{DDMMYY}.csv`

### Console Output

The script displays:
- Certificate information for each domain
- Progress bar for batch processing
- Statistics summary at completion:
  - Total processed
  - Successful
  - Failed
  - Proxy certificates detected
  - Certificates expiring soon

## Proxy Certificate Detection

When `-ProxyCaName` is specified, the script checks if certificates are issued by the specified proxy CA. If detected:

- Serial Number column shows: `PROXY CERT`
- Thumbprint column shows: `PROXY CERT`
- Detection is logged for audit purposes

Example proxy CA names:
- `Prisma` (for Prisma Access)
- `Zscaler` (for Zscaler)
- `Palo Alto` (for Palo Alto Networks)

## Logging

Logs are written to `DEBUG.log` (or custom path specified with `-LogPath`).

### Log Levels

- **Debug**: Detailed diagnostic information
- **Info**: General informational messages
- **Warning**: Warning messages
- **Error**: Error messages

### Log Rotation

Logs are automatically rotated when they exceed 10MB. Old logs are renamed with a date suffix (e.g., `DEBUG-20240101.log`).

### Log Format

```
[2024-01-01 12:00:00] [Level] [FunctionName] Message
```

## Examples

### Example 1: Single Domain

```powershell
PS> .\Get-Certificates.ps1 -Single "github.com"

SSL Certificate for github.com
IP address = 140.82.121.3
Port = 443
Common Name = github.com
Expires on = Monday, May, 15, 2024, 12:00:00 PM
serial# = 0123456789ABCDEF
Thumbprint = 0123456789ABCDEF0123456789ABCDEF01234567
SAN = DNS Name=github.com, DNS Name=www.github.com
```

### Example 2: Batch Processing

```powershell
PS> .\Get-Certificates.ps1 -DomainFile "domains.txt" -Output "scan-results"

Processing Domains
[████████████████████████████] 100%

=== Statistics ===
Total Processed: 50
Successful: 48
Failed: 2
Proxy Certificates Detected: 5
Expiring Soon (within 30 days): 3
Total Duration: 00:02:15
```

### Example 3: With Proxy Detection

```powershell
PS> .\Get-Certificates.ps1 -Single "example.com" -ProxyCaName "Prisma" -Output "proxy-check"

SSL Certificate for example.com
IP address = 192.168.1.100
Port = 443
Common Name = example.com
Expires on = Monday, January, 01, 2024, 12:00:00 PM
serial# = PROXY CERT
Thumbprint = PROXY CERT
SAN = DNS Name=example.com
```

## Error Handling

The script handles various error conditions gracefully:

- **Connection failures**: Retries based on `-RetryCount` parameter
- **DNS resolution failures**: Returns 'NA' for IP address
- **Certificate retrieval failures**: Logs error and continues with next domain
- **Invalid input**: Validates and reports errors clearly

Failed domains are still included in the CSV output with 'NA' values for unavailable fields.

## Performance

- **DNS Caching**: DNS resolutions are cached to avoid redundant lookups
- **Sequential Processing**: Domains are processed sequentially to avoid overwhelming target servers
- **Progress Reporting**: Progress bar shows status for batch operations
- **Resource Management**: All network connections and certificates are properly disposed

## Troubleshooting

### Script Won't Run

**Issue**: Execution policy prevents script execution

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Connection Timeouts

**Issue**: Frequent connection timeouts

**Solution**: Increase timeout:
```powershell
.\Get-Certificates.ps1 -Single "example.com" -Timeout 10
```

### DNS Resolution Failures

**Issue**: Many domains show 'NA' for IP addresses

**Solution**: 
- Check network connectivity
- Verify DNS server configuration
- Check firewall settings

### Proxy Certificates Not Detected

**Issue**: Proxy certificates not being marked

**Solution**: 
- Verify the proxy CA name matches exactly (case-insensitive)
- Check issuer field in certificate details
- Review log file for detection attempts

## Version

Current Version: 1.0.0

## License

This script is provided as-is for use in certificate scanning and auditing.

## Contributing

Improvements and bug fixes are welcome. Please ensure:
- Code follows PowerShell best practices
- All functions have comment-based help
- Error handling is comprehensive
- Tests are included for new features

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

