<#
.SYNOPSIS
    Query domains for SSL/TLS certificates and extract certificate information.

.DESCRIPTION
    Retrieves SSL/TLS certificates from domains and extracts certificate details including:
    - Common Name (CN)
    - Subject Alternative Names (SAN)
    - Serial Number
    - Thumbprint (SHA1)
    - Expiration Date
    - IP Addresses
    - Proxy certificate detection

    Supports processing single domains or files containing multiple domains.
    Outputs results to CSV with automatic date-based filename generation.

.PARAMETER DomainFile
    Path to a file containing a list of domains, one domain per line.
    Domains can include ports in the format: domain:port
    Lines starting with # are treated as comments and ignored.

.PARAMETER Single
    Single domain to query. Can include port: domain:port

.PARAMETER Output
    Base filename for CSV output. Date will be automatically appended in DDMMYY format.
    Example: -Output "domains" results in "domains-010124.csv"
    If not specified, defaults to "certificates-010124.csv"

.PARAMETER ProxyCaName
    CA name to detect proxy certificates (e.g., "Prisma", "Zscaler", "Palo Alto").
    When a proxy certificate is detected, Serial Number and Thumbprint will show "PROXY CERT".

.PARAMETER Timeout
    Connection timeout in seconds. Default is 5 seconds.

.PARAMETER RetryCount
    Number of retry attempts for transient failures. Default is 0 (no retries).

.PARAMETER ThrottleLimit
    Maximum number of concurrent connections when processing multiple domains.
    Default is the number of CPU cores. Only applies to PowerShell 7+.

.PARAMETER LogPath
    Path to log file. Default is "DEBUG.log" in the script directory.

.PARAMETER LogLevel
    Minimum log level to record. Options: Debug, Info, Warning, Error. Default is Debug.

.PARAMETER ExpirationWarningDays
    Number of days before expiration to flag certificates as expiring soon. Default is 30.

.PARAMETER SkipCertificateValidation
    Skip certificate validation (matches Python script behavior). Default is $true.

.EXAMPLE
    Get-Certificates -Single "example.com"

    Query a single domain for its certificate information.

.EXAMPLE
    Get-Certificates -DomainFile "domains.txt" -Output "results" -ProxyCaName "Prisma"

    Process domains from a file, detect Prisma proxy certificates, and save to results-DDMMYY.csv

.EXAMPLE
    Get-Certificates -Single "example.com:8443" -Timeout 10

    Query a domain on a custom port with a 10-second timeout.

.NOTES
    Author: Certificate Scanner
    Version: 1.0.0
    Requires: PowerShell 5.1+ (PowerShell 7+ recommended for parallel processing)
    Requires: .NET Framework 4.5+ or .NET Core/.NET 5+
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
            throw "File not found: $_"
        }
        $true
    })]
    [string]$DomainFile,

    [Parameter()]
    [string]$Single,

    [Parameter()]
    [string]$Output,

    [Parameter()]
    [string]$ProxyCaName,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$Timeout = 5,

    [Parameter()]
    [ValidateRange(0, 10)]
    [int]$RetryCount = 0,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = $(if ($env:NUMBER_OF_PROCESSORS) { [int]$env:NUMBER_OF_PROCESSORS } else { 4 }),

    [Parameter()]
    [string]$LogPath = "DEBUG.log",

    [Parameter()]
    [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
    [string]$LogLevel = 'Debug',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$ExpirationWarningDays = 30,

    [Parameter()]
    [bool]$SkipCertificateValidation = $true
)

#region Script Initialization

# Script version
$script:Version = "1.0.0"

# Initialize certificate data collection
$script:CertificateData = @()

# Statistics tracking
$script:Stats = @{
    TotalProcessed = 0
    Successful = 0
    Failed = 0
    ProxyDetected = 0
    ExpiringSoon = 0
    StartTime = Get-Date
}

# DNS cache for performance
$script:DnsCache = @{}

# Error collection
$script:Errors = @()

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or higher is required. Current version: $($psVersion.ToString())"
    exit 1
}

# Check for parallel processing capability (PowerShell 7+)
$script:SupportsParallel = $PSVersionTable.PSVersion.Major -ge 7

# Set error action preference
$ErrorActionPreference = 'Stop'

#endregion

#region Logging Functions

<#
.SYNOPSIS
    Writes a log entry to the log file.

.DESCRIPTION
    Writes formatted log entries with timestamp, level, and message to the log file.
    Supports log rotation based on file size.

.PARAMETER Message
    The log message to write.

.PARAMETER Level
    The log level (Debug, Info, Warning, Error).

.PARAMETER FunctionName
    Optional function name for context.
#>
function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level,

        [Parameter()]
        [string]$FunctionName = ''
    )

    # Check if log level should be recorded
    $logLevels = @('Debug', 'Info', 'Warning', 'Error')
    $currentLevelIndex = $logLevels.IndexOf($LogLevel)
    $messageLevelIndex = $logLevels.IndexOf($Level)
    
    if ($messageLevelIndex -lt $currentLevelIndex) {
        return
    }

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level]"
        
        if ($FunctionName) {
            $logEntry += " [$FunctionName]"
        }
        
        $logEntry += " $Message"
        
        # Rotate log if it exceeds 10MB
        if (Test-Path $LogPath) {
            $logFile = Get-Item $LogPath
            if ($logFile.Length -gt 10MB) {
                $dateSuffix = Get-Date -Format "yyyyMMdd"
                $rotatedLog = $LogPath -replace '\.log$', "-$dateSuffix.log"
                if (Test-Path $rotatedLog) {
                    Remove-Item $rotatedLog -Force
                }
                Move-Item $LogPath $rotatedLog -Force
                Write-LogFile -Message "Log rotated to $rotatedLog" -Level "Info" -FunctionName "Write-LogFile"
            }
        }
        
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        
        # Only write to console for warnings and info (errors are logged but not displayed)
        # Error messages are handled by the calling functions with user-friendly messages
        switch ($Level) {
            'Error' { 
                # Don't write errors to console - they're logged to file only
                # The calling function should display user-friendly error messages
            }
            'Warning' { 
                # Only show warnings if not in silent mode
                if ($VerbosePreference -ne 'SilentlyContinue') {
                    Write-Warning $Message 
                }
            }
            'Info' { 
                if ($VerbosePreference -ne 'SilentlyContinue') { 
                    Write-Host $Message 
                } 
            }
            'Debug' { 
                Write-Debug $Message 
            }
        }
    }
    catch {
        # Can't log if logging fails, just continue
        Write-Warning "Failed to write to log file: $_"
    }
}

#endregion

#region Network Functions

<#
.SYNOPSIS
    Resolves a hostname to IP address(es).

.DESCRIPTION
    Performs DNS resolution and returns comma-separated list of IP addresses.
    Uses caching to avoid redundant DNS lookups.

.PARAMETER Address
    The hostname or IP address to resolve.

.PARAMETER Port
    The port number (used for logging context).

.OUTPUTS
    String containing comma-separated IP addresses, or 'NA' on failure.
#>
function Get-IpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address,

        [Parameter()]
        [int]$Port = 443
    )

    try {
        # Check cache first
        if ($script:DnsCache.ContainsKey($Address)) {
            Write-LogFile -Message "Using cached DNS result for $Address" -Level "Debug" -FunctionName "Get-IpAddress"
            return $script:DnsCache[$Address]
        }

        $ipAddresses = [System.Net.Dns]::GetHostAddresses($Address)
        
        if ($ipAddresses.Count -eq 0) {
            Write-LogFile -Message "DNS resolution returned no addresses for $Address`:$Port" -Level "Error" -FunctionName "Get-IpAddress"
            $script:DnsCache[$Address] = 'NA'
            return 'NA'
        }

        # Always return comma-separated string for consistency
        $ipList = ($ipAddresses | ForEach-Object { $_.ToString() }) -join ', '
        
        Write-LogFile -Message "IP list for $Address`: $ipList" -Level "Debug" -FunctionName "Get-IpAddress"
        
        # Cache the result
        $script:DnsCache[$Address] = $ipList
        
        return $ipList
    }
    catch {
        Write-LogFile -Message "DNS resolution failed for $Address`:$Port`: $_" -Level "Error" -FunctionName "Get-IpAddress"
        $script:DnsCache[$Address] = 'NA'
        return 'NA'
    }
}

<#
.SYNOPSIS
    Tests if a string is a valid IPv4 address.

.DESCRIPTION
    Validates if the input string is a valid IPv4 address.

.PARAMETER Address
    The string to validate.

.OUTPUTS
    Boolean indicating if the string is a valid IPv4 address.
#>
function Test-Ipv4Address {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    try {
        $null = [System.Net.IPAddress]::Parse($Address)
        $ipBytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
        
        # Check if it's IPv4 (4 bytes)
        if ($ipBytes.Length -eq 4) {
            Write-LogFile -Message "Domain string is an IP address: $Address" -Level "Debug" -FunctionName "Test-Ipv4Address"
            return $true
        }
        return $false
    }
    catch {
        Write-LogFile -Message "Domain string is NOT an IP address: $Address" -Level "Debug" -FunctionName "Test-Ipv4Address"
        return $false
    }
}

#endregion

#region Certificate Retrieval

<#
.SYNOPSIS
    Retrieves SSL certificate from a remote host.

.DESCRIPTION
    Establishes SSL/TLS connection and retrieves the server certificate.
    Supports configurable timeout and certificate validation skipping.

.PARAMETER Address
    The hostname or IP address to connect to.

.PARAMETER Port
    The port number to connect to. Default is 443.

.PARAMETER TimeoutSeconds
    Connection timeout in seconds. Default is 5.

.OUTPUTS
    X509Certificate2 object, or $null on failure.
#>
function Get-SslCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address,

        [Parameter()]
        [int]$Port = 443,

        [Parameter()]
        [int]$TimeoutSeconds = 5
    )

    # Suppress error output - we handle errors internally
    $ErrorActionPreference = 'Stop'
    
    $tcpClient = $null
    $sslStream = $null

    try {
        Write-LogFile -Message "Attempting to retrieve certificate from $Address`:$Port" -Level "Debug" -FunctionName "Get-SslCertificate"

        # Create TCP client with timeout
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $TimeoutSeconds * 1000
        $tcpClient.SendTimeout = $TimeoutSeconds * 1000

        # Connect with timeout
        $connectResult = $tcpClient.BeginConnect($Address, $Port, $null, $null)
        $waitResult = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds), $false)

        if (-not $waitResult) {
            $tcpClient.Close()
            Write-LogFile -Message "Connection timeout for $Address`:$Port" -Level "Error" -FunctionName "Get-SslCertificate"
            return $null
        }

        $tcpClient.EndConnect($connectResult)

        # Create SSL stream with validation callback
        # Store SkipCertificateValidation in a local variable for the callback
        $skipValidation = $SkipCertificateValidation
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            {
                param($s, $certificate, $chain, $sslPolicyErrors)
                # Return the skip validation setting (matching Python behavior when true)
                # $s is the sender object (renamed to avoid automatic variable conflict)
                return $skipValidation
            },
            $null
        )

        # Authenticate as client
        $sslStream.AuthenticateAsClient($Address)

        # Get certificate
        $cert = $sslStream.RemoteCertificate

        if ($null -eq $cert) {
            Write-LogFile -Message "No certificate found for $Address`:$Port" -Level "Info" -FunctionName "Get-SslCertificate"
            return $null
        }

        # Convert to X509Certificate2
        try {
            $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
            Write-LogFile -Message "Certificate retrieved successfully for $Address`:$Port" -Level "Info" -FunctionName "Get-SslCertificate"
            return $x509Cert
        }
        catch {
            Write-LogFile -Message "Failed to parse certificate for $Address`:$Port`: $($_.Exception.Message)" -Level "Error" -FunctionName "Get-SslCertificate"
            return $null
        }
    }
    catch {
        # Handle different exception types
        $exceptionType = $_.Exception.GetType().FullName
        
        if ($exceptionType -eq 'System.Net.Sockets.SocketException' -or 
            $_.Exception -is [System.Net.Sockets.SocketException]) {
            Write-LogFile -Message "$Address`:$Port is not reachable: $($_.Exception.Message)" -Level "Warning" -FunctionName "Get-SslCertificate"
            return $null
        }
        elseif ($exceptionType -like '*TimeoutException*' -or 
                $_.Exception -is [System.TimeoutException]) {
            Write-LogFile -Message "Connection timed out for $Address`:$Port" -Level "Error" -FunctionName "Get-SslCertificate"
            return $null
        }
        elseif ($exceptionType -eq 'System.Security.Authentication.AuthenticationException' -or 
                $_.Exception -is [System.Security.Authentication.AuthenticationException]) {
            Write-LogFile -Message "SSL handshake failed for $Address, $Port`: $($_.Exception.Message)" -Level "Error" -FunctionName "Get-SslCertificate"
            return $null
        }
        else {
            Write-LogFile -Message "Error retrieving certificate for $Address`:$Port`: $($_.Exception.Message)" -Level "Error" -FunctionName "Get-SslCertificate"
            return $null
        }
    }
    finally {
        # Clean up resources
        if ($sslStream) {
            try {
                $sslStream.Dispose()
            }
            catch {
                # Ignore disposal errors
            }
        }
        if ($tcpClient) {
            try {
                $tcpClient.Close()
                $tcpClient.Dispose()
            }
            catch {
                # Ignore disposal errors
            }
        }
    }
}

#endregion

#region Certificate Parsing Functions

<#
.SYNOPSIS
    Extracts Subject Alternative Names from a certificate.

.DESCRIPTION
    Finds and extracts the SAN extension (OID 2.5.29.17) from certificate extensions.

.PARAMETER Certificate
    The X509Certificate2 object to parse.

.OUTPUTS
    String containing SAN information, or "N/A" if not found.
#>
function Get-CertificateSan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        $sanOid = "2.5.29.17"  # Subject Alternative Name OID
        
        foreach ($extension in $Certificate.Extensions) {
            if ($extension.Oid.Value -eq $sanOid) {
                # Use Format() method which returns human-readable format
                $san = $extension.Format($false)
                Write-LogFile -Message "SAN found: $san" -Level "Debug" -FunctionName "Get-CertificateSan"
                return $san
            }
        }
        
        return "N/A"
    }
    catch {
        Write-LogFile -Message "Error extracting SAN: $_" -Level "Error" -FunctionName "Get-CertificateSan"
        return "N/A"
    }
}

<#
.SYNOPSIS
    Extracts Common Name from certificate subject.

.DESCRIPTION
    Parses the certificate subject to find the Common Name (CN) field.

.PARAMETER Certificate
    The X509Certificate2 object to parse.

.OUTPUTS
    String containing the Common Name, or $null if not found.
#>
function Get-CertificateCommonName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        # Use GetNameInfo method which is cleaner
        $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        
        if ([string]::IsNullOrEmpty($cn)) {
            # Fallback: parse subject string
            $subject = $Certificate.Subject
            if ($subject -match 'CN=([^,]+)') {
                $cn = $matches[1].Trim()
            }
        }
        
        return $cn
    }
    catch {
        Write-LogFile -Message "Error extracting Common Name: $_" -Level "Error" -FunctionName "Get-CertificateCommonName"
        return $null
    }
}

<#
.SYNOPSIS
    Gets SHA1 thumbprint of certificate.

.DESCRIPTION
    Calculates and returns the SHA1 thumbprint without colons.

.PARAMETER Certificate
    The X509Certificate2 object.

.OUTPUTS
    String containing the SHA1 thumbprint without colons.
#>
function Get-CertificateThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        # Get SHA1 hash - GetCertHashString() returns colon-separated hex string
        # Available in .NET Framework 2.0+ and .NET Core
        try {
            $thumbprint = $Certificate.GetCertHashString()
            # Remove colons to match Python format
            $thumbprint = $thumbprint.Replace(':', '')
        }
        catch {
            # Fallback for very old .NET versions
            $hashBytes = $Certificate.GetCertHash()
            $thumbprint = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ''
        }
        
        return $thumbprint
    }
    catch {
        Write-LogFile -Message "Error calculating thumbprint: $_" -Level "Error" -FunctionName "Get-CertificateThumbprint"
        return 'NA'
    }
}

<#
.SYNOPSIS
    Gets serial number of certificate in hexadecimal format.

.DESCRIPTION
    Returns the certificate serial number as a hexadecimal string.

.PARAMETER Certificate
    The X509Certificate2 object.

.OUTPUTS
    String containing the serial number in hex format.
#>
function Get-CertificateSerialNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        # SerialNumber is already in hex format
        return $Certificate.SerialNumber
    }
    catch {
        Write-LogFile -Message "Error getting serial number: $_" -Level "Error" -FunctionName "Get-CertificateSerialNumber"
        return 'NA'
    }
}

<#
.SYNOPSIS
    Formats certificate expiration date.

.DESCRIPTION
    Formats the certificate expiration date to match Python output format.

.PARAMETER Certificate
    The X509Certificate2 object.

.OUTPUTS
    String containing formatted expiration date.
#>
function Get-CertificateExpiration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    try {
        $expDate = $Certificate.NotAfter
        $formattedDate = $expDate.ToString('dddd, MMMM, dd, yyyy, hh:mm:ss tt')
        Write-Host $formattedDate
        return $formattedDate
    }
    catch {
        Write-LogFile -Message "Error formatting expiration date: $_" -Level "Error" -FunctionName "Get-CertificateExpiration"
        return 'NA'
    }
}

<#
.SYNOPSIS
    Tests if certificate is issued by a proxy CA.

.DESCRIPTION
    Checks if the certificate issuer contains the specified proxy CA name.

.PARAMETER Certificate
    The X509Certificate2 object to check.

.PARAMETER ProxyCaName
    The proxy CA name to search for (case-insensitive).

.OUTPUTS
    Boolean indicating if certificate is from proxy CA.
#>
function Test-ProxyCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$ProxyCaName
    )

    try {
        if ([string]::IsNullOrWhiteSpace($ProxyCaName)) {
            return $false
        }

        $issuer = $Certificate.Issuer
        
        if ($issuer -match [regex]::Escape($ProxyCaName)) {
            Write-LogFile -Message "Certificate from proxy CA detected: $issuer" -Level "Info" -FunctionName "Test-ProxyCertificate"
            return $true
        }
        
        return $false
    }
    catch {
        Write-LogFile -Message "Error checking proxy certificate: $_" -Level "Error" -FunctionName "Test-ProxyCertificate"
        return $false
    }
}

#endregion

#region Input Processing

<#
.SYNOPSIS
    Validates and processes domain input.

.DESCRIPTION
    Validates domain input, extracts domain and port, and processes the certificate.
    Handles IPv4, IPv6, and hostname formats.

.PARAMETER Input
    The domain input string (can include port).

.PARAMETER RetryCount
    Number of retries for transient failures.

.OUTPUTS
    Boolean indicating if processing was successful.
#>
function Test-DomainInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$DomainInput,

        [Parameter()]
        [int]$RetryCount = 0
    )

    # Handle null or empty input
    if ([string]::IsNullOrWhiteSpace($DomainInput)) {
        $originalInput = ""
    } else {
        $originalInput = $DomainInput.Trim()
    }
    
    # Handle empty lines
    if ([string]::IsNullOrWhiteSpace($originalInput)) {
        Write-Host "$originalInput is not valid, don't have an empty line"
        Write-LogFile -Message "$originalInput is empty" -Level "Error" -FunctionName "Test-DomainInput"
        $script:Stats.TotalProcessed++
        $script:Stats.Failed++
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = 'NA'
            Port = 'NA'
            'Common Name' = 'NA'
            'Expiration Date' = 'NA'
            'Serial Number' = 'NA'
            'Thumbprint (SHA1)' = 'NA'
            SAN = 'NA'
        }
        return $false
    }

    # Handle comments (lines starting with #)
    if ($originalInput.StartsWith('#')) {
        Write-LogFile -Message "Skipping comment line: $originalInput" -Level "Debug" -FunctionName "Test-DomainInput"
        return $false
    }

    # Reject URLs with protocol
    if ($originalInput -match '://') {
        Write-Host "$originalInput is not valid, please remove http:// and such"
        Write-LogFile -Message "URLparse does not like the domain $originalInput and should be removed" -Level "Error" -FunctionName "Test-DomainInput"
        $script:Stats.TotalProcessed++
        $script:Stats.Failed++
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = 'NA'
            Port = 'NA'
            'Common Name' = 'NA'
            'Expiration Date' = 'NA'
            'Serial Number' = 'NA'
            'Thumbprint (SHA1)' = 'NA'
            SAN = 'NA'
        }
        return $false
    }

    $domain = $originalInput
    $port = 443

    # Handle IPv6 addresses with port: [2001:db8::1]:443
    if ($originalInput -match '^\[([^\]]+)\]:(\d+)$') {
        $domain = $matches[1]
        $port = [int]$matches[2]
        Write-LogFile -Message "Detected IPv6 address with port: $domain`:$port" -Level "Debug" -FunctionName "Test-DomainInput"
    }
    # Handle domain:port or IPv4:port
    elseif ($originalInput -match '^([^:]+):(\d+)$') {
        $domain = $matches[1]
        $port = [int]$matches[2]
        Write-LogFile -Message "The Domain $originalInput has a port" -Level "Debug" -FunctionName "Test-DomainInput"
    }
    # Handle multiple colons (could be IPv6 without brackets)
    elseif (($originalInput -split ':').Count -gt 2) {
        # Check if it's a valid IPv6 address
        try {
            $ip = [System.Net.IPAddress]::Parse($originalInput)
            if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                $domain = $originalInput
                $port = 443
                Write-LogFile -Message "Detected IPv6 address without port: $domain" -Level "Debug" -FunctionName "Test-DomainInput"
            }
            else {
                Write-Host "bad domains too many colons in line $originalInput"
                Write-LogFile -Message "bad domains too many colons in line $originalInput" -Level "Error" -FunctionName "Test-DomainInput"
                $script:Stats.TotalProcessed++
                $script:Stats.Failed++
                $script:CertificateData += [PSCustomObject]@{
                    Hostname = $originalInput
                    'IP Address' = 'NA'
                    Port = 'NA'
                    'Common Name' = 'NA'
                    'Expiration Date' = 'NA'
                    'Serial Number' = 'NA'
                    'Thumbprint (SHA1)' = 'NA'
                    SAN = 'NA'
                }
                return $false
            }
        }
        catch {
            Write-Host "bad domains too many colons in line $originalInput"
            Write-LogFile -Message "bad domains too many colons in line $originalInput" -Level "Error" -FunctionName "Test-DomainInput"
            $script:Stats.TotalProcessed++
            $script:Stats.Failed++
            $script:CertificateData += [PSCustomObject]@{
                Hostname = $originalInput
                'IP Address' = 'NA'
                Port = 'NA'
                'Common Name' = 'NA'
                'Expiration Date' = 'NA'
                'Serial Number' = 'NA'
                'Thumbprint (SHA1)' = 'NA'
                SAN = 'NA'
            }
            return $false
        }
    }

    # Validate port range
    if ($port -lt 1 -or $port -gt 65535) {
        Write-Host "Invalid port number: $port (must be 1-65535)"
        Write-LogFile -Message "Invalid port number: $port for domain $domain" -Level "Error" -FunctionName "Test-DomainInput"
        $script:Stats.TotalProcessed++
        $script:Stats.Failed++
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = 'NA'
            Port = 'NA'
            'Common Name' = 'NA'
            'Expiration Date' = 'NA'
            'Serial Number' = 'NA'
            'Thumbprint (SHA1)' = 'NA'
            SAN = 'NA'
        }
        return $false
    }

    Write-Host $domain
    Write-LogFile -Message "Processing domain: $domain on port $port" -Level "Debug" -FunctionName "Test-DomainInput"

    # Retrieve certificate with retry logic
    $cert = $null
    $attempt = 0
    
    while ($attempt -le $RetryCount) {
        if ($attempt -gt 0) {
            $backoffSeconds = [Math]::Pow(2, $attempt - 1)
            Write-LogFile -Message "Retrying connection to $domain`:$port (attempt $attempt, waiting $backoffSeconds seconds)" -Level "Info" -FunctionName "Test-DomainInput"
            Start-Sleep -Seconds $backoffSeconds
        }
        
        # Suppress error output from Get-SslCertificate (we handle errors ourselves)
        $cert = Get-SslCertificate -Address $domain -Port $port -TimeoutSeconds $Timeout -ErrorAction SilentlyContinue
        
        if ($cert) {
            break
        }
        
        $attempt++
    }

    if (-not $cert) {
        # Provide a cleaner error message
        Write-Host ""
        Write-Host "✗ $originalInput is not reachable or does not have a valid SSL certificate" -ForegroundColor Red
        Write-Host "  Port: $port | Timeout: ${Timeout}s" -ForegroundColor Gray
        Write-Host ""
        Write-LogFile -Message "$originalInput is down or unreachable" -Level "Error" -FunctionName "Test-DomainInput"
        $script:Stats.TotalProcessed++
        $script:Stats.Failed++
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = 'NA'
            Port = 'NA'
            'Common Name' = 'NA'
            'Expiration Date' = 'NA'
            'Serial Number' = 'NA'
            'Thumbprint (SHA1)' = 'NA'
            SAN = 'NA'
        }
        return $false
    }

    # Process certificate
    try {
        $certSan = Get-CertificateSan -Certificate $cert
        if ([string]::IsNullOrWhiteSpace($certSan)) {
            $certSan = "N/A"
        }
        
        $certCommonName = Get-CertificateCommonName -Certificate $cert
        $expDate = Get-CertificateExpiration -Certificate $cert
        $ipAddress = Get-IpAddress -Address $domain -Port $port

        # Check for proxy certificate
        $isProxy = $false
        if ($ProxyCaName) {
            $isProxy = Test-ProxyCertificate -Certificate $cert -ProxyCaName $ProxyCaName
            if ($isProxy) {
                $script:Stats.ProxyDetected++
            }
        }

        $serialNumber = if ($isProxy) { "PROXY CERT" } else { Get-CertificateSerialNumber -Certificate $cert }
        $thumbprint = if ($isProxy) { "PROXY CERT" } else { Get-CertificateThumbprint -Certificate $cert }

        # Check expiration warning
        $daysUntilExpiration = ($cert.NotAfter - (Get-Date)).Days
        if ($daysUntilExpiration -le $ExpirationWarningDays -and $daysUntilExpiration -ge 0) {
            $script:Stats.ExpiringSoon++
        }

        # Display certificate information with better formatting
        Write-Host ""
        Write-Host "✓ SSL Certificate for $originalInput" -ForegroundColor Green
        Write-Host "  IP Address: $ipAddress" -ForegroundColor Cyan
        Write-Host "  Port: $port" -ForegroundColor Cyan
        Write-Host "  Common Name: $certCommonName" -ForegroundColor Cyan
        Write-Host "  Expires: $expDate" -ForegroundColor Cyan
        Write-Host "  Serial #: $serialNumber" -ForegroundColor Cyan
        Write-Host "  Thumbprint: $thumbprint" -ForegroundColor Cyan
        Write-Host "  SAN: $certSan" -ForegroundColor Cyan
        Write-Host ""

        # Add to collection
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = $ipAddress
            Port = $port
            'Common Name' = $certCommonName
            'Expiration Date' = $expDate
            'Serial Number' = $serialNumber
            'Thumbprint (SHA1)' = $thumbprint
            SAN = $certSan
        }

        $script:Stats.TotalProcessed++
        $script:Stats.Successful++

        # Dispose certificate
        $cert.Dispose()

        return $true
    }
    catch {
        Write-LogFile -Message "Error processing certificate for $originalInput`: $_" -Level "Error" -FunctionName "Test-DomainInput"
        $script:Stats.TotalProcessed++
        $script:Stats.Failed++
        $script:CertificateData += [PSCustomObject]@{
            Hostname = $originalInput
            'IP Address' = 'NA'
            Port = 'NA'
            'Common Name' = 'NA'
            'Expiration Date' = 'NA'
            'Serial Number' = 'NA'
            'Thumbprint (SHA1)' = 'NA'
            SAN = 'NA'
        }
        
        if ($cert) {
            $cert.Dispose()
        }
        
        return $false
    }
}

#endregion

#region Output Functions

<#
.SYNOPSIS
    Exports certificate data to CSV file.

.DESCRIPTION
    Exports all collected certificate data to a CSV file with automatic date appending.
    Handles file overwrite prompts.

.PARAMETER OutputBase
    Base filename for output (date will be appended).

.PARAMETER CertificateData
    Array of certificate data objects to export.
#>
function Export-CertificateData {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputBase,

        [Parameter(Mandatory = $true)]
        [array]$CertificateData
    )

    try {
        # Generate filename with date
        $dateSuffix = (Get-Date).ToString("ddMMyy")
        
        # Remove .csv extension if present
        $baseName = $OutputBase -replace '\.csv$', ''
        
        $outputFile = "$baseName-$dateSuffix.csv"
        
        Write-LogFile -Message "Preparing to export to $outputFile" -Level "Info" -FunctionName "Export-CertificateData"

        # Check if file exists
        if (Test-Path $outputFile) {
            Write-Host "file already exists"
            Write-LogFile -Message "A file with the same name already exists: $outputFile" -Level "Info" -FunctionName "Export-CertificateData"
            
            $replaceFile = Read-Host "would you like to replace? Y/N"
            $replaceFile = $replaceFile.ToUpper()
            
            if ($replaceFile -eq 'Y') {
                Write-LogFile -Message "User Selected to overwrite: $outputFile" -Level "Info" -FunctionName "Export-CertificateData"
            }
            elseif ($replaceFile -eq 'N') {
                Write-LogFile -Message "User Selected to NOT to overwrite, need a new filename" -Level "Info" -FunctionName "Export-CertificateData"
                $outputFile = Read-Host "Enter a new file name"
                # Ensure it has .csv extension and add date
                if (-not $outputFile.EndsWith('.csv')) {
                    $outputFile = "$outputFile.csv"
                }
                $baseName = $outputFile -replace '\.csv$', ''
                $outputFile = "$baseName-$dateSuffix.csv"
            }
            else {
                Write-LogFile -Message "Invalid response, exiting" -Level "Warning" -FunctionName "Export-CertificateData"
                exit 1
            }
        }

        if ($PSCmdlet.ShouldProcess($outputFile, "Export certificate data")) {
            # Export to CSV
            $CertificateData | Export-Csv -Path $outputFile -Encoding UTF8 -NoTypeInformation
            
            Write-Host "Certificate data exported to $outputFile"
            Write-LogFile -Message "Certificate data exported successfully to $outputFile" -Level "Info" -FunctionName "Export-CertificateData"
            
            # Validate output
            $exportedRows = (Import-Csv $outputFile).Count
            if ($exportedRows -ne $CertificateData.Count) {
                Write-Warning "Row count mismatch: Expected $($CertificateData.Count), exported $exportedRows"
                Write-LogFile -Message "Row count mismatch: Expected $($CertificateData.Count), exported $exportedRows" -Level "Warning" -FunctionName "Export-CertificateData"
            }
        }
    }
    catch {
        Write-Error "Failed to export certificate data: $_"
        Write-LogFile -Message "Failed to export certificate data: $_" -Level "Error" -FunctionName "Export-CertificateData"
        throw
    }
}

#endregion

#region Main Script Logic

# Only execute main logic if script is run directly (not dot-sourced) and has required parameters
# Check if we're being invoked directly (not dot-sourced)
$isDotSourced = $MyInvocation.InvocationName -eq '.' -or $null -eq $MyInvocation.Line

# Only execute if not dot-sourced and we have a PSCmdlet context
if (-not $isDotSourced -and $PSCmdlet -ne $null) {
    # Validate that at least one required parameter is provided (and not just null/empty)
    $hasValidDomainFile = $DomainFile -and $DomainFile.Trim() -ne ''
    $hasValidSingle = $Single -and $Single.Trim() -ne ''
    
    # Ensure only one parameter is provided (mutual exclusivity)
    if ($hasValidDomainFile -and $hasValidSingle) {
        Write-Error "Cannot specify both -DomainFile and -Single. Please specify only one."
        exit 1
    }
    
    if (-not $hasValidDomainFile -and -not $hasValidSingle) {
        Write-Error "Either -DomainFile or -Single parameter must be provided."
        exit 1
    }
    # Initialize logging
    Write-LogFile -Message "Script started - Version $script:Version" -Level "Info" -FunctionName "Main"

    # Process input based on parameter set (check which parameter was actually provided)
    if ($hasValidDomainFile) {
    Write-LogFile -Message "Reading from file with list of domains: $DomainFile" -Level "Debug" -FunctionName "Main"
    
    if (-not (Test-Path $DomainFile -PathType Leaf)) {
        Write-Error "File not found: $DomainFile"
        exit 1
    }

    # Read domains from file
    $domains = Get-Content $DomainFile -Encoding UTF8 | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }
    
    $totalDomains = $domains.Count
    Write-LogFile -Message "Found $totalDomains domains to process" -Level "Info" -FunctionName "Main"

    # Process domains sequentially (parallel processing would require function serialization)
    # For large-scale parallel processing, consider using PowerShell jobs or runspaces
    $current = 0
    foreach ($domain in $domains) {
        $current++
        if ($totalDomains -gt 1) {
            $percentComplete = [Math]::Round(($current / $totalDomains) * 100, 2)
            Write-Progress -Activity "Processing Domains" -Status "Processing $domain ($current of $totalDomains)" -PercentComplete $percentComplete
        }
        
        Test-DomainInput -DomainInput $domain -RetryCount $RetryCount
    }
    Write-Progress -Activity "Processing Domains" -Completed
}
    elseif ($hasValidSingle) {
        Write-LogFile -Message "Checking single domain: $Single" -Level "Debug" -FunctionName "Main"
        Test-DomainInput -DomainInput $Single -RetryCount $RetryCount
    }

    # Export to CSV only when using DomainFile (not for single domain queries)
    # Single domain queries only display to console
    if ($hasValidDomainFile -and $script:CertificateData.Count -gt 0) {
        # Determine output base name:
        # 1. If -Output is specified, use it
        # 2. Otherwise, use the input filename (without extension) as default
        if ($Output) {
            $outputBase = $Output
        }
        else {
            # Extract base filename from DomainFile (remove path and extension)
            $inputFileName = [System.IO.Path]::GetFileNameWithoutExtension($DomainFile)
            $outputBase = $inputFileName
        }
        
        Export-CertificateData -OutputBase $outputBase -CertificateData $script:CertificateData
    }
    elseif ($hasValidSingle -and $Output) {
        # If user explicitly specifies -Output with -Single, honor it
        Export-CertificateData -OutputBase $Output -CertificateData $script:CertificateData
    }

    # Display statistics
    $endTime = Get-Date
    $duration = $endTime - $script:Stats.StartTime

    Write-Host ""
    Write-Host "=== Statistics ===" -ForegroundColor Cyan
    Write-Host "Total Processed: $($script:Stats.TotalProcessed)"
    Write-Host "Successful: $($script:Stats.Successful)" -ForegroundColor Green
    Write-Host "Failed: $($script:Stats.Failed)" -ForegroundColor Red
    Write-Host "Proxy Certificates Detected: $($script:Stats.ProxyDetected)" -ForegroundColor Yellow
    Write-Host "Expiring Soon (within $ExpirationWarningDays days): $($script:Stats.ExpiringSoon)" -ForegroundColor Yellow
    Write-Host "Total Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Host ""

    Write-LogFile -Message "Script completed - Processed: $($script:Stats.TotalProcessed), Successful: $($script:Stats.Successful), Failed: $($script:Stats.Failed)" -Level "Info" -FunctionName "Main"

    # Display certificate data summary
    if ($VerbosePreference -ne 'SilentlyContinue') {
        Write-Host "Certificate Data Summary:" -ForegroundColor Cyan
        $script:CertificateData | Format-Table -AutoSize
    }

    # Exit with appropriate code
    if ($script:Stats.Failed -gt 0 -and $script:Stats.Successful -eq 0) {
        exit 1
    }
    elseif ($script:Stats.Failed -gt 0) {
        exit 2
    }
    else {
        exit 0
    }
}

#endregion

