<#
.SYNOPSIS
    DNS Security Testing Tool - Tests DNS monitoring solutions for detection of malicious domain resolutions
    
.DESCRIPTION
    This script downloads malicious domains from public threat intelligence sources and performs DNS lookups 
    against them using either default or specified DNS server. It generates comprehensive HTML reports
    showing which domains were blocked vs allowed, helping security teams validate their DNS security controls.
    
.PARAMETER DnsServer
    Specify DNS server to use for lookups (e.g., 8.8.8.8). Optional - uses system default if not specified.
    
.PARAMETER OutputPath
    Path where HTML report and logs will be saved. Default is current directory.
    
.PARAMETER MaxThreads
    Maximum number of concurrent DNS lookups. Default is 10.
    
.PARAMETER Help
    Show help information.
    
.EXAMPLE
    .\test-edr-dns.ps1
    Run with default DNS server
    
.EXAMPLE
    .\test-edr-dns.ps1 -DnsServer 8.8.8.8 -OutputPath C:\Reports
    Run with specific DNS server and output path
    
.NOTES
    Version:        2.0
    Author:         Jerzy 'Yuri' Kramarz
    Last Modified:  2025-06-27
#>

param(
    [string]$DnsServer,
    [string]$OutputPath = (Get-Location).Path,
    [int]$MaxThreads = 10,
    [switch]$Help
)

# PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: This script requires PowerShell 5.0 or higher. You have version $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host "Please upgrade PowerShell from: https://aka.ms/wmf5download" -ForegroundColor Yellow
    exit 1
}

# Show help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit
}

# Parameter validation
if ($MaxThreads -lt 1 -or $MaxThreads -gt 50) {
    Write-Host "ERROR: MaxThreads must be between 1 and 50. You specified: $MaxThreads" -ForegroundColor Red
    exit 1
}

if ($DnsServer -and -not ($DnsServer -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -or $DnsServer -match "^[a-zA-Z0-9.-]+$")) {
    Write-Host "ERROR: Invalid DNS server format. Please provide a valid IP address or hostname." -ForegroundColor Red
    exit 1
}

if ($OutputPath -and -not (Test-Path $OutputPath -IsValid)) {
    Write-Host "ERROR: Invalid output path specified: $OutputPath" -ForegroundColor Red
    exit 1
}

# Global variables
$Script:DNSResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$Script:ThreatSources = @{
    "zonefiles.io" = "https://zonefiles.io/f/compromised/domains/live/"
    "romainmarcoux_malicious_domains" = "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-aa.txt"
    "botvrij.eu" = "http://www.botvrij.eu/data/ioclist.domain.raw"
    "openphish" = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    "Disconnect.me" = "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"
}

# Known sinkhole IP ranges and addresses
$Script:SinkholeRanges = @(
    # Cisco OpenDNS/Umbrella
    "146.112.61.104-146.112.61.110",  # OpenDNS block pages
    "67.215.65.130-67.215.65.134",    # OpenDNS (legacy)
    
    # Palo Alto Networks
    "72.5.65.111",                     # Palo Alto (old)
    "198.135.184.22",                  # Palo Alto (new as of 2025)
    
    # Microsoft
    "131.253.18.11-131.253.18.12",     # Microsoft sinkholes
    "199.2.137.0/24",                  # Microsoft sinkhole subnet
    "204.95.99.59",                    # Microsoft sinkhole
    "207.46.90.0/24",                  # Microsoft sinkhole subnet
    
    # Security Research Organizations
    "38.102.150.29",                   # Team Cymru Conficker sinkhole
    "38.229.70.125",                   # Team Cymru Conficker sinkhole
    "176.58.104.168",                  # SIDN Labs
    "212.227.20.19",                   # sinkhole.DK
    "86.124.164.25",                   # sinkhole.in
    
    # Spamhaus
    "208.43.245.213",                  # Spamhaus sinkhole
    "173.192.192.10",                  # Spamhaus sinkhole
    "199.231.211.108",                 # Spamhaus sinkhole
    "198.98.120.157",                  # Spamhaus sinkhole
    "192.42.116.41",                   # Spamhaus sinkhole
    "87.255.51.229",                   # Spamhaus sinkhole
    
    # ISP Sinkholes
    "8.7.198.45",                      # AT&T sinkhole
    "54.244.112.0/24",                 # Amazon sinkhole
    
    # Law Enforcement
    "104.244.12.0/22",                 # FBI sinkhole range
    
    # Other Security Vendors
    "192.203.230.10",                  # Arbor sinkhole
    "198.105.244.11",                  # Dr.Web sinkhole
    "198.105.254.11",                  # Dr.Web sinkhole
    "93.159.228.22",                   # Kaspersky sinkhole
    "95.211.172.143",                  # Kaspersky sinkhole
    "143.215.130.0/24",                # Georgia Tech
    
    # Common Loopback/Null Routes
    "0.0.0.0",                         # Null route
    "127.0.0.1",                       # Localhost
    "::1",                             # IPv6 loopback
    
    # Private IP Ranges (commonly used for internal sinkholes)
    "10.255.255.1",                    # Common private sinkhole
    "192.168.255.254"                  # Common private sinkhole
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-IsSinkholed {
    param([string]$IPAddress)
    
    foreach ($range in $Script:SinkholeRanges) {
        if ($range -match "/") {
            # CIDR notation
            $network = $range -split "/"
            $baseIP = $network[0]
            $subnet = [int]$network[1]
            # Simplified check - would need proper CIDR calculation for production
            if ($IPAddress -like "$($baseIP.Split('.')[0..2] -join '.').*") {
                return $true
            }
        }
        elseif ($range -match "-") {
            # Range notation
            $parts = $range -split "-"
            $startIP = $parts[0]
            $endIP = $parts[1]
            # Simplified check
            if ($IPAddress -ge $startIP -and $IPAddress -le $endIP) {
                return $true
            }
        }
        else {
            # Single IP
            if ($IPAddress -eq $range) {
                return $true
            }
        }
    }
    return $false
}

function Get-ThreatDomains {
    Write-ColorOutput "[*] Starting download of threat intelligence feeds..." "Cyan"
    
    $allDomains = [System.Collections.Generic.HashSet[string]]::new()
    
    foreach ($source in $Script:ThreatSources.GetEnumerator()) {
        $webClient = $null
        try {
            Write-ColorOutput "[+] Downloading from $($source.Key)..." "Green"
            
            # Download content to memory
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "DNS-Security-Tester/2.0")
            
            # Set timeout for web requests (30 seconds)
            $webClient.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
            
            $content = $webClient.DownloadString($source.Value)
            
            if ([string]::IsNullOrWhiteSpace($content)) {
                Write-ColorOutput "    Warning: Empty response from $($source.Key)" "Yellow"
                continue
            }
            
            # Parse domains from memory
            $domains = Parse-DomainList -Content $content -Source $source.Key
            if ($domains -and $domains.Count -gt 0) {
                foreach ($domain in $domains) {
                    [void]$allDomains.Add($domain)
                }
                Write-ColorOutput "    Found $($domains.Count) domains" "Gray"
            }
            else {
                Write-ColorOutput "    Warning: No valid domains found in $($source.Key)" "Yellow"
            }
        }
        catch {
            Write-ColorOutput "[-] Failed to download from $($source.Key): $_" "Red"
        }
        finally {
            if ($webClient) {
                $webClient.Dispose()
            }
        }
    }
    
    $totalCollected = $allDomains.Count
    Write-ColorOutput "[*] Total unique domains collected: $totalCollected" "Yellow"
    
    # Check if we got any domains
    if ($totalCollected -eq 0) {
        Write-ColorOutput "[-] ERROR: No domains were collected from any source. Check your internet connection." "Red"
        return [PSCustomObject]@{
            Domains = @()
            TotalAvailable = 0
        }
    }
    
    # Randomly select 3000 domains
    $domainArray = @($allDomains)
    if ($domainArray.Count -gt 3000) {
        Write-ColorOutput "[*] Randomly selecting 3000 domains from $totalCollected total domains..." "Yellow"
        
        # Shuffle for true randomization
        $random = New-Object System.Random
        for ($i = $domainArray.Count - 1; $i -gt 0; $i--) {
            $j = $random.Next($i + 1)
            $temp = $domainArray[$i]
            $domainArray[$i] = $domainArray[$j]
            $domainArray[$j] = $temp
        }
        
        # Take first 3000 after shuffle
        $selectedDomains = $domainArray[0..2999]
        Write-ColorOutput "[*] Selected 3000 random domains for testing" "Green"
        
        return [PSCustomObject]@{
            Domains = $selectedDomains
            TotalAvailable = $totalCollected
        }
    }
    else {
        Write-ColorOutput "[*] Using all $totalCollected domains (less than 3000 available)" "Yellow"
        return [PSCustomObject]@{
            Domains = $domainArray
            TotalAvailable = $totalCollected
        }
    }
}

function Parse-DomainList {
    param(
        [string]$Content,
        [string]$Source
    )
    
    $domains = [System.Collections.Generic.List[string]]::new()
    
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $domains
    }
    
    $lines = $Content -split "`r?`n"
    
    if (!$lines -or $lines.Count -eq 0) { 
        return $domains 
    }
    
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        
        # Skip comments and empty lines
        if ($line -match "^#" -or $line -match "^\s*$") {
            continue
        }
        
        # Skip specific headers for Disconnect.me
        if ($Source -eq "Disconnect.me" -and ($line -match "Malvertising list by Disconnect" -or $line -match "License:" -or $line -match "Email:")) {
            continue
        }
        
        # Parse based on source
        $domain = $null
        
        switch ($Source) {
            "openphish" {
                # OpenPhish contains full URLs, extract domain
                if ($line -match "^https?://([^/:]+)") {
                    $domain = $matches[1].Trim()
                }
            }
            
            "zonefiles.io" {
                # Plain domains, one per line
                if ($line -match "^[^#\s][\w\.-]+\.\w+") {
                    $domain = $line.Trim()
                }
            }
            
            "romainmarcoux_malicious_domains" {
                # Plain domains including internationalized (xn--)
                if ($line -match "^[\w\.-]+\.\w+") {
                    $domain = $line.Trim()
                }
            }
            
            "botvrij.eu" {
                # Plain domains
                if ($line -match "^[\w\.-]+\.\w+") {
                    $domain = $line.Trim()
                }
            }
            
            "Disconnect.me" {
                # Plain domains after header
                if ($line -match "^[^#][\w\.-]+\.\w+") {
                    $domain = $line.Trim()
                }
            }
            
            default {
                # Legacy format handling for old sources
                if ($FilePath -like "*hosts.txt") {
                    # Format: 127.0.0.1  malicious.domain.com
                    if ($line -match "^\d+\.\d+\.\d+\.\d+\s+(.+)$") {
                        $domain = $matches[1].Trim()
                    }
                }
                elseif ($FilePath -like "*domains.txt") {
                    # Format: primarydomain secondarydomain
                    $parts = $line -split '\s+|\t+'
                    if ($parts.Count -ge 2) {
                        $domain = $parts[1].Trim()
                    }
                    else {
                        $domain = $line.Trim()
                    }
                }
                else {
                    # Simple domain list
                    $domain = $line.Trim()
                }
            }
        }
        
        # Validate and add domain
        # Enhanced validation to support internationalized domains (xn--)
        if ($domain -and $domain -ne "localhost" -and $domain -match "^[a-zA-Z0-9]([a-zA-Z0-9-_.])*[a-zA-Z0-9]$|^xn--[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$") {
            # Remove 'www.' prefix if present for consistency
            $domain = $domain -replace "^www\.", ""
            $domains.Add($domain.ToLower())
        }
    }
    
    return $domains
}

function Test-DNSResolution {
    param(
        [string[]]$Domains,
        [string]$DnsServer,
        [int]$MaxThreads
    )
    
    # Validate input
    if (-not $Domains -or $Domains.Count -eq 0) {
        Write-ColorOutput "[-] ERROR: No domains provided for testing" "Red"
        return
    }
    
    $total = $Domains.Count
    $batchSize = [Math]::Min(100, $MaxThreads * 2)  # Process domains in batches
    $batches = [Math]::Ceiling([double]$total / [double]$batchSize)
    
    Write-ColorOutput "[*] Starting DNS resolution tests on $total domains" "Cyan"
    Write-ColorOutput "[*] Processing in $batches batches of $batchSize domains with $MaxThreads concurrent threads" "Cyan"
    
    $processedCount = 0
    $batchNumber = 0
    
    # Process domains in batches
    for ($i = 0; $i -lt $total; $i += $batchSize) {
        $batchNumber++
        $batchEnd = [Math]::Min($i + $batchSize, $total)
        $batchDomains = @($Domains[$i..($batchEnd - 1)])
        
        Write-ColorOutput "`n[*] Processing batch $batchNumber of $batches (domains $($i + 1) to $batchEnd)" "Yellow"
        
        # Create runspace pool for this batch
        $runspacePool = $null
        try {
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
            $runspacePool.Open()
        }
        catch {
            Write-ColorOutput "[-] ERROR: Failed to create runspace pool: $_" "Red"
            Write-ColorOutput "[-] Consider reducing MaxThreads parameter" "Red"
            return
        }
        
        $jobs = @()
        $batchStartTime = Get-Date
        
        foreach ($domain in $batchDomains) {
            $powershell = [powershell]::Create()
            $powershell.RunspacePool = $runspacePool
            
            $scriptBlock = {
                param($domain, $dnsServer, $results)
                
                $result = [PSCustomObject]@{
                    Domain = $domain
                    Resolved = $false
                    IPAddress = $null
                    Status = "Unknown"
                    Error = $null
                    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
                    IsSinkholed = $false
                }
                
                try {
                    $maxRetries = 3
                    $retryCount = 0
                    $dnsResult = $null
                    $lastError = $null
                    
                    while ($retryCount -lt $maxRetries -and -not $dnsResult) {
                        try {
                            $params = @{
                                Name = $domain
                                NoHostsFile = $true
                                DnsOnly = $true
                                ErrorAction = "Stop"
                            }
                            
                            if ($dnsServer) {
                                $params.Server = $dnsServer
                            }
                            
                            $dnsResult = Resolve-DnsName @params
                            break  # Success, exit retry loop
                        }
                        catch {
                            $lastError = $_
                            $retryCount++
                            if ($retryCount -lt $maxRetries) {
                                # Wait briefly before retry (exponential backoff)
                                Start-Sleep -Milliseconds ([Math]::Min(300, 100 * $retryCount))
                            }
                        }
                    }
                    
                    # If still no result after all retries, throw the last error
                    if (-not $dnsResult -and $lastError) {
                        throw $lastError
                    }
                    
                    if ($dnsResult) {
                        $result.Resolved = $true
                        $result.IPAddress = ($dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
                        
                        if ($result.IPAddress) {
                            # Check if sinkholed
                            $isSinkholed = $false
                            
                            # Exact match sinkholes
                            $exactSinkholes = @(
                                "0.0.0.0", "127.0.0.1", "::1",
                                "72.5.65.111", "198.135.184.22",
                                "204.95.99.59", "38.102.150.29", "38.229.70.125",
                                "176.58.104.168", "212.227.20.19", "86.124.164.25",
                                "208.43.245.213", "173.192.192.10", "199.231.211.108",
                                "198.98.120.157", "192.42.116.41", "87.255.51.229",
                                "8.7.198.45", "192.203.230.10", "198.105.244.11",
                                "198.105.254.11", "93.159.228.22", "95.211.172.143",
                                "10.255.255.1", "192.168.255.254"
                            )
                            
                            # Prefix match sinkholes
                            $prefixSinkholes = @(
                                "146.112.61.10", "146.112.61.11",  # OpenDNS (104-110)
                                "67.215.65.13",                    # OpenDNS legacy (130-134)
                                "131.253.18.1",                    # Microsoft (11-12)
                                "199.2.137.",                      # Microsoft /24
                                "207.46.90.",                      # Microsoft /24
                                "54.244.112.",                     # Amazon /24
                                "104.244.12.", "104.244.13.",      # FBI /22
                                "104.244.14.", "104.244.15.",      # FBI /22
                                "143.215.130."                     # Georgia Tech /24
                            )
                            
                            # Check exact matches first
                            if ($exactSinkholes -contains $result.IPAddress) {
                                $isSinkholed = $true
                            }
                            else {
                                # Check prefix matches
                                foreach ($prefix in $prefixSinkholes) {
                                    if ($result.IPAddress.StartsWith($prefix)) {
                                        $isSinkholed = $true
                                        break
                                    }
                                }
                            }
                            
                            $result.IsSinkholed = $isSinkholed
                            $result.Status = if ($isSinkholed) { "Sinkholed" } else { "Resolved" }
                        }
                    }
                    else {
                        $result.Status = "Blocked"
                        $result.Error = "No response or timeout"
                    }
                }
                catch {
                    $result.Resolved = $false
                    $result.Status = "Blocked"
                    $result.Error = $_.Exception.Message
                }
                
                $results.Add($result)
            }
            
            [void]$powershell.AddScript($scriptBlock)
            [void]$powershell.AddArgument($domain)
            [void]$powershell.AddArgument($DnsServer)
            [void]$powershell.AddArgument($Script:DNSResults)
            
            $jobs += [PSCustomObject]@{
                PowerShell = $powershell
                Handle = $powershell.BeginInvoke()
                Domain = $domain
            }
        }
        
        # Wait for batch to complete with progress
        $completed = 0
        $batchResults = @{
            Blocked = 0
            Resolved = 0
            Sinkholed = 0
        }
        
        while ($jobs | Where-Object { -not $_.Handle.IsCompleted }) {
            $completedNow = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
            if ($completedNow -gt $completed) {
                $completed = $completedNow
                $percentComplete = [Math]::Round(($completed / $batchDomains.Count) * 100, 0)
                Write-Progress -Activity "Batch $batchNumber of $batches" -Status "Completed $completed of $($batchDomains.Count) domains" -PercentComplete $percentComplete
            }
            Start-Sleep -Milliseconds 100
        }
        
        # Collect results from completed batch
        foreach ($job in $jobs) {
            try {
                $job.PowerShell.EndInvoke($job.Handle)
            }
            catch {
                Write-ColorOutput "[-] Error processing domain $($job.Domain): $_" "Red"
            }
            finally {
                $job.PowerShell.Dispose()
            }
        }
        
        $runspacePool.Close()
        $runspacePool.Dispose()
        
        # Calculate batch statistics
        $batchTime = [Math]::Round(((Get-Date) - $batchStartTime).TotalSeconds, 2)
        $processedCount += $batchDomains.Count
        
        # Get current results count by status
        $currentResults = @($Script:DNSResults)
        $blockedCount = ($currentResults | Where-Object { $_.Status -eq "Blocked" }).Count
        $resolvedCount = ($currentResults | Where-Object { $_.Status -eq "Resolved" }).Count
        $sinkholedCount = ($currentResults | Where-Object { $_.Status -eq "Sinkholed" }).Count
        
        Write-ColorOutput "[+] Batch $batchNumber completed in $batchTime seconds" "Green"
        Write-ColorOutput "    Running totals - Blocked: $blockedCount, Resolved: $resolvedCount, Sinkholed: $sinkholedCount" "Gray"
        
        # Small delay between batches to avoid overwhelming DNS server
        if ($batchNumber -lt $batches) {
            Start-Sleep -Milliseconds 500
        }
    }
    
    Write-Progress -Activity "DNS Resolution Testing" -Completed
    Write-ColorOutput "`n[+] All DNS resolution tests completed" "Green"
}

function New-HTMLReport {
    param(
        [array]$Results,
        [string]$OutputPath,
        [string]$DnsServer,
        [int]$TotalDomainsAvailable
    )
    
    $reportPath = Join-Path $OutputPath "DNS_Security_Test_Report_$((Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss'))_UTC.html"
    
    # Calculate statistics
    $totalDomains = $Results.Count
    $blockedDomains = ($Results | Where-Object { $_.Status -eq "Blocked" }).Count
    $resolvedDomains = ($Results | Where-Object { $_.Status -eq "Resolved" }).Count
    $sinkholedDomains = ($Results | Where-Object { $_.Status -eq "Sinkholed" }).Count
    $blockRate = if ($totalDomains -gt 0) { [math]::Round(($blockedDomains / $totalDomains) * 100, 2) } else { 0 }
    $effectiveBlockRate = if ($totalDomains -gt 0) { [math]::Round((($blockedDomains + $sinkholedDomains) / $totalDomains) * 100, 2) } else { 0 }
    
    # Group results by status
    $groupedResults = $Results | Group-Object Status
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Security Test Report - $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #666;
            font-size: 1.1em;
        }
        
        .stat-card.blocked { border-top: 4px solid #10b981; }
        .stat-card.blocked .stat-number { color: #10b981; }
        
        .stat-card.resolved { border-top: 4px solid #ef4444; }
        .stat-card.resolved .stat-number { color: #ef4444; }
        
        .stat-card.sinkholed { border-top: 4px solid #f59e0b; }
        .stat-card.sinkholed .stat-number { color: #f59e0b; }
        
        .stat-card.total { border-top: 4px solid #6366f1; }
        .stat-card.total .stat-number { color: #6366f1; }
        
        .chart-container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }
        
        .chart-title {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #333;
        }
        
        .progress-bar {
            width: 100%;
            height: 40px;
            background-color: #e5e7eb;
            border-radius: 20px;
            overflow: hidden;
            position: relative;
            margin-bottom: 30px;
        }
        
        .progress-segment {
            height: 100%;
            float: left;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.5s ease;
        }
        
        .progress-blocked { background-color: #10b981; }
        .progress-sinkholed { background-color: #f59e0b; }
        .progress-resolved { background-color: #ef4444; }
        
        .legend {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }
        
        .details-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #333;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th {
            background-color: #f3f4f6;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 2px solid #e5e7eb;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        tr:hover {
            background-color: #f9fafb;
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .status-blocked { background-color: #d1fae5; color: #065f46; }
        .status-resolved { background-color: #fee2e2; color: #991b1b; }
        .status-sinkholed { background-color: #fed7aa; color: #92400e; }
        
        .test-info {
            background: #f3f4f6;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .info-label {
            font-weight: 600;
            color: #4b5563;
        }
        
        .info-value {
            color: #111827;
        }
        
        .recommendations {
            background: #fef3c7;
            border: 1px solid #fbbf24;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .recommendations h3 {
            color: #92400e;
            margin-bottom: 15px;
        }
        
        .recommendations ul {
            margin-left: 20px;
        }
        
        .recommendations li {
            margin-bottom: 10px;
            color: #78350f;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: #6b7280;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .legend {
                flex-direction: column;
                gap: 10px;
            }
            
            table {
                font-size: 0.9em;
            }
        }
        
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background-color: #f3f4f6;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1.1em;
            font-weight: 600;
            width: 100%;
            margin-top: 20px;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        
        .collapsible:hover {
            background-color: #e5e7eb;
        }
        
        .collapsible:after {
            content: '\002B';
            float: right;
            font-weight: bold;
        }
        
        .active:after {
            content: '\2212';
        }
        
        .content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .content.show {
            max-height: 2000px;
            padding: 20px 0;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>DNS Security Test Report</h1>
            <p class="subtitle">Analysis of DNS Security Controls (Sample of 3000 Domains)</p>
        </div>
    </header>
    
    <div class="container">
        <div class="test-info">
            <div class="info-row">
                <span class="info-label">Test Date (UTC):</span>
                <span class="info-value">$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))</span>
            </div>
            <div class="info-row">
                <span class="info-label">DNS Server:</span>
                <span class="info-value">$(if ($DnsServer) { $DnsServer } else { "System Default" })</span>
            </div>
            <div class="info-row">
                <span class="info-label">Total Domains Available:</span>
                <span class="info-value">$(if ($TotalDomainsAvailable) { "{0:N0}" -f $TotalDomainsAvailable } else { "N/A" })</span>
            </div>
            <div class="info-row">
                <span class="info-label">Domains Tested (Random Sample):</span>
                <span class="info-value">$totalDomains</span>
            </div>
            <div class="info-row">
                <span class="info-label">Test Duration:</span>
                <span class="info-value" id="duration">Calculating...</span>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="stat-card blocked">
                <div class="stat-number">$blockedDomains</div>
                <div class="stat-label">Blocked Domains</div>
            </div>
            <div class="stat-card sinkholed">
                <div class="stat-number">$sinkholedDomains</div>
                <div class="stat-label">Sinkholed Domains</div>
            </div>
            <div class="stat-card resolved">
                <div class="stat-number">$resolvedDomains</div>
                <div class="stat-label">Resolved Domains</div>
            </div>
            <div class="stat-card total">
                <div class="stat-number">$effectiveBlockRate%</div>
                <div class="stat-label">Effective Block Rate</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2 class="chart-title">DNS Resolution Status Distribution</h2>
            <div class="progress-bar">
                <div class="progress-segment progress-blocked" style="width: $(($blockedDomains / $totalDomains) * 100)%">
                    $([math]::Round(($blockedDomains / $totalDomains) * 100, 1))%
                </div>
                <div class="progress-segment progress-sinkholed" style="width: $(($sinkholedDomains / $totalDomains) * 100)%">
                    $([math]::Round(($sinkholedDomains / $totalDomains) * 100, 1))%
                </div>
                <div class="progress-segment progress-resolved" style="width: $(($resolvedDomains / $totalDomains) * 100)%">
                    $([math]::Round(($resolvedDomains / $totalDomains) * 100, 1))%
                </div>
            </div>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #10b981;"></div>
                    <span>Blocked</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #f59e0b;"></div>
                    <span>Sinkholed</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #ef4444;"></div>
                    <span>Resolved</span>
                </div>
            </div>
        </div>
        
        <div class="details-section">
            <h2 class="section-title">Resolution Details by Status</h2>
"@

    # Add collapsible sections for each status
    foreach ($group in $groupedResults) {
        $statusName = $group.Name
        $statusCount = $group.Count
        $statusClass = $statusName.ToLower()
        
        $html += @"
            <button class="collapsible">$statusName Domains ($statusCount)</button>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>IP Address</th>
                            <th>Status</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($result in ($group.Group | Select-Object -First 100)) {
            $html += @"
                        <tr>
                            <td>$($result.Domain)</td>
                            <td>$(if ($result.IPAddress) { $result.IPAddress } else { "N/A" })</td>
                            <td><span class="status-badge status-$statusClass">$($result.Status)</span></td>
                            <td>$($result.Timestamp)</td>
                        </tr>
"@
        }
        
        if ($group.Count -gt 100) {
            $html += @"
                        <tr>
                            <td colspan="4" style="text-align: center; font-style: italic;">
                                ... and $($group.Count - 100) more entries
                            </td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
"@
    }
    
    $html += @"
        </div>
        
        <div class="recommendations">
            <h3>Security Recommendations</h3>
            <ul>
"@

    # Add recommendations based on results
    if ($effectiveBlockRate -lt 90) {
        $html += "<li><strong>Critical:</strong> Your DNS security is blocking less than 90% of known malicious domains. Consider implementing or improving DNS filtering.</li>"
    }
    
    if ($resolvedDomains -gt 0) {
        $html += "<li><strong>High Priority:</strong> $resolvedDomains malicious domains were successfully resolved. Review and block these domains immediately.</li>"
    }
    
    if ($sinkholedDomains -gt 0) {
        $html += "<li><strong>Good:</strong> $sinkholedDomains domains are being sinkholed, which provides some protection.</li>"
    }
    
    if ($effectiveBlockRate -ge 95) {
        $html += "<li><strong>Excellent:</strong> Your DNS security is performing well with a $effectiveBlockRate% effective block rate.</li>"
    }
    
    $html += @"
                <li>Regularly update your DNS blocklists with the latest threat intelligence.</li>
                <li>Consider implementing DNS over HTTPS (DoH) or DNS over TLS (DoT) for additional security.</li>
                <li>Monitor DNS logs for any successful resolutions to malicious domains.</li>
            </ul>
        </div>
    </div>
    
    <footer>
        <p>Generated by DNS-Testing-Script @ https://github.com/op7ic/DNS-Testing-Script | Report created on $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")) UTC</p>
    </footer>
    
    <script>
        // Calculate and display test duration
        const startTime = new Date('$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))');
        const endTime = new Date();
        const duration = Math.round((endTime - startTime) / 1000);
        document.getElementById('duration').textContent = duration + ' seconds';
        
        // Collapsible functionality
        const collapsibles = document.getElementsByClassName('collapsible');
        
        for (let i = 0; i < collapsibles.length; i++) {
            collapsibles[i].addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                content.classList.toggle('show');
            });
        }
        
        // Auto-expand first section
        if (collapsibles.length > 0) {
            collapsibles[0].click();
        }
    </script>
</body>
</html>
"@

    # Save the HTML report
    try {
        $html | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-ColorOutput "[+] HTML report saved to: $reportPath" "Green"
    }
    catch {
        Write-ColorOutput "[-] ERROR: Failed to save HTML report: $_" "Red"
    }
    
    # Also save a CSV for further analysis
    try {
        $csvPath = Join-Path $OutputPath "DNS_Security_Test_Results_$((Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss'))_UTC.csv"
        $Results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
        Write-ColorOutput "[+] CSV results saved to: $csvPath" "Green"
    }
    catch {
        Write-ColorOutput "[-] ERROR: Failed to save CSV results: $_" "Red"
    }
    
    return $reportPath
}

function Show-Summary {
    param([array]$Results)
    
    $totalDomains = $Results.Count
    $blockedDomains = ($Results | Where-Object { $_.Status -eq "Blocked" }).Count
    $resolvedDomains = ($Results | Where-Object { $_.Status -eq "Resolved" }).Count
    $sinkholedDomains = ($Results | Where-Object { $_.Status -eq "Sinkholed" }).Count
    
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "                    TEST SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    Write-Host "`nTotal Domains Tested: " -NoNewline
    Write-Host $totalDomains -ForegroundColor Yellow
    
    if ($totalDomains -gt 0) {
        Write-Host "`nBlocked (Good): " -NoNewline
        Write-Host "$blockedDomains ($([math]::Round(($blockedDomains / $totalDomains) * 100, 2))%)" -ForegroundColor Green
        
        Write-Host "Sinkholed (Good): " -NoNewline
        Write-Host "$sinkholedDomains ($([math]::Round(($sinkholedDomains / $totalDomains) * 100, 2))%)" -ForegroundColor Yellow
        
        Write-Host "Resolved (Bad): " -NoNewline
        Write-Host "$resolvedDomains ($([math]::Round(($resolvedDomains / $totalDomains) * 100, 2))%)" -ForegroundColor Red
        
        Write-Host "`nEffective Block Rate: " -NoNewline
        $effectiveRate = [math]::Round((($blockedDomains + $sinkholedDomains) / $totalDomains) * 100, 2)
    }
    else {
        Write-Host "`nNo domains were tested." -ForegroundColor Yellow
        $effectiveRate = 0
    }
    $color = if ($effectiveRate -ge 95) { "Green" } elseif ($effectiveRate -ge 80) { "Yellow" } else { "Red" }
    Write-Host "$effectiveRate%" -ForegroundColor $color
    
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
}

# Main execution
try {
    $startTime = Get-Date
    
	Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
	Write-Host "          DNS-Testing-Script by op7ic" -ForegroundColor Cyan
	Write-Host ("=" * 60) -ForegroundColor Cyan
	Write-Host ""
    
    # Validate output path
    if (!(Test-Path $OutputPath)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
            Write-ColorOutput "[+] Created output directory: $OutputPath" "Green"
        }
        catch {
            Write-ColorOutput "[-] ERROR: Failed to create output directory: $_" "Red"
            exit 1
        }
    }
    
    # Display configuration
    Write-ColorOutput "[*] Configuration:" "Yellow"
    Write-ColorOutput "    DNS Server: $(if ($DnsServer) { $DnsServer } else { 'System Default' })" "Gray"
    Write-ColorOutput "    Output Path: $OutputPath" "Gray"
    Write-ColorOutput "    Max Threads: $MaxThreads" "Gray"
    Write-Host ""
    
    # Get threat domains
    $domainData = Get-ThreatDomains
    $domains = $domainData.Domains
    $totalAvailable = $domainData.TotalAvailable
    
    if ($domains.Count -eq 0) {
        Write-ColorOutput "[-] No domains collected. Exiting." "Red"
        exit 1
    }
    
    # Test DNS resolutions
    Test-DNSResolution -Domains $domains -DnsServer $DnsServer -MaxThreads $MaxThreads
    
    # Convert results to array
    $results = @($Script:DNSResults)
    
    # Show summary
    Show-Summary -Results $results
    
    # Generate HTML report
    $reportPath = New-HTMLReport -Results $results -OutputPath $OutputPath -DnsServer $DnsServer -TotalDomainsAvailable $totalAvailable
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n[*] Test completed in $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor Cyan
    
    # Try to open the report in default browser
    if ($reportPath -and (Test-Path $reportPath)) {
        if ($env:OS -eq "Windows_NT" -or $PSVersionTable.Platform -eq "Win32NT") {
            try {
                Start-Process $reportPath -ErrorAction Stop
                Write-ColorOutput "[+] Report opened in default browser" "Green"
            }
            catch {
                Write-ColorOutput "[*] Could not open report automatically. Please open manually: $reportPath" "Yellow"
            }
        }
        else {
            Write-ColorOutput "[*] Report saved. Please open manually: $reportPath" "Yellow"
        }
    }
}
catch {
    Write-ColorOutput "`n[-] CRITICAL ERROR: $_" "Red"
    Write-ColorOutput "[-] Error details: $($_.Exception.Message)" "Red"
    Write-ColorOutput "[-] Stack trace: $($_.ScriptStackTrace)" "Red"
    exit 1
}