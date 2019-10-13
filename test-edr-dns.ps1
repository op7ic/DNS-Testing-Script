<#
VERSION      DATE          AUTHOR
0.1A      14/10/2019       op7ic
#> # Revision History


<#
  .SYNOPSIS
    This script downloads malicious domains from public repositories and executes nslookup against these domaions with default DNS server.
	Run script as "powershell -nop -exec bypass .\test-edr-dns.ps1 -dnsserver <IP>"
  .EXAMPLE
    test-edr-dns.ps1
#>

function help{
Write-Host @"
Usage: powershell -nop -exec bypass .\test-edr-dns.ps1 
-dnsserver Specify DNS server to use for lookups (i.e. 208.67.222.222). Optional
-help   Show this help
"@
}
#Global variable used to stored DNS records
$DNSNames = New-Object collections.arraylist

#Function to perform actual DNS lookup
function resolveMalwareDNS($arrayToResolve,$dnsserver){
$success = 0
$fail = 0
foreach ($mal in $arrayToResolve){
try{
if ($dnsserver){
$obj=(Resolve-DnsName -NoHostsFile -Name $mal -DnsOnly -Server $dnsserver -ErrorAction Stop) | Out-Null
Write-Host "[!] $mal resolves as " $obj.IPAddress
}else{
$obj=(Resolve-DnsName -NoHostsFile -Name $mal -DnsOnly -ErrorAction Stop) | Out-Null
Write-Host "[!] $mal resolves as " $obj.IPAddress
}
$success += 1
}catch{
$fail +=1
}
}
Write-Host "[+] Successful resolutions for malicious domains: " $success -ForegroundColor Red
Write-Host "[!] Blocked resolutions for malicious domains: " $fail -ForegroundColor Green
}


#Function to dowload and cleanup domain names
function downloadCombine($dnsserver){
#Download domains from the following locations:
#"https://www.malwaredomainlist.com/hostslist/hosts.txt",
#"https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
#"https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
#"https://www.dshield.org/feeds/suspiciousdomains_Medium.txt",
#"https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"
# http://mirror1.malwaredomains.com/files/domains.txt
$unpackdirectory = (Convert-Path .) + "\malwarednsrecord"	
checkPath	
$data = @(
"https://www.malwaredomainlist.com/hostslist/hosts.txt",
"https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
"https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
"https://www.dshield.org/feeds/suspiciousdomains_Medium.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
"http://mirror1.malwaredomains.com/files/domains.txt"
)

foreach ($url in $data){
     try{
	 $basename = ($url -split "/")[-1]
	 (New-Object System.Net.WebClient).DownloadFile($url, "$unpackdirectory\$basename")
	 Write-Host "[+] Downloading $url to $unpackdirectory\$basename"
	 cleanDownload("$unpackdirectory\$basename")
     }catch{
	 Write-Host "[+] Unable to download $url"
	 }
}

Write-Host "[+] Total number of records: " $DNSNames.Count
resolveMalwareDNS($DNSNames,$dnsserver)
Write-Host "[+] Removing output folder: $unpackdirectory"
rmdir $unpackdirectory
}

#Depending on file name use different ways to cleanup and extract domains
function cleanDownload($path){
if($path -like "*domains.txt"){
$domainSource = Get-Content -Path $path | Where { $_ -notmatch "^#" -and $_ -notmatch "Site" -and $_ -notmatch "Malvertising list by Disconnect" -and $_ -notmatch "malware-check.disconnect.me" -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0) -and $_ -notmatch "localhost"}
foreach ($line in $domainSource){
    $ob = $line -split '\s+|\t+'
    $DNSNames.Add($ob[1]) | Out-Null
}
}elseif($path -like "*hosts.txt"){
$hostSource = Get-Content -Path $path | Where { $_ -notmatch "^#" -and $_ -notmatch "Site" -and $_ -notmatch "Malvertising list by Disconnect" -and $_ -notmatch "malware-check.disconnect.me" -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0) -and $_ -notmatch "localhost"}
foreach ($line in $hostSource){
    $ob2 = $line.split(" ")
	$DNSNames.Add($ob2[2]) | Out-Null
}
}else{
$remaining = Get-Content -Path $path | Where { $_ -notmatch "^#" -and $_ -notmatch "Site" -and $_ -notmatch "Malvertising list by Disconnect" -and $_ -notmatch "malware-check.disconnect.me" -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0) -and $_ -notmatch "localhost"}
foreach ($r in $remaining){
	$DNSNames.Add($r) | Out-Null
}
}
}

function checkPath(){
#Harcode path for downloads of temp files
$unpackdirectory = (Convert-Path .) + "\malwarednsrecord\"
# Check if output directory exists. Powershell 2.0 unzip version
if(!(Test-Path $unpackdirectory)){
#If directory doesnt exist, create it
Write-Host "[+] folder for downloads missing, creating it at $unpackdirectory"
New-Item -ItemType Directory -Path $unpackdirectory | Out-Null 
}else
{
Write-Host "[+] Output folder at $unpackdirectory exists. Doing nothing"
}
}


if($args[0] -eq "-help"){
Write-Output "[!] Option selected: Help" 
help
}elseif($args[0] -eq "-dnsserver"){
Write-Output "[!] Option selected: Run against $args[1] DNS server" 
downloadCombine($args[1])
}else{
Write-Output "[!] Option selected: Run against default DNS server" 
downloadCombine
}

