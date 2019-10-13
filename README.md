# DNS-Testing-Script

This repository contains a PowerShell-based tool, which can be used to test DNS monitoring solutions for correct detection of malicious DNS name resolutions. This tool is written as a single script, so it can be easily uploaded and run (as opposed to un-zipped, compiled and installed). The script can run as a normal user and does not need any extra privileges other than having PowerShell enabled. It will use the default DNS Server, or an alternative DNS Server can be specified via the **-dnsserver** parameter. 


**How To**

Run the [test-edr-dns.ps1](test-edr-dns.ps1) script and observe alerts coming to DNS monitoring console. Cross-verify these alerts to check how many malicious DNS calls are identified correctly. All of the downloaded repositories are marked as malicious or phishing or malware (reference list below). DO NOT USE THIS SCRIPTS ON PRODUCTION SYSTEMS, INSTEAD DEPLOY THIS IN A VM WHICH IS MONITORED BY DNS MONITORING AND FILTERING SOLUTION.  

**Weaponization** 

None - this script will simply lookup known bad DNS domain names.

**Tested On**

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

**Coverage**

The following DNS repositories are downloaded and used: 

| URL | Source | 
| ------------- | ------------- |
| https://www.malwaredomainlist.com/hostslist/hosts.txt | MalwareDomainList | 
| https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | Abuse.ch |
| https://isc.sans.edu/feeds/suspiciousdomains_High.txt | SANS | 
| https://www.dshield.org/feeds/suspiciousdomains_Medium.txt | DSHIELD | 
| https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | disconnect.me | 
| http://mirror1.malwaredomains.com/files/domains.txt | malwaredomains.com | 

**Process** 

For each domain name from above list a simple nslookup is executed. If nslookup fails this mean that DNS block was successful. If nslookup shows IP address from sinkholed ranges this is considered as successful block too.

**Expected Outcome**

DNS resolution to malware domains should be blocked. Following this example, if 44223 malware domains are looked up and there are 44223 alerts in your tool then coverage is 100%.

**Sinkholed traffic**

If an IP is resolved correctly but to sinkholed range this is good. For example, any domain resolved to an IP from the following range could be simply sinkholed by OpenDNS:

https://bgp.he.net/search?search%5Bsearch%5D=OpenDNS&commit=Search

