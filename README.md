# DNS-Testing-Script

This repository contains PowerShell-based tool which can be used to test DNS monitoring solutions for correct detection of known malicious domains. This tool is written as a single script so it can be easily uploaded and run (as opposed to un-zipped, compiled and installed). The script can run as a normal user and does not need any extra privilages other than having PowerShell enabled. It will use default DNS Server to test malware resolutions. Alternative DNS Server can be specified via **-dnsserver** parameter.

Right now this script only works on Windows and should work with most security endpoint solutions.

**How To**

Run the [test-edr-dns.ps1](test-edr-dns.ps1) script and observe alerts coming to DNS monitoring console. Cross-verify these alerts to check how many malicious DNS calls are identified correctly. All of the domains used in repositories are marked as malicious or phishing or malware (reference list below). DO NOT USE THIS SCRIPTS ON PRODUCTION SYSTEMS, INSTEAD DEPLOY THIS IN A VM WHICH IS MONITORED BY DNS MONITORING AND FILTERING SOLUTION.  

**Weaponization** 

None - this script will simply lookup known bad DNS domain names.

**Tested On**

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

**Coverage**

The following DNS repositories are downloaded and used: 

* https://www.malwaredomainlist.com/hostslist/hosts.txt 
* https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
* https://isc.sans.edu/feeds/suspiciousdomains_High.txt
* https://www.dshield.org/feeds/suspiciousdomains_Medium.txt
* https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt
* http://mirror1.malwaredomains.com/files/domains.txt

**Process** 

For each domain name from above list a simple nslookup is executed. If nslookup fails this mean that DNS block was successful. 

**Expected Outcome**

DNS resolution to malware domains should be blocked.

**Sinkholed traffic**

If an IP is resolved correctly but to sinkholed range this is good. For example, any IP resolved to the following range could be simply sinkholed:

https://bgp.he.net/search?search%5Bsearch%5D=OpenDNS&commit=Search

