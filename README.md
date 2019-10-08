# DNS-Testing-Script

This repository contains a simple script to test DNS monitoring solutions. It is written as a single PowerShell script so it can be easily uploaded and run (as opposed to un-zipped, compiled and installed). The script can run as a normal user and does not need any extra privilages.

Right now this script only works on Windows and should work with most security endpoint solutions.

**How To**

Run the [runtests](runtests.bat) script and observe alerts coming to your console. Cross-verify these alerts to check how many are identified correctly. All of the domains used in repositories are known to be malicious with exception of top 1m sites used for some extra traffic generation. DO NOT USE THIS SCRIPTS ON PRODUCTION SYSTEMS, INSTEAD DEPLOY THIS IN A VM WHICH IS MONITORED BY DNS MONITORING SOLUTION.  

**Why**

Because it is hard to figure out how accurate DNS filtering devices/services are.  

**Weaponization** 

None - this script will simply lookup DNS domain names.

**Tested On**

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

**Coverage**

The following DNS repositories are downloaded and used: 

* http://www.malwaredomainlist.com/mdlcsv.php?inactive=off
* https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
* https://isc.sans.edu/feeds/suspiciousdomains_High.txt
* https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt
* http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip

**Process** 

For each domain name from above list a simple nslookup is executed. 