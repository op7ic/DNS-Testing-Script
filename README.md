# DNS-Testing-Script

A comprehensive PowerShell-based DNS security testing tool designed to validate the effectiveness of DNS monitoring and filtering solutions. This tool helps security teams assess their DNS security controls by testing against known malicious domains from multiple threat intelligence sources.

## Features

- **Smart sampling** - Tests a representative sample of 3000 domains randomly selected from all threat feeds
- **In-memory processing** - Downloads and processes all blocklists without writing to disk
- **Reliable DNS resolution** - Each domain is tested up to 3 times to ensure accurate results
- **Batch processing** - Domains are processed in manageable batches with progress tracking
- **Multi-threaded DNS lookups** for improved performance
- **HTML report** showing findings
- **Sinkhole detection** script will attempt to identify known sinkhole IPs
- **CSV export** is provided for reporting purposes
- **Comprehensive statistics** including effective block rates
- **Security recommendations** based on test results
- **UTC timestamps** - All times are recorded in UTC ISO 8601 format
- **Fisher-Yates shuffle** used for random array choices based on downloaded domains

## How It Works

The script downloads malicious domain lists from trusted threat intelligence sources directly into memory, randomly selects 3000 domains for testing, and performs DNS lookups to test if they're being blocked by your DNS security solution. Results are categorized as:

- **Blocked**: DNS resolution failed (good - domain is blocked)
- **Sinkholed**: Resolved to known sinkhole IPs (good - provides protection)
- **Resolved**: Successfully resolved to real IPs (bad - potential security risk)

## Usage

**⚠️ WARNING**: DO NOT RUN THIS SCRIPT ON PRODUCTION SYSTEMS. Deploy in a controlled test environment monitored by your DNS security solution.

### Basic Usage
```powershell
.\test-edr-dns.ps1
```

### Advanced Usage
```powershell
# Specify custom DNS server
.\test-edr-dns.ps1 -DnsServer 8.8.8.8

# Custom output directory
.\test-edr-dns.ps1 -OutputPath C:\DNSReports

# Increase thread count for faster testing
.\test-edr-dns.ps1 -MaxThreads 20

# Show help
.\test-edr-dns.ps1 -Help
```

### Parameters

- `-DnsServer`: Specify DNS server to test (default: system DNS)
- `-OutputPath`: Directory for reports (default: current directory)
- `-MaxThreads`: Number of concurrent lookups (default: 10)
- `-Help`: Display detailed help information

## Output

The tool generates two types of output:

1. **HTML Report**: A comprehensive, interactive report with:
   - Total domains available vs tested sample size
   - Summary statistics and visualizations
   - Effective block rate calculation
   - Detailed results grouped by status
   - Security recommendations
   - Collapsible sections for easy navigation

2. **CSV Export**: Raw data for further analysis in Excel or other tools

## Requirements

- PowerShell 5.0 or higher
- Internet connectivity to download threat intelligence feeds
- DNS resolution capabilities

## Tested On

- Windows 7 x86/x64
- Windows 10 x64
- Windows 11
- Windows Server 2016+

## Threat Intelligence Sources

The tool downloads and tests domains from the following actively maintained sources:

| Source | Description | Format |
|--------|-------------|--------|
| ZoneFiles.io | Compromised domains database | Plain domains |
| RomainMarcoux | Curated malicious domains list | Plain domains (includes IDN) |
| Botvrij.eu | IoC domain indicators | Plain domains |
| OpenPhish | Phishing URLs feed | Full URLs (domains extracted) |
| Disconnect.me | Malvertising domains | Plain domains with header |

### Domain Parsing

The tool intelligently parses different feed formats:
- **Plain domain lists**: Direct domain extraction
- **URL feeds**: Extracts domains from full URLs (e.g., OpenPhish)
- **Commented lists**: Skips lines starting with `#`
- **International domains**: Supports punycode (xn--) domains
- **Normalization**: Removes `www.` prefixes for consistency

### Sampling Methodology

To ensure efficient testing while maintaining statistical validity:
- Downloads all available threat feeds
- Collects all unique domains across all sources
- Uses shuffle algorithm for unbiased random selection (Fisher-Yates)
- Tests 3000 domains as a representative sample
- If fewer than 3000 domains are available, tests all domains

### DNS Resolution Reliability

To ensure accurate results and eliminate false positives:
- **Retry Logic**: Each DNS query is attempted up to 3 times before marking as blocked
- **Exponential Backoff**: Retries use increasing delays (100ms, 200ms, 300ms) to handle transient failures
- **Batch Processing**: Domains are tested in batches of 100 (or 2x MaxThreads) to prevent overwhelming DNS servers
- **Progress Tracking**: Real-time feedback shows completion status for each batch
- **Error Handling**: Detailed error messages help identify specific resolution failures

## How DNS Blocking Works

The tool tests three types of DNS security responses:

1. **Direct Blocking**: DNS resolution fails completely (NXDOMAIN or timeout)
2. **Sinkholing**: Domains resolve to known sinkhole IPs (e.g., OpenDNS, ISP sinkholes)
3. **Allowed**: Domains resolve to actual IPs (potential security risk)

### Known Sinkhole Detection

The tool recognizes sinkhole IPs from major security vendors and organizations:

**Security Vendors:**
- Cisco OpenDNS/Umbrella: 146.112.61.104-110
- Palo Alto Networks: 72.5.65.111 (old), 198.135.184.22 (new)
- Microsoft: 131.253.18.11-12, 199.2.137.0/24, 207.46.90.0/24
- Kaspersky: 93.159.228.22, 95.211.172.143

**Security Research:**
- Team Cymru: 38.102.150.29, 38.229.70.125 (Conficker sinkholes)
- Spamhaus: Multiple IPs for various threats
- SIDN Labs, sinkhole.DK, and other research organizations

**ISPs & Cloud Providers:**
- AT&T: 8.7.198.45
- Amazon: 54.244.112.0/24

**Law Enforcement:**
- FBI: 104.244.12.0/22

**Common Sinkholes:**
- Null routes: 0.0.0.0, 127.0.0.1, ::1
- Private IPs: 10.255.255.1, 192.168.255.254

## Expected Outcomes

### Good DNS Security
- **95%+ Effective Block Rate**: Most malicious domains are blocked or sinkholed
- **Minimal Resolved Domains**: Very few malicious domains resolve successfully

### Poor DNS Security
- **<90% Effective Block Rate**: Many malicious domains are not blocked
- **High Resolution Rate**: Significant number of threats can be accessed

## Security Note

This tool is designed for defensive security testing only. It helps organizations:
- Validate DNS security controls
- Identify gaps in threat coverage
- Demonstrate compliance with security policies
- Test incident response procedures

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.