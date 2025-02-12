# VT_API

VT_API is a Rust command-line tool that interacts with the [VirusTotal API](https://www.virustotal.com/) to analyze URLs, domains, IPs, and files. It generates either full reports or summaries of the analysis results.

## Features

- **URL Analysis**: Generates a report for a given URL.
- **Domain & IP Resolution**: Fetches a report for a domain or an IP address.
- **File Scanning**: Analyzes files, including those larger than 32 MB.

## Installation

Ensure you have Rust installed. You can install Rust using [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then, clone the repository and build the project:

```sh
git clone https://github.com/mathieuemery/vt_api.git
cd vt_api
cargo build --release
```

### Installing cURL

cURL is required for interacting with the VirusTotal API. Install it using the following commands:

On Linux (Debian/Ubuntu-based):

```sh
sudo apt update && sudo apt install curl
```

On macOS:

```sh
brew install curl
```

## Usage

Before using the tool, set your VirusTotal API key as an environment variable:

### Setting the API Key

On Linux and macOS:

```sh
export VT_API_KEY="your_api_key_here"
```

On Windows (PowerShell):

```powershell
$env:VT_API_KEY="your_api_key_here"
```

On Windows (Command Prompt):

```cmd
set VT_API_KEY=your_api_key_here
```

Run the tool with the following commands:

### Scan a URL

```sh
cargo run url https://www.example.com
```
Would give the following result:

```sh
{
  "categories": {
    "alphaMountain.ai": "Information Technology (alphaMountain.ai)",
    "Forcepoint ThreatSeeker": "information technology",
    "Sophos": "information technology",
    "BitDefender": "computersandsoftware",
    "Xcitium Verdict Cloud": "content server"
  },
  "harmless_count": 70,
  "undetected_count": 26,
  "unrated_count": 0,
  "suspicious_count": 0,
  "malicious_count": 0,
  "first_submission_date": 1327695701,
  "last_analysis_date": 1739392419,
  "last_http_response_code": "Success (200)",
  "reputation": 5,
  "times_submitted": 2701,
  "tld": "com",
  "title": "Example Domain"
}
```

### Scan a Domain

```sh
cargo run domain example.com
```
Would give the following result:

```sh
{
  "choice": "domain",
  "domain": {
    "domain": "example.com",
    "categories": {},
    "last_analysis_date": 1739385308
  },
  "analysis_stats": {
    "harmless": 65,
    "malicious": 0,
    "suspicious": 0,
    "timeout": 0,
    "undetected": 29
  },
  "dns_records": {
    "a_records": [
      "23.215.0.136",
      "96.7.128.175",
      "96.7.128.198",
      "23.192.228.80",
      "23.192.228.84",
      "23.215.0.138"
    ],
    "mx_records": [
      ""
    ],
    "ns_records": [
      "a.iana-servers.net",
      "b.iana-servers.net"
    ],
    "txt_records": [
      "v=spf1 -all",
      "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"
    ],
    "soa_records": [
      "ns.icann.org"
    ]
  },
  "ssl_certificate": {
    "issuer": "DigiCert Global G3 TLS ECC SHA384 2020 CA1",
    "validity_start": "2025-01-15 00:00:00",
    "validity_end": "2026-01-15 23:59:59",
    "key_type": "EC",
    "key_size": 0,
    "alternative_names": []
  }
}

```

### Scan an IP Address

```sh
cargo run domain 8.8.8.8
```
Would give the following result:

```sh
{
    "choice":"ip",
    "ip_details": {
        "ip_address":"8.8.8.8",
        "owner":"GOOGLE",
        "country":"US",
        "continent":"NA"
    },
    "threat_analysis": {
        "total_votes":{
            "harmless":63,
            "malicious":0,
            "suspicious":0,
            "timeout":0,
            "undetected":31
        },
        "crowdsourced_threats":[{
            "details":"AsyncRAT botnet C2 server (confidence level: 100%)","severity":"medium","source":"ArcSight Threat Intelligence"
        }],
        "reputation_score":545
    },
    "network_info": {
        "network_range":"8.8.8.0/24",
        "registry":"ARIN",
        "abuse_contact":"OrgAbuseEmail: network-abuse@google.com"
    },
    "certificate_info":{
        "validity_period":"2025-01-20 08:37:58 to 2025-04-14 08:37:57",
        "issuer":"Google Trust Services",
        "alternative_names":[
            "dns.google",
            "dns.google.com",
            "*.dns.google.com",
            "8888.google",
            "dns64.dns.google",
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
            "2001:4860:4860::6464",
            "2001:4860:4860::64"
        ]
    }
}
```

### Scan a file
This part hasn't been finished yet.

## License

This project is licensed under the MIT License.

## Contributing

Pull requests are welcome! Please open an issue first to discuss what you would like to change.

## Disclaimer

This tool relies on VirusTotal and requires a valid API key. Make sure to comply with VirusTotal's terms of service when using this tool.