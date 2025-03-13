# NexScout

# Network Connection & Virus Scanner

## Overview
This Go application scans active network connections, retrieves the associated process ID (PID), and fetches information about the remote IP address. It can also scan the executable file of a selected process using **VirusTotal** API.

## Features
- Lists active TCP connections and their corresponding process IDs (PIDs).
- Retrieves geographical location data for remote IPs using **IPInfo** API.
- Extracts file path of a process using **PowerShell**.
- Uploads the file to **VirusTotal** for a malware scan and fetches the report.

## Prerequisites
### 1. Install Go
Ensure you have **Go** installed. You can download it from [golang.org](https://go.dev/dl/).
```sh
# Check if Go is installed
 go version
```

### 2. API Keys
You'll need API keys for:
- **VirusTotal**: Get your API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
- **IPInfo**: Sign up at [IPInfo](https://ipinfo.io/) and get a token.

Add them to the `VirusTotalAPIKey` and `IPInfoToken` constants in `main.go`.

## Installation
Clone the repository and install dependencies:
```sh
git clone https://github.com/yourusername/network-virus-scanner.git
cd network-virus-scanner
go mod tidy
```

## Running the Program
```sh
go run main.go
```

## Usage
1. The program will list active TCP connections and their associated process IDs.
2. Enter a **PID** to scan.
3. The program will:
   - Retrieve the file path of the process.
   - Upload the file to **VirusTotal**.
   - Wait for results and display the malware scan report.

## Dependencies
This project uses:
- **resty** (HTTP client): `github.com/go-resty/resty/v2`

Install dependencies using:
```sh
go get github.com/go-resty/resty/v2
```

## Disclaimer
- Use this tool responsibly.
- Ensure you have permission before scanning a file or network connection.
