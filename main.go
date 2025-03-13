package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	VirusTotalAPIKey = ""
	IPInfoToken      = ""
)

type VirusTotalScanResponse struct {
	ScanID     string `json:"scan_id"`
	Resource   string `json:"resource"`
	Response   int    `json:"response_code"`
	VerboseMsg string `json:"verbose_msg"`
}

type VirusTotalReportResponse struct {
	ScanID    string `json:"scan_id"`
	Positives int    `json:"positives"`
	Total     int    `json:"total"`
	Scans     map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
	} `json:"scans"`
}

type IPInfoResponse struct {
	City        string `json:"city"`
	CountryName string `json:"country"`
}

func main() {
	fmt.Println("Fetching netstat output...")
	output, err := exec.Command("netstat", "-ano", "-n", "-p", "TCP").Output()
	if err != nil {
		fmt.Println("Error executing netstat:", err)
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	pids := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.Contains(line, "0.0.0.0") || strings.Contains(line, "127.0.0.1") {
			continue
		}
		remoteAddr := fields[2]
		pid := fields[4]
		if !pids[pid] {
			fmt.Printf("Process ID: %s | Remote Address: %s\n", pid, remoteAddr)
			locateIP(remoteAddr)
			pids[pid] = true
		}
	}

	fmt.Print("Enter Process ID to scan: ")
	var pid string
	fmt.Scan(&pid)

	filePath := getFilePathFromPID(pid)
	if filePath == "" {
		fmt.Println("File path not found for PID", pid)
		return
	}

	scanFile(filePath)
}

func locateIP(ip string) {
	cleanIP, _, err := net.SplitHostPort(ip)
	if err != nil {
		cleanIP = ip
	}
	resp, err := resty.New().R().SetAuthToken(IPInfoToken).Get("https://ipinfo.io/" + cleanIP + "/json")
	if err != nil {
		fmt.Println("IP lookup failed:", err)
		return
	}

	var ipInfo IPInfoResponse
	json.Unmarshal(resp.Body(), &ipInfo)
	fmt.Printf("Location: %s, %s\n", ipInfo.City, ipInfo.CountryName)
}

func getFilePathFromPID(pid string) string {
	cmd := exec.Command("powershell", "-Command", "(Get-Process -Id "+pid+").Path")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error fetching file path:", err)
		return ""
	}
	return strings.TrimSpace(string(output))
}

func scanFile(filePath string) {
	fmt.Println("Uploading", filePath, "to VirusTotal...")
	resp, err := resty.New().R().SetFile("file", filePath).SetFormData(map[string]string{
		"apikey": VirusTotalAPIKey,
	}).Post("https://www.virustotal.com/vtapi/v2/file/scan")
	if err != nil {
		fmt.Println("File scan failed:", err)
		return
	}

	var scanResp VirusTotalScanResponse
	json.Unmarshal(resp.Body(), &scanResp)
	fmt.Println("Scan started: ", scanResp.ScanID)
	time.Sleep(20 * time.Second)

	getFileScanReport(scanResp.Resource)
}

func getFileScanReport(resource string) {
	fmt.Println("Fetching scan report...")
	resp, err := resty.New().R().SetQueryParams(map[string]string{
		"apikey":   VirusTotalAPIKey,
		"resource": resource,
	}).Get("https://www.virustotal.com/vtapi/v2/file/report")
	if err != nil {
		fmt.Println("Scan report retrieval failed:", err)
		return
	}

	var report VirusTotalReportResponse
	json.Unmarshal(resp.Body(), &report)
	fmt.Printf("Scan completed: %s\nPositives: %d/%d\n", report.ScanID, report.Positives, report.Total)

	for scanner, info := range report.Scans {
		if info.Detected {
			fmt.Printf("%s -> %s\n", scanner, info.Result)
		}
	}
}
