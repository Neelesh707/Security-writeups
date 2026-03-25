# CTF Write-Up: ExifViewer (exifviewer.hv)

## Objective
Identify vulnerabilities in the ExifViewer web application, gain remote access, and extract sensitive information.

## Reconnaissance
- Enumerated directories using gobuster
- Found:
  - /assets (403 Forbidden)
  - /index.php
- Identified image upload functionality

## Vulnerability
- ExifTool v12.23
- Vulnerable to CVE-2021-22204 (RCE via image metadata)

## Exploitation
1. Generated malicious image payload
2. Uploaded via web application
3. Triggered metadata processing
4. Obtained reverse shell

Access:
