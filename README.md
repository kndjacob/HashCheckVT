# HashCheckVT

## Overview
HashCheckVT is a PowerShell script designed to hash files locally and submit the hashes to VirusTotal's API to check if the files are known to be malicious. The script calculates the MD5 hash of each file in the specified directory, sends the hash to VirusTotal, and reports the results.

## Features
- Hashes files using the MD5 algorithm.
- Submits the hashes to VirusTotal for analysis.
- Displays whether each file is flagged as malicious or clean based on VirusTotal's results.
- Supports easy configuration and use.

## Prerequisites
- PowerShell 5.0 or later.
- An active VirusTotal API key. Sign up for an account on VirusTotal to obtain an API key.

## Setup
1. Clone or download the script to your local machine.
2. Open the script file in a text editor.
3. Replace the `""` in `$apiKey = ""` with your VirusTotal API key.

## Usage
1. Open PowerShell with administrative privileges.
2. Navigate to the directory where the script is located.
3. Run the script using the command:
   ```powershell
   .\HashCheckVT.ps1
