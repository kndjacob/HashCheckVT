function Submit-HashToVirusTotal {
    param ([string]$Hash)

    try {
        $apiKey = ""#Write your API Key Here - To get one just sign up for an account with VirusTotal!
        $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$Hash"
        $result = Invoke-RestMethod -Uri $url -Method Get
        return $result.response_code, $result.positives
    } catch {
        Write-Host "Error submitting hash to VirusTotal: $_"
        return $null, $null
    }
}

$DownloadsDirectory = "C:\Users\$Env:UserName\Downloads"

cls

$files = Get-ChildItem $DownloadsDirectory
foreach ($file in $files) {
    $hash = Get-FileChecksum -FilePath $file.FullName -Algorithm "MD5"
    if ($hash -ne $null) {
        $statusCode, $positives = Submit-HashToVirusTotal -Hash $hash
        if ($statusCode -ne $null) {
            if ($statusCode -eq 1 -and $positives -gt 0) {
                Write-Host ("$($file.Name) MD5($hash): MALICIOUS - flagged by $($positives) antivirus engines.") -ForegroundColor Red
            }
            else {
                Write-Host ("$($file.Name) MD5($hash): CLEAN") -ForegroundColor Green
            }
        } 
        else {
            Write-Host "Error submitting $($file.Name) MD5($hash) to VirusTotal." -ForegroundColor Yellow
        }
        Start-Sleep -Seconds 15
    }
}
