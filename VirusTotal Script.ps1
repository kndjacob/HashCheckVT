function Submit-HashToVirusTotal {
    param ([string]$Hash)

    try {
        $apiKey = "" #API Key Here.
        $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$Hash"
        $result = Invoke-RestMethod -Uri $url -Method Get
        return $result.response_code, $result.positives
    } catch {
        Write-Host "Error submitting hash to VirusTotal: $_"
        return $null, $null
    }
}

$DownloadsDirectory = "C:\Users\$Env:UserName\Downloads"

Clear-Host

$files = Get-ChildItem $DownloadsDirectory
foreach ($file in $files) {
    $hash = Get-FileHash -Path $file.FullName -Algorithm "MD5"
    if ($null -ne $hash) {
        $statusCode, $positives = Submit-HashToVirusTotal -Hash $hash
        if ($null -ne $statusCode) {
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
