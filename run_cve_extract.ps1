

$base = "C:\cves"   # Root folder
$out  = "C:\cves\output"               # Output folder
$script = "C:\cves\extract_cves_v2.py"    # Python path



$startYear = Read-Host "Enter start year"


if ($startYear -notmatch '^\d{4}$') {
    Write-Host "Invalid year"
    exit
}

$startYear = [int]$startYear



New-Item -ItemType Directory -Force -Path $out | Out-Null



$yearFolders = Get-ChildItem $base -Directory |
    Where-Object {
        $_.Name -match '^\d{4}$' -and [int]$_.Name -ge $startYear
    } |
    Sort-Object Name

if ($yearFolders.Count -eq 0) {
    Write-Host "No matching year folders found."
    exit
}



foreach ($folder in $yearFolders) {

    $year = $folder.Name
    $rootPath = Join-Path $base $year
    $outputFile = Join-Path $out "cve_$year.csv"

    Write-Host "=============================="
    Write-Host "Processing year $year"
    Write-Host "=============================="

    try {
        py $script `
            --root $rootPath `
            --out  $outputFile

        Write-Host "Finished year $year"
    }
    catch {
        Write-Warning "Failed processing year $year"
        Write-Warning $_.Exception.Message
    }
}

Write-Host ""
Write-Host "All requested years processed."
