param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$OutDir = "",
    [switch]$IncludePo,
    [switch]$IncludePot
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $ProjectRoot "dist"
}

$pluginSlug = Split-Path $ProjectRoot -Leaf
$stageRoot = Join-Path $OutDir $pluginSlug

if (Test-Path $stageRoot) {
    Remove-Item -Path $stageRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

$includeItems = @(
    "nexifymy-security.php",
    "uninstall.php",
    "includes",
    "modules",
    "assets",
    "languages"
)

foreach ($item in $includeItems) {
    $src = Join-Path $ProjectRoot $item
    if (-not (Test-Path $src)) {
        throw "Required item not found: $src"
    }
    Copy-Item -Path $src -Destination $stageRoot -Recurse -Force
}

$langDir = Join-Path $stageRoot "languages"
if (Test-Path $langDir) {
    if (-not $IncludePo) {
        Get-ChildItem -Path $langDir -Filter "*.po" -File -Recurse | Remove-Item -Force
    }
    if (-not $IncludePot) {
        Get-ChildItem -Path $langDir -Filter "*.pot" -File -Recurse | Remove-Item -Force
    }
}

$mainFile = Join-Path $ProjectRoot "nexifymy-security.php"
$version = "dev"
$versionMatch = Select-String -Path $mainFile -Pattern "^\s*\*\s*Version:\s*(.+)$" | Select-Object -First 1
if ($versionMatch) {
    $version = $versionMatch.Matches[0].Groups[1].Value.Trim()
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$zipName = "$pluginSlug-v$version.zip"
$zipPath = Join-Path $OutDir $zipName

if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

# Build ZIP entries with forward slashes so WordPress extraction works reliably on Linux hosts.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $basePath = Split-Path -Path $stageRoot -Parent
    Get-ChildItem -Path $stageRoot -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($basePath.Length).TrimStart('\', '/')
        $entryName = $relativePath -replace '\\', '/'
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip,
            $_.FullName,
            $entryName,
            [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
    }
}
finally {
    $zip.Dispose()
}

Write-Host "Package created: $zipPath"
Write-Host "Included: $($includeItems -join ', ')"
if ($IncludePo) {
    Write-Host "Included language source: .po"
} else {
    Write-Host "Excluded language source: .po"
}
if ($IncludePot) {
    Write-Host "Included language template: .pot"
} else {
    Write-Host "Excluded language template: .pot"
}
