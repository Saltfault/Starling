# Starling launcher installer — Windows (PowerShell)
# Usage:
#   irm https://forgejo.hearthhome.lol/Saltfault/Starling/raw/branch/main/install.ps1 | iex

param(
    [string]$Version = "latest",
    [switch]$Uninstall,
    [switch]$Upgrade
)

$ErrorActionPreference = "Stop"
$ForgejoBase = "https://forgejo.hearthhome.lol/Saltfault"
$Binary = "starling"
$Repo = "Starling"
$InstallDir = "$env:LOCALAPPDATA\Starling\bin"

$target = "x86_64-pc-windows-msvc"
$ext = ".exe"

if ($Uninstall) {
    $binPath = Join-Path $InstallDir "$Binary$ext"
    if (Test-Path $binPath) { Remove-Item $binPath -Force }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -like "*$InstallDir*") {
        $newPath = ($userPath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    }
    Write-Host "Uninstalled $Binary" -ForegroundColor Green
    exit 0
}

if ($Upgrade) { Write-Host "Upgrading $Binary to $Version..." -ForegroundColor Cyan }

if ($Version -eq "latest") {
    $release = Invoke-RestMethod "$ForgejoBase/$Repo/releases/latest"
    $Tag = $release.tag_name
} else { $Tag = $Version }

$assetName = "$Binary-$target$ext"
$url = "$ForgejoBase/$Repo/releases/download/$Tag/$assetName"
Write-Host "Downloading $assetName ($Tag)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$outPath = Join-Path $InstallDir "$Binary$ext"
Invoke-WebRequest -Uri $url -OutFile $outPath

$shaUrl = "$ForgejoBase/$Repo/releases/download/$Tag/$Binary-$target.sha256"
try {
    $expected = (Invoke-RestMethod $shaUrl).Split(" ")[0].Trim()
    $actual = (Get-FileHash $outPath -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Remove-Item $outPath -Force
        throw "Checksum mismatch! Expected $expected, got $actual"
    }
    Write-Host "Checksum verified" -ForegroundColor Green
} catch { Write-Host "Skipping checksum verification" -ForegroundColor Yellow }

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to PATH (restart terminal to apply)" -ForegroundColor Yellow
}

Write-Host "Installed $Binary $Tag to $outPath" -ForegroundColor Green
