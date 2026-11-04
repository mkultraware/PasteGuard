# build.ps1 - Rebuild PasteGuard.exe and the Inno Setup installer.
#
# Usage:  .\build.ps1
# Output: dist\PasteGuard.exe
#         installer_output\SekuraPasteGuard_Setup_v2.0.exe
#
# To change the app icon, drop a new PNG in the repo as new-icon.png and
# re-run this script - it is converted to clipboard-x.512.ico automatically
# (only when the PNG is newer than the current .ico). The tray icon, the exe
# icon, and the installer icon all read from that one .ico file.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venv = Join-Path $root ".venv"
$py   = Join-Path $venv "Scripts\python.exe"

# --- 1. Virtual environment ---
if (-not (Test-Path $py)) {
    Write-Host "[1/5] Creating virtual environment..." -ForegroundColor Cyan
    python -m venv $venv
} else {
    Write-Host "[1/5] Virtual environment already present." -ForegroundColor Cyan
}

# --- 2. Dependencies ---
Write-Host "[2/5] Installing dependencies..." -ForegroundColor Cyan
& $py -m pip install --upgrade pip --quiet
& $py -m pip install -r requirements.txt pyinstaller --quiet
if ($LASTEXITCODE -ne 0) { throw "Dependency install failed." }

# --- 3. Icon: convert new-icon.png -> clipboard-x.512.ico if the PNG is newer ---
$png = Join-Path $root "new-icon.png"
$ico = Join-Path $root "clipboard-x.512.ico"
if ((Test-Path $png) -and (Test-Path $ico) -and ((Get-Item $png).LastWriteTime -gt (Get-Item $ico).LastWriteTime)) {
    Write-Host "[3/5] Converting new-icon.png -> clipboard-x.512.ico..." -ForegroundColor Cyan
    & $py -c @"
from PIL import Image
img = Image.open(r'$png').convert('RGBA')
sizes = [(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256),(512,512)]
try:
    img.save(r'$ico', sizes=sizes)
except Exception:
    img.save(r'$ico', sizes=[s for s in sizes if s[0] <= 256])
print('icon updated')
"@
    if ($LASTEXITCODE -ne 0) { throw "Icon conversion failed." }
} else {
    Write-Host "[3/5] Icon up to date (no newer new-icon.png)." -ForegroundColor Cyan
}

# --- 4. PyInstaller -> dist\PasteGuard.exe ---
Write-Host "[4/5] Building PasteGuard.exe..." -ForegroundColor Cyan
& $py -m PyInstaller `
    --noconfirm --clean `
    --onefile --noconsole `
    --name PasteGuard `
    --icon "clipboard-x.512.ico" `
    --add-data "clipboard-x.512.ico;." `
    clipboard_defanger.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
if (-not (Test-Path "dist\PasteGuard.exe")) { throw "dist\PasteGuard.exe was not produced." }

# --- 5. Inno Setup -> installer_output\*.exe ---
Write-Host "[5/5] Compiling installer..." -ForegroundColor Cyan
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    Write-Warning "Inno Setup (ISCC) not found - skipping the installer."
    Write-Host "  PasteGuard.exe is ready in dist\."
    Write-Host "  To build the installer, install Inno Setup then re-run:"
    Write-Host "      winget install JRSoftware.InnoSetup"
} else {
    & $iscc pasteguard_setup.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed." }
    Write-Host "Installer ready in installer_output\." -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Green
