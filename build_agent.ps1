# CloudShield Agent Build & Deploy Script
# Automates the creation of the standalone EDR binary

$BackendStaticDir = "backend/static"
$AgentDir = "agent"
$AgentSpec = "cloudshield-agent.spec"
$FinalBinary = "cloudshield-agent.exe"

Write-Host "=========================================" -ForegroundColor Green
Write-Host "   CloudShield -- Agent Build Tool        " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# 1. Ensure Backend Static Directory Exists
if (-not (Test-Path $BackendStaticDir)) {
    Write-Host "[*] Creating $BackendStaticDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $BackendStaticDir | Out-Null
}

# 2. Check for PyInstaller
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "[!] PyInstaller not found. Installing..." -ForegroundColor Yellow
    pip install pyinstaller
}

# 3. Build the Agent
Write-Host "[*] Building agent with PyInstaller..." -ForegroundColor Yellow
cd $AgentDir
if (Test-Path $AgentSpec) {
    pyinstaller --noconfirm $AgentSpec
} else {
    pyinstaller --noconfirm --onefile --windowed --name cloudshield-agent agent.py
}

# 4. Deploy to Backend
Write-Host "[*] Deploying binary to backend..." -ForegroundColor Yellow
$BuiltBinary = "dist/$FinalBinary"
if (Test-Path $BuiltBinary) {
    Copy-Item $BuiltBinary "../$BackendStaticDir/$FinalBinary" -Force
    Write-Host "[+] SUCCESS: Agent deployed to $BackendStaticDir/$FinalBinary" -ForegroundColor Green
} else {
    Write-Host "[-] ERROR: Build failed. Binary not found at $BuiltBinary" -ForegroundColor Red
    exit 1
}

cd ..
Write-Host "=========================================" -ForegroundColor Green
