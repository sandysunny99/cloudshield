param(
    [Parameter(Mandatory=$false)]
    [string]$ApiKey = "default-agent-key-123"
)

# CloudShield Windows Service Automated Installer
# Must be executed as an elevated Administrator

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  CloudShield SaaS Service Deployer      " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Check for Administrator elevation
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "CRITICAL ERROR: This script requires Administrator privileges!"
    Write-Warning "Please right-click the script and select 'Run as Administrator'."
    Exit
}

$CurrentDir = Get-Location
$TargetDir = "C:\CloudShield"
$NssmDir = "C:\nssm"
$NssmExe = "$NssmDir\nssm.exe"

Write-Host "`n[STEP 1] VERIFYING PREREQUISITES & NSSM..." -ForegroundColor Yellow
if (!(Test-Path $NssmDir)) {
    New-Item -ItemType Directory -Path $NssmDir | Out-Null
}

if (!(Test-Path $NssmExe)) {
    Write-Host "[-] NSSM not found. Downloading from https://nssm.cc..."
    $nssmZip = "$env:TEMP\nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip
    Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm_extracted" -Force
    # Move the 64-bit exe to C:\nssm\nssm.exe
    Copy-Item "$env:TEMP\nssm_extracted\nssm-2.24\win64\nssm.exe" -Destination $NssmExe -Force
    Write-Host "[+] NSSM downloaded and installed to $NssmExe" -ForegroundColor Green
} else {
    Write-Host "[+] NSSM found at $NssmExe" -ForegroundColor Green
}

Write-Host "`n[STEP 2] CREATING INSTALL DIRECTORY..." -ForegroundColor Yellow
if (!(Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
    Write-Host "[+] Directory $TargetDir created." -ForegroundColor Green
}

# The agent should already be compiled in \dist\ by the pipeline.
if (Test-Path "$CurrentDir\dist\cloudshield-agent.exe") {
    Write-Host "[+] Artifact found. Copying executables..."
    Copy-Item "$CurrentDir\dist\cloudshield-agent.exe" -Destination "$TargetDir\cloudshield-agent.exe" -Force
    Write-Host "[+] Agent relocated to $TargetDir\cloudshield-agent.exe" -ForegroundColor Green
} else {
    Write-Warning "[-] Error: dist\cloudshield-agent.exe not found! Please compile the agent first:"
    Write-Warning "    pyinstaller --noconfirm --onefile --windowed --name cloudshield-agent agent/agent.py"
    Exit
}


Write-Host "`n[STEP 3] BINDING MACHINE-LEVEL ENVIRONMENT VARIABLES..." -ForegroundColor Yellow
$ApiUrl = "https://cloudshield-tya3.onrender.com/api/agent-scan"
Write-Host "Service will use ApiKey: $ApiKey and ApiUrl: $ApiUrl"
Write-Host "[+] Environment parameters ready for NSSM." -ForegroundColor Green


Write-Host "`n[STEP 4 & 5] INSTALLING AND CONFIGURING CLOUDSHIELD SERVICE..." -ForegroundColor Yellow
# If the service already exists, stop and remove it cleanly for update
$serviceStatus = Get-Service -Name "CloudShieldAgent" -ErrorAction SilentlyContinue
if ($serviceStatus) {
    Write-Host "[*] Service exists, replacing..."
    Stop-Service "CloudShieldAgent" -Force -ErrorAction SilentlyContinue
    & $NssmExe remove CloudShieldAgent confirm
    Start-Sleep -Seconds 2
}

& $NssmExe install CloudShieldAgent "$TargetDir\cloudshield-agent.exe"
& $NssmExe set CloudShieldAgent AppDirectory "$TargetDir"
& $NssmExe set CloudShieldAgent AppStdout "$TargetDir\agent.log"
& $NssmExe set CloudShieldAgent AppStderr "$TargetDir\agent-error.log"
& $NssmExe set CloudShieldAgent AppRestartDelay 5000
& $NssmExe set CloudShieldAgent Start SERVICE_AUTO_START

& $NssmExe set CloudShieldAgent AppEnvironmentExtra "CLOUDSHIELD_API_KEY=$ApiKey" "CLOUDSHIELD_API_URL=$ApiUrl"

Write-Host "[+] NSSM Service Daemon successfully registered!" -ForegroundColor Green


Write-Host "`n[STEP 6] STARTING SERVICE..." -ForegroundColor Yellow
& $NssmExe start CloudShieldAgent
Start-Sleep -Seconds 2
$finalCheck = (sc.exe query CloudShieldAgent | findstr STATE)
Write-Host "[+] $finalCheck" -ForegroundColor Green

Write-Host "`n=======================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] CloudShield Endpoint Agent is Active!" -ForegroundColor Cyan
Write-Host ""
Write-Host "VERIFICATION STEPS:"
Write-Host "1. Check logs at: C:\CloudShield\agent.log"
Write-Host "2. See agent online: curl https://cloudshield-tya3.onrender.com/api/agent-status"
Write-Host "3. If issues arise, monitor C:\CloudShield\agent-error.log"
Write-Host "=======================================================" -ForegroundColor Cyan
