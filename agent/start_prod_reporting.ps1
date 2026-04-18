# CloudShield Agent - Production Reporting Script
# Use this to report telemetry to your live Vercel/Render dashboard

$env:CLOUDSHIELD_API_URL = "https://cloudshield-tya3.onrender.com/api/agent-scan"
$env:CLOUDSHIELD_API_KEY = "default-agent-key-123"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   CloudShield -- Production Reporting   " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[*] Target Dashboard: https://cloudshield-vtah.vercel.app" -ForegroundColor Yellow
Write-Host "[*] Target Backend:   https://cloudshield-tya3.onrender.com" -ForegroundColor Yellow
Write-Host "[*] Using API Key:    $env:CLOUDSHIELD_API_KEY" -ForegroundColor Yellow
Write-Host "-----------------------------------------" -ForegroundColor Gray
Write-Host "[*] Launching Agent..." -ForegroundColor Cyan

# Use absolute path detection to ensure it runs from any directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$ScriptDir\agent.py"
