# CloudShield Local Demo Stack Runner
# Fixes: Handles spaces in paths, terminates strings correctly, and launches Frontend (Vite)

$BackendDir = "backend"
$AgentDir = "agent"
$FrontendDir = "frontend"

Write-Host "=========================================" -ForegroundColor Green
Write-Host "   CloudShield -- Local Demo Launcher     " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# 1. Start Backend in a new window
Write-Host "[*] Launching Backend on http://localhost:5000..." -ForegroundColor Yellow
$BackendCmd = "cd '$BackendDir'; `$env:AGENT_KEYS='default-agent-key-123'; python app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $BackendCmd

# 2. Start Frontend in a new window
Write-Host "[*] Launching Frontend (Vite) on http://localhost:5173..." -ForegroundColor Yellow
$FrontendCmd = "cd '$FrontendDir'; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $FrontendCmd

# Wait for services to warm up
Write-Host "[*] Waiting 7 seconds for services to initialize..." -ForegroundColor Yellow
Start-Sleep -s 7

# 3. Start Agent in a new window
Write-Host "[*] Launching EDR Agent..." -ForegroundColor Yellow
$AgentCmd = "cd '$AgentDir'; `$env:CLOUDSHIELD_API_KEY='default-agent-key-123'; `$env:CLOUDSHIELD_API_URL='http://localhost:5000/api/agent-scan'; python agent.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $AgentCmd

Write-Host "=========================================" -ForegroundColor Green
Write-Host "[+] API Backend: http://localhost:5000" -ForegroundColor Green
Write-Host "[+] DASHBOARD:   http://localhost:5173" -ForegroundColor Green
Write-Host "[+] Local Agent is now reporting telemetry." -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
