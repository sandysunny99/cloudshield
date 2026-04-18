# CloudShield Local Demo Stack Runner
# Fix: Ensure all strings are terminated and spaces in paths are handled

$BackendDir = "backend"
$AgentDir = "agent"

Write-Host "=========================================" -ForegroundColor Green
Write-Host "   CloudShield -- Local Demo Launcher     " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# Start Backend in a new window
Write-Host "[*] Launching Backend on http://localhost:5000..." -ForegroundColor Yellow
$BackendCmd = "cd '$BackendDir'; `$env:AGENT_KEYS='default-agent-key-123'; python app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $BackendCmd

# Wait for backend to warm up
Write-Host "[*] Waiting 5 seconds for backend to initialize..." -ForegroundColor Yellow
Start-Sleep -s 5

# Start Agent in a new window
Write-Host "[*] Launching EDR Agent..." -ForegroundColor Yellow
$AgentCmd = "cd '$AgentDir'; `$env:CLOUDSHIELD_API_KEY='default-agent-key-123'; `$env:CLOUDSHIELD_API_URL='http://localhost:5000/api/agent-scan'; python agent.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $AgentCmd

Write-Host "[+] Dashboard available at: http://localhost:5000" -ForegroundColor Green
Write-Host "[+] Local Agent is now reporting telemetry." -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
