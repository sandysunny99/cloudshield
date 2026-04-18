$env:CLOUDSHIELD_API_KEY = "default-agent-key-123"
$env:CLOUDSHIELD_API_URL = "http://localhost:5000/api/agent-scan"
Write-Host "[*] Starting CloudShield Agent in Local Mode..." -ForegroundColor Cyan
python agent.py
