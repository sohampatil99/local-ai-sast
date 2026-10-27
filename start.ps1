# Starts the dashboard and opens it in the browser. Usage: .\start.ps1 (or double-click start.bat)
Set-Location $PSScriptRoot
$url = "http://127.0.0.1:8000"

try {
    if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "The dashboard is already running. Opening $url" -ForegroundColor Green
        Start-Process $url
        Read-Host "Press Enter to close this window (the dashboard keeps running)"
        exit 0
    }
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        throw "Python environment not found at $PSScriptRoot\.venv. See README.md, Quick start."
    }
    if (-not (Get-Process ollama -ErrorAction SilentlyContinue)) {
        $ollama = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
        if (Test-Path $ollama) {
            Write-Host "Starting Ollama..."
            Start-Process $ollama -ArgumentList "serve" -WindowStyle Hidden
        } else {
            Write-Host "Ollama not found: scans will run without AI." -ForegroundColor Yellow
        }
    }
    Write-Host "Starting the dashboard at $url (keep this window open; Ctrl+C to stop)" -ForegroundColor Green
    Start-Job { Start-Sleep 3; Start-Process "http://127.0.0.1:8000" } | Out-Null
    & .\.venv\Scripts\python.exe backend\cli.py serve --port 8000
    if ($LASTEXITCODE -ne 0) { throw "The dashboard stopped with exit code $LASTEXITCODE (see the messages above)." }
} catch {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Read-Host "Press Enter to close"
}
