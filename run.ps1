param(
    [ValidateSet("main", "cve", "news", "check")]
    [string]$Mode = "main"
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param([string]$Description, [scriptblock]$Action)

    Write-Host "[Runner] $Description..."
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Description"
    }
}

function Ensure-GitHubToken {
    param([string]$Mode)

    if ($Mode -notin @("main", "cve")) {
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
        return
    }

    $savedToken = [Environment]::GetEnvironmentVariable("GITHUB_TOKEN", "User")
    if (-not [string]::IsNullOrWhiteSpace($savedToken)) {
        $env:GITHUB_TOKEN = $savedToken
        Write-Host "[Runner] Loaded GitHub token from user environment."
        return
    }

    Write-Host "[Runner] No GitHub token found. CVE fetching may be rate-limited."
    $enteredTokenSecure = Read-Host "Enter GitHub token (or press Enter to continue without one)" -AsSecureString
    $enteredTokenPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($enteredTokenSecure)
    $enteredToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($enteredTokenPtr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($enteredTokenPtr)

    if ([string]::IsNullOrWhiteSpace($enteredToken)) {
        Write-Host "[Runner] Continuing without token."
        return
    }

    $env:GITHUB_TOKEN = $enteredToken.Trim()
    $saveChoice = Read-Host "Save token for future runs in user environment? (y/N)"
    if ($saveChoice -match '^[Yy]$') {
        [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", $env:GITHUB_TOKEN, "User")
        Write-Host "[Runner] Token saved to user environment."
    } else {
        Write-Host "[Runner] Token set for this run only."
    }
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$requirementsPath = Join-Path $repoRoot "requirements.txt"
$requirementsStampPath = Join-Path $venvPath ".requirements.sha256"

Ensure-GitHubToken -Mode $Mode

$venvCreated = $false
if (-not (Test-Path $venvPython)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        Invoke-Step "Creating virtual environment with py" { py -3 -m venv $venvPath }
    } else {
        Invoke-Step "Creating virtual environment with python" { python -m venv $venvPath }
    }
    $venvCreated = $true
}

$requirementsHash = (Get-FileHash -Path $requirementsPath -Algorithm SHA256).Hash
$storedHash = ""
if (Test-Path $requirementsStampPath) {
    $storedHash = (Get-Content $requirementsStampPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
}
$requirementsChanged = ($requirementsHash -ne $storedHash)

if ($venvCreated -or $requirementsChanged) {
    Invoke-Step "Upgrading pip" { & $venvPython -m pip install --upgrade pip }
    Invoke-Step "Installing dependencies" { & $venvPython -m pip install -r $requirementsPath }
    Set-Content -Path $requirementsStampPath -Value $requirementsHash -Encoding UTF8
} else {
    Write-Host "[Runner] Requirements unchanged. Skipping dependency install."
}

$scriptMap = @{
    "main"  = "main.py"
    "cve"   = "cve_scraper.py"
    "news"  = "news_scraper.py"
    "check" = "check_data.py"
}

$scriptToRun = Join-Path $repoRoot $scriptMap[$Mode]
Invoke-Step "Running $($scriptMap[$Mode])" { & $venvPython $scriptToRun }
