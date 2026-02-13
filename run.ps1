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
        $env:GITHUB_TOKEN = Normalize-GitHubToken $env:GITHUB_TOKEN
        return
    }

    $savedToken = [Environment]::GetEnvironmentVariable("GITHUB_TOKEN", "User")
    if (-not [string]::IsNullOrWhiteSpace($savedToken)) {
        $env:GITHUB_TOKEN = Normalize-GitHubToken $savedToken
        Write-Host "[Runner] Loaded GitHub token from user environment."
        return
    }

    Write-Host "[Runner] No GitHub token found. CVE fetching may be rate-limited."
    $enteredTokenSecure = Read-Host "Enter GitHub token (or press Enter to continue without one)" -AsSecureString
    $enteredTokenPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($enteredTokenSecure)
    $enteredToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($enteredTokenPtr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($enteredTokenPtr)

    if ([string]::IsNullOrWhiteSpace($enteredToken)) {
        Write-Host "[Runner] Continuing without token."
        return
    }

    $normalized = Normalize-GitHubToken $enteredToken
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        Write-Host "[Runner] Token input was not recognized. Continuing without token."
        return
    }

    $env:GITHUB_TOKEN = $normalized
    $suffix = if ($normalized.Length -ge 4) { $normalized.Substring($normalized.Length - 4) } else { $normalized }
    Write-Host "[Runner] Token captured (length: $($normalized.Length), ends with: $suffix)."
    $saveChoice = Read-Host "Save token for future runs in user environment? (y/N)"
    if ($saveChoice -match '^[Yy]$') {
        [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", $env:GITHUB_TOKEN, "User")
        Write-Host "[Runner] Token saved to user environment."
    } else {
        Write-Host "[Runner] Token set for this run only."
    }
}

function Normalize-GitHubToken {
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return ""
    }

    $clean = $Token.Replace([char]27 + "[200~", "").Replace([char]27 + "[201~", "")
    $clean = $clean.Trim()
    $clean = $clean -replace "^[~\s]*200~", ""
    $clean = $clean -replace "201~[~\s]*$", ""
    $clean = $clean -replace "[\r\n\t ]+", ""

    $patterns = @(
        "(github_pat_[A-Za-z0-9_]+)",
        "(gh[pousr]_[A-Za-z0-9]+)"
    )
    foreach ($pattern in $patterns) {
        $match = [regex]::Match($clean, $pattern)
        if ($match.Success) {
            return $match.Groups[1].Value
        }
    }

    return $clean
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
