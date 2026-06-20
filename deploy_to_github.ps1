# TDG Tracker - GitHub Deploy Script
# Run this once to create the repo and push all files

$TOKEN = "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"

$HEADERS = @{
    "Authorization"        = "Bearer $TOKEN"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "Content-Type"         = "application/json"
}

Write-Host "=== TDG Tracker - GitHub Deploy ===" -ForegroundColor Cyan

# 1. Get username
Write-Host "`nVerifying token..." -ForegroundColor Yellow
$user = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $HEADERS
$USERNAME = $user.login
Write-Host "Logged in as: $USERNAME" -ForegroundColor Green

# 2. Create repo
Write-Host "`nCreating repo 'tdg-tracker'..." -ForegroundColor Yellow
$repoBody = @{
    name        = "tdg-tracker"
    description = "TDG Daily Log - MBR Texas Field Operations"
    private     = $true
    auto_init   = $false
} | ConvertTo-Json

try {
    $repo = Invoke-RestMethod -Uri "https://api.github.com/user/repos" `
        -Method POST -Headers $HEADERS -Body $repoBody
    Write-Host "Repo created: $($repo.html_url)" -ForegroundColor Green
} catch {
    Write-Host "Repo already exists or error — continuing with file upload." -ForegroundColor Yellow
}

# 3. Upload files
$BASE = "C:\Users\magav\OneDrive\Desktop\TDG\Daily report\tdg-tracker"

$FILES = @(
    "app.py",
    "requirements.txt",
    "Procfile",
    "templates/index.html"
)

Write-Host "`nUploading files..." -ForegroundColor Yellow

foreach ($FILE in $FILES) {
    $FULL_PATH = Join-Path $BASE ($FILE -replace "/", "\")

    if (-not (Test-Path $FULL_PATH)) {
        Write-Host "  MISSING: $FILE — skipped" -ForegroundColor Red
        continue
    }

    $BYTES   = [System.IO.File]::ReadAllBytes($FULL_PATH)
    $B64     = [System.Convert]::ToBase64String($BYTES)
    $API_PATH = $FILE -replace "\\", "/"

    $BODY = @{
        message = "Add $API_PATH"
        content = $B64
    } | ConvertTo-Json

    $URI = "https://api.github.com/repos/$USERNAME/tdg-tracker/contents/$API_PATH"

    try {
        Invoke-RestMethod -Uri $URI -Method PUT -Headers $HEADERS -Body $BODY | Out-Null
        Write-Host "  OK: $FILE" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR on $FILE`: $_" -ForegroundColor Red
    }
}

Write-Host "`n=== Done! ===" -ForegroundColor Cyan
Write-Host "Repo URL : https://github.com/$USERNAME/tdg-tracker" -ForegroundColor White
Write-Host ""
Write-Host "Next step: go to render.com, connect this repo, and set env vars:" -ForegroundColor Yellow
Write-Host "  SUPABASE_URL = https://wanfpiogchwttsippekm.supabase.co" -ForegroundColor White
Write-Host "  SUPABASE_KEY = sb_publishable_iQ1LkfjN_qxBTNfTfa4MWA_LHEcZApJ" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to close"
