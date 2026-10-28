<#
.SYNOPSIS
    Builds and launches Upuaut — Opener of the Ways.

.DESCRIPTION
    Compiles the Upuaut solution and starts the desktop application.
    Runs with Administrator privileges by default (via UAC prompt) to enable full
    access to the Security event log, raw sockets, and kernel ETW trace sessions.

.PARAMETER Configuration
    Build configuration: 'Debug' (default) or 'Release'.

.PARAMETER Clean
    Performs a clean build before launching.

.PARAMETER NoBuild
    Skips compilation and launches the existing binary directly.

.PARAMETER NoElevate
    Skips the Administrator UAC elevation prompt and runs with standard user rights.

.PARAMETER Wait
    Blocks the PowerShell terminal until the application exits.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Configuration Release
    .\run.ps1 -NoBuild
    .\run.ps1 -NoElevate
    .\run.ps1 -Wait
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [switch]$Clean,

    [switch]$NoBuild,

    [switch]$NoElevate,

    [switch]$Wait
)

$ErrorActionPreference = "Stop"

# Auto-elevate to Administrator by default unless -NoElevate is explicitly passed
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    Write-Host "[*] Requesting Administrator privileges via UAC prompt..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    $params = @("-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"", "-Configuration", $Configuration)
    if ($Clean) { $params += "-Clean" }
    if ($NoBuild) { $params += "-NoBuild" }
    if ($Wait) { $params += "-Wait" }
    
    try {
        Start-Process powershell.exe -ArgumentList $params -Verb RunAs
        exit
    }
    catch {
        Write-Host "[!] UAC elevation was declined. Continuing with standard user privileges..." -ForegroundColor Yellow
        Write-Host ""
    }
}

# Upuaut Banner
Clear-Host
Write-Host ""
Write-Host "   ===================================================================" -ForegroundColor DarkYellow
Write-Host "     [UPUAUT] (WEPWAWET)  -  Opener of the Ways" -ForegroundColor Yellow
Write-Host "         Windows System Triage & Network Diagnostic Console" -ForegroundColor Cyan
Write-Host "   ===================================================================" -ForegroundColor DarkYellow
Write-Host ""

if ($isAdmin) {
    Write-Host "   [+] Privilege: ADMINISTRATOR (Full access: Security Log + Kernel ETW enabled)" -ForegroundColor Green
} else {
    Write-Host "   [!] Privilege: STANDARD USER (Some channels like 'Security' may require elevation)" -ForegroundColor DarkYellow
}

Write-Host "   [i] Runtime: .NET 10 LTS" -ForegroundColor Gray
Write-Host "   [i] Configuration: $Configuration" -ForegroundColor Gray
Write-Host ""

$solutionRoot = $PSScriptRoot
$appProjectPath = Join-Path $solutionRoot "src\Upuaut.App\Upuaut.App.csproj"

# Clean if requested
if ($Clean) {
    Write-Host "[*] Cleaning solution..." -ForegroundColor Yellow
    $slnPath = Join-Path $solutionRoot "Upuaut.slnx"
    if (-not (Test-Path $slnPath)) { $slnPath = Join-Path $solutionRoot "Upuaut.sln" }
    dotnet clean $slnPath -c $Configuration --nologo -v quiet
}

# Build unless -NoBuild specified
if (-not $NoBuild) {
    Write-Host "[*] Compiling Upuaut ($Configuration)..." -ForegroundColor Cyan
    $buildStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    $buildResult = dotnet build $appProjectPath -c $Configuration --nologo
    $buildStopwatch.Stop()

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[X] Build failed with exit code $LASTEXITCODE." -ForegroundColor Red
        exit $LASTEXITCODE
    }

    $elapsedSec = $buildStopwatch.Elapsed.TotalSeconds.ToString("0.00")
    Write-Host "[+] Build succeeded in ${elapsedSec}s" -ForegroundColor Green
    Write-Host ""
}

# Find target executable dynamically
$binDir = Join-Path $solutionRoot "src\Upuaut.App\bin\$Configuration"
$targetExe = Get-ChildItem -Path $binDir -Filter "Upuaut.App.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

# Verify binary exists
if (-not $targetExe -or -not (Test-Path $targetExe)) {
    Write-Host "[X] Target executable not found under: $binDir" -ForegroundColor Red
    Write-Host "    Run without -NoBuild to compile the project first." -ForegroundColor Yellow
    exit 1
}

# Launch the desktop host
Write-Host "[*] Launching Upuaut Desktop Host..." -ForegroundColor Yellow
$appDir = Split-Path -Parent $targetExe
$proc = Start-Process -FilePath $targetExe -WorkingDirectory $appDir -PassThru

# Health check: verify process didn't instantly exit/crash on startup
Start-Sleep -Milliseconds 1200
$proc.Refresh()

if ($proc.HasExited) {
    Write-Host ""
    Write-Host "[X] Upuaut exited immediately with exit code: $($proc.ExitCode)" -ForegroundColor Red
    $crashDir = Join-Path $env:LOCALAPPDATA "Upuaut\Crashes"
    $logDir = Join-Path $env:LOCALAPPDATA "Upuaut\Logs"
    Write-Host "    Check diagnostic logs at: $logDir" -ForegroundColor Yellow
    Write-Host "    Check crash dumps at:     $crashDir" -ForegroundColor Yellow
    exit $proc.ExitCode
}

Write-Host "[+] Upuaut is active (PID: $($proc.Id))." -ForegroundColor Green
Write-Host "    Window is active on desktop." -ForegroundColor Cyan
Write-Host "    Diagnostic logs: $env:LOCALAPPDATA\Upuaut\Logs" -ForegroundColor Gray
Write-Host ""

if ($Wait) {
    Write-Host "[*] Attached to process. Waiting for exit (Ctrl+C to detach)..." -ForegroundColor Yellow
    $proc.WaitForExit()
    Write-Host "[i] Upuaut exited with code: $($proc.ExitCode)" -ForegroundColor Gray
}
