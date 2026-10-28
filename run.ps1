<#
.SYNOPSIS
    Builds and launches Upuaut — Opener of the Ways.

.DESCRIPTION
    Compiles the Upuaut solution and starts the desktop application.
    Supports elevation to Administrator for inspecting the Security log and running ETW sessions.

.PARAMETER Configuration
    Build configuration: 'Debug' (default) or 'Release'.

.PARAMETER Clean
    Performs a clean build before launching.

.PARAMETER NoBuild
    Skips compilation and launches the existing binary directly.

.PARAMETER Elevated
    Relaunches this script with Administrator privileges via UAC prompt.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Configuration Release
    .\run.ps1 -Elevated
    .\run.ps1 -NoBuild
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [switch]$Clean,

    [switch]$NoBuild,

    [switch]$Elevated
)

$ErrorActionPreference = "Stop"

# Self-elevation if requested
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Elevated -and -not $isAdmin) {
    Write-Host "[*] Requesting Administrator elevation..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    $params = @("-File", "`"$scriptPath`"", "-Configuration", $Configuration)
    if ($Clean) { $params += "-Clean" }
    if ($NoBuild) { $params += "-NoBuild" }
    
    Start-Process powershell.exe -ArgumentList $params -Verb RunAs
    exit
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
    Write-Host "   [!] Privilege: STANDARD USER" -ForegroundColor DarkGray
    Write-Host "       (Tip: Pass -Elevated to unlock the Security log and real-time ETW capture)" -ForegroundColor DarkGray
}

Write-Host "   [i] Configuration: $Configuration" -ForegroundColor Gray
Write-Host ""

$solutionRoot = $PSScriptRoot
$appProjectPath = Join-Path $solutionRoot "src\Upuaut.App\Upuaut.App.csproj"

# Clean if requested
if ($Clean) {
    Write-Host "[*] Cleaning solution..." -ForegroundColor Yellow
    dotnet clean $solutionRoot -c $Configuration --nologo -v quiet
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
Start-Process -FilePath $targetExe -WorkingDirectory $appDir

Write-Host "[+] Upuaut is active." -ForegroundColor Green
Write-Host ""
