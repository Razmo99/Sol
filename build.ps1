param(
    [string]$SourcePath = (Join-Path -Path $PSScriptRoot -ChildPath 'Source'),
    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'output'),
    [switch]$UseGitVersion
)

# Get version from GitVersion if available and requested
$moduleVersion = $null
$semVer = $null
if ($UseGitVersion) {
    try {
        # Check if GitVersion tool is available
        $gitVersionPath = Get-Command dotnet-gitversion -ErrorAction SilentlyContinue
        if ($gitVersionPath) {
            Write-Host "Getting version from GitVersion..." -ForegroundColor Green
            $gitVersionOutput = & dotnet-gitversion | ConvertFrom-Json
            $moduleVersion = [Version]$gitVersionOutput.MajorMinorPatch
            $semVer = $gitVersionOutput.SemVer
            Write-Host "GitVersion calculated version: $moduleVersion" -ForegroundColor Green
            Write-Host "GitVersion full semantic version: $semVer" -ForegroundColor Green
        } else {
            Write-Warning "GitVersion tool not found. Install with: dotnet tool install --global GitVersion.Tool"
        }
    } catch {
        Write-Warning "Failed to get version from GitVersion: $_"
    }
}

$buildParams = @{
    Path                       = $SourcePath
    OutputDirectory            = $OutputDirectory
    UnversionedOutputDirectory = $true
    Passthru                   = $true
    Suffix                     = "./build.suffix.ps1"
    Prefix                     = "./build.prefix.ps1"
}

# Add version information if we got one from GitVersion
if ($moduleVersion -and $semVer) {
    # Use SemVer parameter for full semantic versioning support (includes pre-release tags)
    $buildParams['SemVer'] = $semVer
    Write-Host "Using semantic version for build: $semVer" -ForegroundColor Green
} elseif ($moduleVersion) {
    # Fallback to Version parameter if only basic version is available
    $buildParams['Version'] = $moduleVersion
    Write-Host "Using basic version for build: $moduleVersion" -ForegroundColor Green
}

$module = Build-Module @buildParams

# Validate the built module can be imported
if ($module) {
    Write-Host "Build completed successfully. Module: $($module.Name) Version: $($module.Version)" -ForegroundColor Green

    # Test module import
    try {
        Import-Module $module.ModuleBase -Force -ErrorAction Stop
        $importedModule = Get-Module $module.Name
        Write-Host "Module import validation successful. Functions exported: $($importedModule.ExportedFunctions.Count)" -ForegroundColor Green
        Remove-Module $module.Name -Force
    } catch {
        Write-Error "Module import validation failed: $_"
        throw
    }
} else {
    Write-Error "Build failed - no module output"
    throw "Build process failed"
}