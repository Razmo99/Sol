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
            Write-Information "Getting version from GitVersion..."
            $gitVersionOutput = & dotnet-gitversion | ConvertFrom-Json
            $moduleVersion = [Version]$gitVersionOutput.MajorMinorPatch
            $semVer = $gitVersionOutput.SemVer
            Write-Information "GitVersion calculated version: $moduleVersion"
            Write-Information "GitVersion full semantic version: $semVer"
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
    Suffix                     = "./build.suffix.ps1"
    Prefix                     = "./build.prefix.ps1"
}

# Add version information if we got one from GitVersion
if ($moduleVersion -and $semVer) {
    # Use SemVer parameter for full semantic versioning support (includes pre-release tags)
    $buildParams['SemVer'] = $semVer
    Write-Information "Using semantic version for build: $semVer"
} elseif ($moduleVersion) {
    # Fallback to Version parameter if only basic version is available
    $buildParams['Version'] = $moduleVersion
    Write-Information "Using basic version for build: $moduleVersion"
}

Build-Module @buildParams