param(
    [string]$SourcePath = (Join-Path -Path $PSScriptRoot -ChildPath 'Source'),
    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'output'),
    [switch]$UseGitVersion
)

# Get version from GitVersion if available and requested
$moduleVersion = $null
$nugetVersion = $null
if ($UseGitVersion) {
    try {
        # Check if GitVersion tool is available
        $gitVersionPath = Get-Command dotnet-gitversion -ErrorAction SilentlyContinue
        if ($gitVersionPath) {
            Write-Information "Getting version from GitVersion..."
            $gitVersionOutput = & dotnet-gitversion | ConvertFrom-Json
            $moduleVersion = [Version]$gitVersionOutput.MajorMinorPatch
            $nugetVersion = $gitVersionOutput.NuGetVersionV2
            Write-Information "GitVersion calculated version: $moduleVersion"
            Write-Information "GitVersion NuGet-compatible version: $nugetVersion"
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
if ($moduleVersion -and $nugetVersion) {
    # Use NuGet-compatible version for module publishing compatibility
    $buildParams['SemVer'] = $nugetVersion
    Write-Information "Using NuGet-compatible version for build: $nugetVersion"
} elseif ($moduleVersion) {
    # Fallback to Version parameter if only basic version is available
    $buildParams['Version'] = $moduleVersion
    Write-Information "Using basic version for build: $moduleVersion"
}

Build-Module @buildParams