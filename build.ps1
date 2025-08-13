param(
    [string]$SourcePath = (Join-Path -Path $PSScriptRoot -ChildPath 'Source'),
    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath 'output')
)

$buildParams = @{
    Path                      = $SourcePath
    OutputDirectory           = $OutputDirectory
    UnversionedOutputDirectory = $true
    Passthru                  = $true
    Suffix = "./build.suffix.ps1"
    Prefix = "./build.prefix.ps1"

}

$module = Build-Module @buildParams