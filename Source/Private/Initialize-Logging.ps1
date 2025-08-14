function Initialize-Logging {
    <#
    .SYNOPSIS
        Configures the centralized logging module.
    .DESCRIPTION
        This function sets up the console and file logging targets for the 'Logging' module,
        including specified color schemes for different log levels.
    .PARAMETER LogFilePath
        The absolute path to the directory where log files should be stored.
    .PARAMETER LogFileNamePrefix
        A prefix for the log file names.
    .PARAMETER MaxLogFileSizeMB
        The maximum size of a log file in megabytes before it rotates.
    .PARAMETER MaxLogFiles
        The maximum number of rotating log files to keep.
    .INPUTS
        None.
    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$LogFilePath,
        [Parameter(Mandatory = $true)][string]$LogFileNamePrefix,
        [Parameter(Mandatory = $false)][int]$RotateAfterSize = 5*1024*1024,
        [Parameter(Mandatory = $false)][int]$RotateAfterAmount = 5,
        [string][ValidateSet('DEBUG','INFO','WARNING','ERROR')]$Level='DEBUG'

    )

    # Define common colors for both targets
    $LogColors = @{
        Debug       = 'Cyan'
        Warning     = 'Yellow'
        Error       = 'Red'
        Information = 'Green'
    }

    Set-LoggingDefaultLevel -Level $Level

    Add-LoggingTarget -Name Console -Configuration @{
        ColorMapping = $color_mapping
        level = $Level
    }

    Add-LoggingTarget -Name File -Configuration @{
        Path = (Join-Path $LogFilePath "$($LogFileNamePrefix)_$(Get-Date -Format 'yyyyMMdd').log")
        level = $Level
        ColorMapping = $LogColors
        Encoding = 'utf8'
        RotateAfterSize = $RotateAfterSize
        RotateAfterAmount = $RotateAfterAmount
        RotateAmount = 1
    }
}
