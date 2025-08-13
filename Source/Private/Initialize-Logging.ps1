function Initialize-Logging{
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
        [Parameter(Mandatory=$true)][string]$LogFilePath,
        [Parameter(Mandatory=$true)][string]$LogFileNamePrefix,
        [Parameter(Mandatory=$false)][int]$MaxLogFileSizeMB = 10,
        [Parameter(Mandatory=$false)][int]$MaxLogFiles = 5
    )

    # Define common colors for both targets
    $LogColors = @{
        Debug = 'Cyan'
        Warning = 'Yellow'
        Error = 'Red'
        Information = 'Green'
    }

    # Configure Console Handler
    Add-LoggingTarget -Type Console -Level Debug -Colors $LogColors

    # Configure Rotating File Handler
    Add-LoggingTarget -Type File -Level Debug -Path (Join-Path $LogFilePath "$($LogFileNamePrefix)_$(Get-Date -Format 'yyyyMMdd').log") -RollingFile -MaxFileSizeMB $MaxLogFileSizeMB -MaxFiles $MaxLogFiles -Colors $LogColors
}
