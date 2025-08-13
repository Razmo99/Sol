function Start-Logging{
    <#
    .SYNOPSIS
        Creates a spot to store transcripts from scripts
    .DESCRIPTION
    Creates a folder called logs at the specified Path, then stores transcripts from script execution. 
    These are prefixed with the $Name variable then a timestamp.
    It will need a specified Number of logs default being 50, any logs older then this will be deleted
    .PARAMETER Path
        system.string file path to store the logs in
    .PARAMETER Name
        system.string name to prefix the log with
        E.G firstname.lastname or the name of the script
    .PARAMETER NumberOfLogsToKeep
        system.string 
    .INPUTS
        system.string for Path
        system.string for Name
    .OUTPUTS
        None.
    #>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true,HelpMessage='Must Be $MyInvocation.MyCommand.Path')][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$false)][int]$NumberOfLogsToKeep=50
	)
    #Region Logging Variables
    $LogPath = Join-Path -Path $Path -ChildPath 'Logs'
    $TimeStamp = Get-Date -Format yyyy-MM-dd_HHmmss
    $LogFileName = '{0}_{1}.log' -f $Name, $TimeStamp
    $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName
    #Change this value to how many log files you want to keep
    If(Test-Path -Path $LogPath){
        #Make some cleanup and keep only the most recent ones
        $Filter = '*_????-??-??_??????.log'
        Get-ChildItem -Path $Filter |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -Skip $NumberOfLogsToKeep |
        Remove-Item -Verbose
    }else{
        #No logs to clean but create the Logs folder
        New-Item -Path $LogPath -ItemType Directory -Verbose
    }
    Start-Transcript -Path $Logfile
    #endregion Logging Variables
}
