function Test-EMSConnected {
    <#
    .SYNOPSIS
    Checks if a connection to EMS is Present
    .DESCRIPTION
        Checks to see if an active ps session is present and if the command New-RemoteMailbox is available.
        If it is not it checked for a stale session and removes it.
        returns true if the command can be retreived false otherwise
    .OUTPUTS
        system.boolean
    .INPUTS
     None
    #>    
    $CheckExistingSession = Get-PSSession | Where-Object {$_.State -eq 'Opened' -and $_.ConfigurationName -eq 'Microsoft.Exchange'}
    [bool]$CheckEMSCommandPresent = Get-Command New-RemoteMailbox -ErrorAction SilentlyContinue
    if(!$CheckEMSCommandPresent){
        Write-Log -Level Verbose -Message 'Unable to get EMS Commands'
        if ($CheckExistingSession) {
            Write-Log -Level Verbose -Message 'Removing stale PSSession'
            $CheckExistingSession | Remove-PSSession
        }
        return $false
    }elseif($CheckExistingSession) {
        Write-Log -Level Verbose -Message 'EMS Session Already Present'
        return $true
    }
}
