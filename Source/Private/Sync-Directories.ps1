function Sync-Directories{
    <#
    .SYNOPSIS
    Sync AD or AAD with each other
    .DESCRIPTION
    Can sync all domain controllers in a forest, Can also start a delta sync on Azure Active Directory Connector
    .PARAMETER Credentials
        ADGroup Names to match against
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER ActiveDirectory
        Switch to sync ActiveDirectory

    .PARAMETER AzureActiveDirectory
        Switch to Sync Azure Active Directory Connector
    .INPUTS
        None.
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0,Mandatory=$false)][pscredential]$Credential,
        [Parameter(Mandatory=$true)][string]$Server,
        [switch]$AzureActiveDirectory,
        [switch]$ActiveDirectory
    )
    if (!$WhatIfPreference) {
        if (!$Credential) {
            $Credential = Get-Credential -Message ('Enter Credentials for '+$Server)
            if (!$Credential) {
                return Write-Error('No Credentials Provided')
            }
        }
    }
    if($ActiveDirectory) {
        $ADReplicate = {
            $DCSession = New-PSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $DCSession -ScriptBlock { 
                Import-Module -Name 'ActiveDirectory'
                Write-Output ('Syncing all DC held on '+$Server)
                repadmin.exe /syncall /AdeP | Out-Null
                Write-Output 'SyncAll Completed'
            }
            Remove-PSSession $DCSession
        }
        Write-Verbose('Syncing Domain Controllers')
        if ($PSCmdlet.ShouldProcess($Server, "repadmin.exe /syncall /AdeP")) {
            if((Invoke-Command $ADReplicate -ErrorAction Stop).Result -eq 'Success'){
                return $true
            }else{
                return $false
            }    
        }
    }elseif($AzureActiveDirectory){
        $AADConnectSync = {
            $AADConnectSession = New-PSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $AADConnectSession -ScriptBlock {
                $VerbosePreference='Continue'
                Import-Module -Name 'ADSync' -Function Get-ADSyncConnectorRunStatus,Start-ADSyncSyncCycle
                $TimeStart = Get-Date
                $TimeEnd = $timeStart.addminutes(2)
                $Finished=$false
                do {
                    $TimeNow = Get-Date
                    if (!(Get-ADSyncConnectorRunStatus)) {
                        try{
                            Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
                            $Finished = $true
                            return $true
                        }catch [System.Management.Automation.RuntimeException]{
                            Write-Verbose('Sync is already running. Cannot start a new run till this one completes.')
                            $Finished = $false
                        }catch{
                            Write-Verbose($_.Exception.Message)
                        }
                    }elseif($TimeNow -ge $TimeEnd){
                        $Finished = $true
                        Write-Warning('Searched for 2 minute Exiting...')
                        Write-Warning('Azure AD is still Busy.')
                        Write-Error('User Creation will no continue past this point')
                        return $false
                    }else {
                        Write-Verbose('Sleeping 10 second')
                        Start-Sleep -Seconds 10
                    }
                } until ($Finished -eq $true)
            }
            Remove-PSSession $AADConnectSession
        }
        if ($PSCmdlet.ShouldProcess($Server, "Start-ADSyncSyncCycle -PolicyType Delta")) {
            Write-Verbose('Syncing ADConnect')
            $PSIResult = Invoke-Command $AADConnectSync -ErrorAction Stop
            if ($PSIResult) {
                return $true
            }else{
                return $false
            }

        }

    }elseif(!$AzureActiveDirectory -and !$ActiveDirectory) {
        return Write-Error('No System switch specified')
    }else{
        return $false
    }
}
