function Sync-Directory {
    <#
    .SYNOPSIS
    Sync AD or Microsoft Graph with each other
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Position = 0, Mandatory = $false)][pscredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Server,
        [switch]$EntraID,
        [switch]$ActiveDirectory
    )
    if (!$WhatIfPreference) {
        if (!$Credential) {
            $Credential = Get-Credential -Message ('Enter Credentials for ' + $Server)
            if (!$Credential) {
                return Write-Log -Level Error -Message 'No Credentials Provided'
            }
        }
    }
    if ($ActiveDirectory) {
        $ADReplicate = {
            $DCSession = New-ManagedPSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $DCSession -ScriptBlock {
                Import-Module -Name 'ActiveDirectory'
                Write-Output ('Syncing all DC held on ' + $using:Server)
                repadmin.exe /syncall /AdeP | Out-Null
                Write-Output 'SyncAll Completed'
            }
            Remove-PSSession $DCSession
        }
        Write-Log -Level Debug -Message 'Syncing Domain Controllers'
        if ($PSCmdlet.ShouldProcess($Server, "repadmin.exe /syncall /AdeP")) {
            if ((Invoke-Command $ADReplicate -ErrorAction Stop).Result -eq 'Success') {
                return $true
            }
            else {
                return $false
            }
        }
    }
    elseif ($EntraID) {
        $EntraIDSync = {
            $EntraIDSession = New-ManagedPSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $EntraIDSession -ScriptBlock {
                $VerbosePreference = 'Continue'
                Import-Module -Name 'ADSync' -Function Get-ADSyncConnectorRunStatus, Start-ADSyncSyncCycle
                
                # Use Wait-UntilTrue to wait for sync completion, then start new cycle
                $SyncCompleted = Wait-UntilTrue -Condition { 
                    !(Get-ADSyncConnectorRunStatus) 
                } -TimeoutSeconds 120 -SleepSeconds 10 -Context "EntraID sync completion"
                
                if (!$SyncCompleted) {
                    Write-Log -Level Warning -Message 'Timeout waiting for EntraID sync to complete'
                    Write-Log -Level Error -Message 'User Creation will not continue past this point'
                    return $false
                }
                
                try {
                    Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
                    return $true
                }
                catch [System.Management.Automation.RuntimeException] {
                    Write-Log -Level Warning -Message 'Sync cycle could not start - another sync may still be running'
                    return $false
                }
                catch {
                    Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                    return $false
                }
            }
            Remove-PSSession $EntraIDSession
        }
        if ($PSCmdlet.ShouldProcess($Server, "Start-ADSyncSyncCycle -PolicyType Delta")) {
            Write-Log -Level Debug -Message 'Syncing Entra ID Connect'
            $PSIResult = Invoke-Command $EntraIDSync -ErrorAction Stop
            if ($PSIResult) {
                return $true
            }
            else {
                return $false
            }

        }

    }
    elseif (!$EntraID -and !$ActiveDirectory) {
        return Write-Log -Level Error -Message 'No System switch specified'
    }
    else {
        return $false
    }
}