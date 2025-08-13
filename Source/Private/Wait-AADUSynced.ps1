function Wait-AADUSynced {
    <#
    .SYNOPSIS
    Waits till a user is found in AzureAD.
    .DESCRIPTION
    Checks every 5 seconds if the user can be found.
    returns $true when they are found
    returns $false after trying for 2 minutes
    .PARAMETER UserPrincipalName
        system.string UserprincipalName
        E.G 'firstname.lastname@Domain.com'
    .INPUTS
        system.string for UserPrincipalName
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    [cmdletbinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$UserPrincipalName
    )
    Begin {}
    Process {
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(2)
        $Finished = $false
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Check UserSynced")) {
            do {
                $TimeNow = Get-Date
                if (Assert-AADUExists -UserPrincipalName $UserPrincipalName) {
                    $Finished = $true
                    Write-Log -Level Debug -Message 'Found {0} In AzureAD' -Arguments $UserPrincipalName
                    return $true
                }
                elseif ($TimeNow -ge $TimeEnd) {
                    $Finished = $true
                    Write-Log -Level Warning -Message 'Searched for 2 minute Exiting...'
                    Write-Log -Level Warning -Message 'Failed to confirm AzureAD Connection'
                    Write-Log -Level Error -Message 'User Creation will no continue past this point'
                    return $false
                }
                else {
                    Write-Log -Level Debug -Message 'Sleeping 5 second'
                    Start-Sleep -Seconds 5
                }
            } until ($Finished -eq $true)
        }
    }
    End {}
}