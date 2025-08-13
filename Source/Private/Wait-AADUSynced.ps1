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
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName
    )
    Begin{}
    Process{
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(2)
        $Finished=$false
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Check UserSynced")) {
            do {
                $TimeNow = Get-Date
                if (Assert-AADUExists -UserPrincipalName $UserPrincipalName) {
                    $Finished = $true
                    Write-Verbose('Found '+$UserPrincipalName+' In AzureAD')
                    return $true
                }elseif($TimeNow -ge $TimeEnd){
                    $Finished = $true
                    Write-Warning('Searched for 2 minute Exiting...')
                    Write-Warning('Failed to confirm AzureAD Connection')
                    Write-Error('User Creation will no continue past this point')
                    return $false
                }else {
                    Write-Verbose('Sleeping 5 second')
                    Start-Sleep -Seconds 5
                }
            } until ($Finished -eq $true)   
        }
    }
    End{}
}
