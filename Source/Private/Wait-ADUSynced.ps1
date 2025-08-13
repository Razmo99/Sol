function Wait-ADUSynced {
    <#
    .SYNOPSIS
    Waits till a user is found in Active Directory
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
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][String]$Server,
        [Parameter(Mandatory = $false)][pscredential]$Credential
    )
    Begin {}
    Process {
        #Hash table for the assert user function.
        [HashTable]$SplatUserExists = @{
            SamAccountName = $SamAccountName
            Server         = $Server
            ErrorAction    = 'SilentlyContinue'
        }
        #If Credentials add them to the splat
        if ($Credentials) { $SplatUserExists.Add('Credential', $Credential) }

        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(1)
        $Finished = $false
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Check UserSynced")) {
            do {
                $TimeNow = Get-Date
                if (Assert-ADUExists @SplatUserExists) {
                    $Finished = $true
                    Write-Log -Level Debug -Message 'Found {0} In AD' -Arguments $SamAccountName
                    return $true
                }
                elseif ($TimeNow -ge $TimeEnd) {
                    $Finished = $true
                    Write-Log -Level Warning -Message 'Searched for 1 minute Exiting...'
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