function Assert-MgUserExist {
    <#
    .SYNOPSIS
    Asserts if a user exists in Microsoft Graph
    .DESCRIPTION
    Asserts if a user exists in Microsoft Graph,
    returns true if they do, and false if they do not.
    .PARAMETER UserPrincipalName
        system.string UserprincipalName
        E.G 'firstname.lastname@Domain.com'
    .INPUTS
        system.string for UserPrincipalName
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$UserPrincipalName
    )
    begin {
        if (!(Test-MgConnected -whatif:$false -DirectoryRoles @('User Administrator'))) {
            Write-Log -Level Error -Message 'No Microsoft Graph Connection'
            return
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Get-MgUser')) {
            try {
                [bool]$Exists = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
                if ($Exists) {
                    Write-Log -Level Debug -Message 'Found {0} in Microsoft Graph' -Arguments $UserPrincipalName
                    return $true
                }
                else {
                    Write-Log -Level Debug -Message '{0} could not be found in Microsoft Graph' -Arguments $UserPrincipalName
                    return $false
                }
            }
            catch {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                return $false
            }
        }
    }
    end {}
}