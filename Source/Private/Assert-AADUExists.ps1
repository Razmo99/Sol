function Assert-AADUExist {
    <#
    .SYNOPSIS
    Asserts if a user exists in Azure Active Directory
    .DESCRIPTION
    Asserts if a user exists in Azure Active Directory,
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
        if (!(Test-AADConnected -whatif:$false -AADRoles @('User Administrator'))) {
            Write-Log -Level Error -Message 'No AzureAD Connection'
            return
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Get-AzureADUser')) {
            [bool]$Exists = Get-AzureADUser -objectid $UserPrincipalName -ErrorAction SilentlyContinue
            if ($Exists) {
                Write-Log -Level Debug -Message 'Found {0} in AzureAD' -Arguments $UserPrincipalName
                return $true
            }
            else {
                Write-Log -Level Debug -Message '{0} could not be found in AzureAD' -Arguments $UserPrincipalName
                return $false
            }
        }
    }
    end {}
}