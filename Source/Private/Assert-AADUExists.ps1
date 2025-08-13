function Assert-AADUExists {
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
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName
    )
    begin {
        if (!(Test-AADConnected -whatif:$false -AADRoles @('User Administrator'))) {
            Write-Error -Message 'No AzureAD Connection'
            return
            }
    }
    process {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Get-AzureADUser')) {
            try {[bool]$Exists = Get-AzureADUser -objectid $UserPrincipalName -ErrorAction SilentlyContinue
            }catch {

            }
            if ($Exists) {
                Write-Verbose('Found '+$UserPrincipalName+' in AzureAD')
                return $true
            }
            else {
                Write-Verbose ($UserPrincipalName + ' could not be found in AzureAD')
                return $false
            }
        }
    }
    end {}
}
