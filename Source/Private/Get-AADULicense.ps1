Function Get-AADULicense {
    <#
    .SYNOPSIS
    Gets the Microsoft 365 License for a specific User
    .DESCRIPTION
    Checks for an existing connection to AzureAD or initiates one.
    Looks up the SKuID and Matches it to the SKuPartNumber
    .PARAMETER UserPrincipalName
        System.String UserprincipalName
    .INPUTS
        System.String. Set-AADULicense Accepts Values for UserPrincipalName
    .OUTPUTS
        PSCustomObject. Set-AADULicense returns a PSObject with the UserPrincipalName, SkuPartNumber
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$UserPrincipalName
    )
    Begin {
        if (!(Test-AADConnected -whatif:$false -AADRole @('User Administrator'))) {
            Write-Log -Level Error -Message 'No AzureAD Connection'
            return
        }
        $SkuInfo = Get-AzureADSubscribedSku
    }
    Process {
        [System.Collections.ArrayList]$LicenseArray = @()
        $AssignedLicenses = (Get-AzureADUser -ObjectId $UserPrincipalName).AssignedLicenses
        foreach ($License in $AssignedLicenses) {
            if ($SkuInfo.SkuId -contains $License.SkuID) {
                $Key = $SkuInfo.SkuId.IndexOf($License.SkuId)
                $null = $LicenseArray.Add($SkuInfo[$Key].SkuPartNumber)
            }
        }
        [PSCustomObject]@{
            UserPrincipalName = $UserPrincipalName
            SkuPartNumber     = $LicenseArray
        }
        #>
    }
    End {}
}
