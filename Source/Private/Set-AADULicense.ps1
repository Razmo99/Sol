function Set-AADULicense {
    <#
    .SYNOPSIS
    Sets the Microsoft 365 License for a specific User
    .DESCRIPTION
    Checks for an existing connection to AzureAD or initiates one.
    Makes sure the country code is set correctly
    Checks their are enough Licenses to assign then assignes one for the user.
    .PARAMETER UserPrincipalName
        System.String UserprincipalName Has an Alias 'Email'
    .PARAMETER LicenseType
        System.String License to Set, Supports E1, E2, E3
    .PARAMETER CountryCode
        System.String UsageLocation to set for the assigned License
    .INPUTS
        System.String. Set-AADULicense Accepts Values for UserPrincipalName, LicenseType & CountryCode
    .OUTPUTS
        PSObject. Set-AADULicense returns a PSObject with the UserPrincipalName, LicenseType & CountryCode
    #>
    
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Alias('Email')][string]$UserPrincipalName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateSet('E1','E2','E3')][String]$LicenseType,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$CountryCode='AU'
    )
    Begin{
        #Ensure AzureAD is Connected
        if (!(Test-AADConnected -whatif:$false -AADRole @('User Administrator'))) {
            return Write-Error('No AzureAD Connection')
        }
    }
    Process{
        #Check the users Country Code is selected
        if($PSCmdlet.ShouldProcess($UserPrincipalName,'Set-AzureADUser -UsageLocation '+$CountryCode)){
            try{
                $UseLoc = (Get-AzureADUser -ObjectID $UserPrincipalName).UsageLocation
            }catch{            
                return Write-Error($_.Exception.Message)
            }
            if ($useLoc -eq $CountryCode) {
                Write-Verbose('Country already set to; '+$CountryCode)
            }else{
                
                if(!$UseLoc){
                    Write-Verbose('Country code not set; Setting to: '+$CountryCode)
                }elseif($UseLoc){
                    Write-Verbose('Country code is currently: '+$UseLoc)
                }
                try {
                    Set-AzureADUser -ObjectID $UserPrincipalName -UsageLocation $CountryCode -ErrorAction Stop
                }
                catch {
                    if(exception.message.contains('Insufficient privileges to complete the operation.')){
                        Write-Warning('RunAs User has Insufficient privileges')
                        Disconnect-AzureAD -WhatIf:$false
                        Connect-AzureAD -WhatIf:$false
                        Set-AADULicense -CountryCode $CountryCode -UserPrincipalName $UserPrincipalName -LicenseType $LicenseType
                    }else{
                        Write-Error($_.Exception.Message)
                        return
                    }
                }
            }
        }
        if ($LicenseType -eq 'E3') {$planName='ENTERPRISEPACK'}
        elseif($LicenseType -eq 'E2'){$planName='EXCHANGEENTERPRISE'}
        elseif($LicenseType -eq 'E1'){$planName='STANDARDPACK'}

        $LicenseInfo = Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $planName -EQ | Select-Object SkuPartNumber, consumedunits, prepaidunits
        if ($LicenseInfo.consumedunits -lt $LicenseInfo.prepaidunits.enabled) {
            Write-Verbose(($LicenseInfo.prepaidunits.enabled - $LicenseInfo.consumedunits).ToString()+' '+$LicenseType+' Available; Proceeding to assign a License')
            $License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
            $License.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $planName -EQ).SkuID
            $LicensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            $LicensesToAssign.AddLicenses = $License
            if($PSCmdlet.ShouldProcess($UserPrincipalName,'Set-AzureADUserLicense to: '+$LicenseType)){
                    Set-AzureADUserLicense -ObjectId $UserPrincipalName -AssignedLicenses $LicensesToAssign -ErrorAction Stop
                if($?){
                    [PSCustomObject]@{
                        UserPrincipalName=$UserPrincipalName
                        License=$LicenseType
                        UsageLocation=$CountryCode
                    }
                }
            }
        }elseif(($LicenseInfo.prepaidunits.enabled - $LicenseInfo.consumedunits) -eq 0){
            Write-Warning('No '+$LicenseType+' License Available. No License will be assigned')
            Write-Verbose($LicenseInfo.prepaidunits.enabled.ToString() + ' PrePaid | '+ $LicenseInfo.consumedunits.ToString() + ' Consumed')
        }else {
            Write-Error -Message 'Unhandled Exception'
        }
    }
    End{}
}
