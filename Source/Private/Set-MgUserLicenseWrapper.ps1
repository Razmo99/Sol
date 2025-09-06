function Set-MgUserLicenseWrapper {
    <#
    .SYNOPSIS
    Sets the Microsoft 365 License for a specific User
    .DESCRIPTION
    Checks for an existing connection to Microsoft Graph or initiates one.
    Makes sure the country code is set correctly
    Checks their are enough Licenses to assign then assignes one for the user.
    .PARAMETER UserPrincipalName
        System.String UserprincipalName Has an Alias 'Email'
    .PARAMETER LicenseType
        System.String License to Set, Supports E1, E2, E3
    .PARAMETER CountryCode
        System.String UsageLocation to set for the assigned License
    .INPUTS
        System.String. Set-MgUserLicenseWrapper Accepts Values for UserPrincipalName, LicenseType & CountryCode
    .OUTPUTS
        PSObject. Set-MgUserLicenseWrapper returns a PSObject with the UserPrincipalName, LicenseType & CountryCode
    #>

    [cmdletbinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('Email')][string]$UserPrincipalName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateSet('E1', 'E2', 'E3')][String]$LicenseType,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][String]$CountryCode = 'AU'
    )
    Begin {
        #Ensure Microsoft Graph is Connected
        if (!(Test-MgConnected -whatif:$false -DirectoryRoles @('User Administrator'))) {
            return Write-Log -Level Error -Message 'No Microsoft Graph Connection'
        }
    }
    Process {
        #Check the users Country Code is selected
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Update-MgUser -UsageLocation ' + $CountryCode)) {
            try {
                $UseLoc = (Get-MgUser -UserId $UserPrincipalName -Property UsageLocation -ErrorAction Stop).UsageLocation
            }
            catch {
                return Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
            if ($useLoc -eq $CountryCode) {
                Write-Log -Level Debug -Message 'Country already set to; {0}' -Arguments $CountryCode
            }
            else {
                if (!$UseLoc) {
                    Write-Log -Level Debug -Message 'Country code not set; Setting to: {0}' -Arguments $CountryCode
                }
                elseif ($UseLoc) {
                    Write-Log -Level Debug -Message 'Country code is currently: {0}' -Arguments $UseLoc
                }
                try {
                    Update-MgUser -UserId $UserPrincipalName -UsageLocation $CountryCode -ErrorAction Stop
                }
                catch {
                    if ($_.Exception.Message.Contains('Insufficient privileges to complete the operation.')) {
                        Write-Log -Level Warning -Message 'RunAs User has Insufficient privileges'
                        Disconnect-MgGraph -WhatIf:$false
                        Connect-MgGraph -Scopes @('User.ReadWrite.All', 'Directory.Read.All', 'Organization.Read.All') -WhatIf:$false
                        Set-MgUserLicenseWrapper -CountryCode $CountryCode -UserPrincipalName $UserPrincipalName -LicenseType $LicenseType
                    }
                    else {
                        Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                        return
                    }
                }
            }
        }
        if ($LicenseType -eq 'E3') { $planName = 'ENTERPRISEPACK' }
        elseif ($LicenseType -eq 'E2') { $planName = 'EXCHANGEENTERPRISE' }
        elseif ($LicenseType -eq 'E1') { $planName = 'STANDARDPACK' }

        $LicenseInfo = Get-MgSubscribedSku | Where-Object -Property SkuPartNumber -Value $planName -EQ | Select-Object SkuPartNumber, SkuId, ConsumedUnits, PrepaidUnits
        if ($LicenseInfo.ConsumedUnits -lt $LicenseInfo.PrepaidUnits.Enabled) {
            Write-Log -Level Debug -Message '{0} {1} Available; Proceeding to assign a License' -Arguments @(($LicenseInfo.PrepaidUnits.Enabled - $LicenseInfo.ConsumedUnits).ToString(), $LicenseType)
            $addLicenses = @(@{SkuId = $LicenseInfo.SkuId})
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Set-MgUserLicense to: ' + $LicenseType)) {
                try {
                    Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses $addLicenses -RemoveLicenses @() -ErrorAction Stop
                    if ($?) {
                        [PSCustomObject]@{
                            UserPrincipalName = $UserPrincipalName
                            License           = $LicenseType
                            UsageLocation     = $CountryCode
                        }
                    }
                }
                catch {
                    Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                    return
                }
            }
        }
        elseif (($LicenseInfo.PrepaidUnits.Enabled - $LicenseInfo.ConsumedUnits) -eq 0) {
            Write-Log -Level Warning -Message 'No {0} License Available. No License will be assigned' -Arguments $LicenseType
            Write-Log -Level Debug -Message '{0} PrePaid | {1} Consumed' -Arguments @($LicenseInfo.PrepaidUnits.Enabled.ToString(), $LicenseInfo.ConsumedUnits.ToString())
        }
        else {
            Write-Log -Level Error -Message 'Unhandled Exception'
        }
    }
    End {}
}
