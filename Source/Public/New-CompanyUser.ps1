function New-CompanyUser {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(1, 20)][string]$Firstname,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Lastname,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][SecureString]$Password,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][ValidatePattern('^[0-9]{4,4}$|^(?![\s\S])')][String]$OfficePhone,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][ValidatePattern('^[0-9]{10,10}$|^(?![\s\S])')][String]$MobilePhone,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Title,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Description,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$StreetAddress,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$State,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$City,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$PostalCode,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Country,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Department,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$LogonScript,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$ProfilePath,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$HomeDirectory,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$HomeDrive,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Manager,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$UserOU,
        [Parameter(Mandatory = $true)][String]$EMSServer,
        [Parameter(Mandatory = $true)][String]$ADSyncServer,
        [Parameter(Mandatory = $true)][String]$EmailDomain,
        [Parameter(Mandatory = $true)][String]$Domain,
        [Parameter(Mandatory = $true)][String]$Company,
        [Parameter(Mandatory = $false)][System.Collections.ArrayList]$AdminGroups,
        [Parameter(Mandatory = $false)][String]$FallbackUserOU,
        [Parameter(Mandatory = $false)][HashTable]$InteractivePrompts,
        [Parameter(Mandatory = $false)][HashTable]$AutoMemberOf,
        [Parameter(Mandatory = $false)][PSCredential]$ADAdminCreds,
        [Parameter(Mandatory = $false)][PSCredential]$EMSAdminCreds,
        [Parameter(Mandatory = $false)][PSCredential]$ADSyncAdminCreds
    )
    Begin {
        Initialize-Logging -LogFilePath $PSScriptRoot -LogFileNamePrefix ($Firstname + '.' + $Lastname)
        if ($ADAdminCreds) {
            [HashTable]$SplatAssertADPerms = @{
                Server      = $Domain
                AdminGroups = $AdminGroups
                Credential  = $ADAdminCreds
            }
        }
        else {
            [HashTable]$SplatAssertADPerms = @{
                Server      = $Domain
                AdminGroups = $AdminGroups
            }
        }
        if ($PSCmdlet.ShouldProcess($Domain, 'Assert-ADPermission')) {
            if (!(Assert-ADPermission @SplatAssertADPerms)) {
                $ADAdminCreds = Get-Credential -Message 'Enter AD Admin Credentials'
                $SplatAssertADPerms.Credential = $ADAdminCreds
                if (!(Assert-ADPermission @SplatAssertADPerms)) {
                    Write-Log -Level Error -Message 'Provided Credentials have insufficient permissions'
                    return
                }
            }
        }
        if ($PSCmdlet.ShouldProcess($EMSServer, 'Assert-EMSPermission')) {
            if ($EMSAdminCreds) {
                [HashTable]$SplatAssertEMSPerms = @{
                    Server     = $EMSServer
                    Credential = $EMSAdminCreds
                }
            }
            else {
                [HashTable]$SplatAssertEMSPerms = @{
                    Server = $EMSServer
                }
            }
            if (!(Assert-EMSPermission @SplatAssertEMSPerms)) {
                $EMSAdminCreds = Get-Credential -Message 'Enter EMS Admin Credentials'
                $SplatAssertEMSPerms.Credential = $EMSAdminCreds
                if (!(Assert-EMSPermission @SplatAssertEMSPerms)) {
                    Write-Log -Level Error -Message 'Provided Credentials have insufficient permissions'
                    return
                }
            }
        }
        if ($PSCmdlet.ShouldProcess($ADSyncServer, 'Assert-ADSyncPermission')) {
            if ($ADSyncAdminCreds) {
                [HashTable]$SplatAssertADSyncPerms = @{
                    Server     = $ADSyncServer
                    Credential = $ADSyncAdminCreds
                }
            }
            else {
                [HashTable]$SplatAssertADSyncPerms = @{
                    Server = $ADSyncServer
                }
            }
            if (!(Assert-ADSyncPermission @SplatAssertADSyncPerms)) {
                $ADSyncAdminCreds = Get-Credential -Message 'Enter ADSync Admin Credentials'
                $SplatAssertADSyncPerms.Credential = $ADSyncAdminCreds
                if (!(Assert-ADSyncPermission @SplatAssertADSyncPerms)) {
                    Write-Log -Level Error -Message 'Provided Credentials have insufficient permissions'
                    return
                }
            }
        }
        [XML]$Branches = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Branches.xml') -Raw
        if ($Branches) {
            $UserBranch = Show-CompanyBranches -Branches $Branches
            if ($UserBranch) {
                $Branch = $Branches.$UserBranch
                $StreetAddress = $Branch.StreetAddress
                $State = $Branch.State
                $City = $Branch.City
                $PostalCode = $Branch.PostalCode
                $Country = $Branch.Country
                $Department = $Branch.Department
                $LogonScript = $Branch.LogonScript
                $ProfilePath = $Branch.ProfilePath
                $HomeDirectory = $Branch.HomeDirectory
                $HomeDrive = $Branch.HomeDrive
                $Manager = $Branch.Manager
                $UserOU = $Branch.UserOU
            }
        }
        if (!$UserOU) {
            $UserOU = $FallbackUserOU
        }
    }
    Process {
        $SamAccountName = $Firstname + '.' + $Lastname
        $UserPrincipalName = $SamAccountName + $EmailDomain
        $DisplayName = $Firstname + ' ' + $Lastname
        [HashTable]$SplatAssertADUExists = @{
            SamAccountName = $SamAccountName
            Server         = $Domain
        }
        if ($ADAdminCreds) {
            $SplatAssertADUExists.Add('Credential', $ADAdminCreds)
        }
        if (Assert-ADUExists @SplatAssertADUExists) {
            Write-Log -Level Error -Message 'User Already Exists in AD'
            return
        }
        if (Assert-MgUserExist -UserPrincipalName $UserPrincipalName) {
            Write-Log -Level Error -Message 'User Already Exists in Microsoft Graph'
            return
        }
        if (Assert-EMSUExists -SamAccountName $SamAccountName -Server $EMSServer) {
            Write-Log -Level Error -Message 'User Already Exists in EMS'
            return
        }
        [HashTable]$SplatNewADUser = @{
            Name                  = $DisplayName
            GivenName             = $Firstname
            Surname               = $Lastname
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $UserPrincipalName
            AccountPassword       = $Password
            ChangePasswordAtLogon = $true
            Enabled               = $true
            Path                  = $UserOU
            Company               = $Company
            Server                = $Domain
        }
        if ($ADAdminCreds) {
            $SplatNewADUser.Add('Credential', $ADAdminCreds)
        }
        if ($OfficePhone) { $SplatNewADUser.add('OfficePhone', $OfficePhone) }
        if ($MobilePhone) { $SplatNewADUser.add('MobilePhone', $MobilePhone) }
        if ($Title) { $SplatNewADUser.add('Title', $Title) }
        if ($Description) { $SplatNewADUser.add('Description', $Description) }
        if ($StreetAddress) { $SplatNewADUser.add('StreetAddress', $StreetAddress) }
        if ($State) { $SplatNewADUser.add('State', $State) }
        if ($City) { $SplatNewADUser.add('City', $City) }
        if ($PostalCode) { $SplatNewADUser.add('PostalCode', $PostalCode) }
        if ($Country) { $SplatNewADUser.add('Country', $Country) }
        if ($Department) { $SplatNewADUser.add('Department', $Department) }
        if ($LogonScript) { $SplatNewADUser.add('ScriptPath', $LogonScript) }
        if ($ProfilePath) { $SplatNewADUser.add('ProfilePath', $ProfilePath) }
        if ($HomeDirectory) { $SplatNewADUser.add('HomeDirectory', $HomeDirectory) }
        if ($HomeDrive) { $SplatNewADUser.add('HomeDrive', $HomeDrive) }
        if ($Manager) { $SplatNewADUser.add('Manager', $Manager) }
        if ($PSCmdlet.ShouldProcess($UserOU, 'New-ADUser')) {
            try {
                New-ADUser @SplatNewADUser -ErrorAction Stop
            }
            catch {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                return
            }
        }
        [HashTable]$SplatWaitADUSynced = @{
            SamAccountName = $SamAccountName
            Server         = $Domain
        }
        if ($ADAdminCreds) {
            $SplatWaitADUSynced.Add('Credential', $ADAdminCreds)
        }
        if (Wait-ADUSynced @SplatWaitADUSynced) {
            [HashTable]$SplatSyncAD = @{
                Server          = $Domain
                ActiveDirectory = $true
            }
            if ($ADAdminCreds) {
                $SplatSyncAD.Add('Credential', $ADAdminCreds)
            }
            Sync-Directories @SplatSyncAD
        }
        [HashTable]$SplatSyncMgGraph = @{
            Server  = $ADSyncServer
            EntraID = $true
        }
        if ($ADSyncAdminCreds) {
            $SplatSyncMgGraph.Add('Credential', $ADSyncAdminCreds)
        }
        if (Sync-Directories @SplatSyncMgGraph) {
            Wait-MgUserSynced -UserPrincipalName $UserPrincipalName
        }
        [boolean]$FileServerAccess = $false
        if ($HomeDrive -and $HomeDirectory) {
            $FileServerAccess = $true
        }
        [String]$M365License = ''
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Set-MgUserLicenseWrapper')) {
            $response = Read-Host 'Assign M365 License? [E1,E2,E3,N]ostyn'
            if ($response -match 'E[1-3]') {
                $M365License = $response.ToUpper()
                Set-MgUserLicenseWrapper -UserPrincipalName $UserPrincipalName -LicenseType $M365License
            }
        }
        if ($InteractivePrompts -or $AutoMemberOf) {
            $Groups = Test-InteractivePrompts -InteractivePrompts $InteractivePrompts -AutoMemberOf $AutoMemberOf -FileServerAccess $FileServerAccess -M365License $M365License
            if ($Groups) {
                [HashTable]$SplatSetADUGroups = @{
                    Identity = $SamAccountName
                    Groups   = $Groups
                    Server   = $Domain
                }
                if ($ADAdminCreds) {
                    $SplatSetADUGroups.Add('Credential', $ADAdminCreds)
                }
                Set-ADUGroups @SplatSetADUGroups
            }
        }
    }
    End {
    }
}