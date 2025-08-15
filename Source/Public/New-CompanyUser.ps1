function New-CompanyUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(1, 20)][string]$Firstname,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Lastname,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][SecureString]$Password,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][ValidatePattern('^[0-9]{4,4}$|^(?![\s\S])')][String]$OfficePhone,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][ValidatePattern('^[0-9]{10,10}$|^(?![\s\S])')][String]$MobilePhone,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Title,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Manager,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][String]$Branch,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][AllowEmptyString()][validateset('E1', 'E2', 'E3', '')][string]$M365License,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][validateset('TRUE', 'FALSE')][string]$FileServerAccess,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][System.Collections.ArrayList]$MemberOf = @(),
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][HashTable]$AutoMemberOf = @{},
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][HashTable]$InteractivePrompts = @{},
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][validateset('Enabled', 'Disabled', 'Enforced')][String]$StrongAuthenticationRequiremets,        
        [Parameter(Mandatory = $true)][String]$Domain,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][validateset('TRUE', 'FALSE')][string]$DistributionList = 'TRUE',
        [Parameter(Mandatory = $false)][PSCredential]$EMSCredentials,
        [Parameter(Mandatory = $false)][String]$EMSServer,
        [Parameter(Mandatory = $false)][PSCredential]$ADCredentials,
        [Parameter(Mandatory = $false)][Boolean]$Interactive = $true,
        [Parameter(Mandatory = $false)][System.Collections.ArrayList]$AdminGroups,
        [Parameter(Mandatory = $false)][PSCredential]$ADSyncCredentials,
        [Parameter(Mandatory = $true)][String]$ADSyncServer,
        [Parameter(Mandatory = $true)][String]$EmailDomain,
        [Parameter(Mandatory = $true)][String]$FallbackUserOU,
        [Parameter(Mandatory = $true)][String]$Company,
        [Parameter(Mandatory = $false)][String][validateset('Hybrid', 'Cloud')]$M365DeploymentType = 'Hybrid'
    )
    begin {
        $CurrentPath = Split-Path -Path $PSCmdlet.MyInvocation.PSCommandPath -Parent
        Write-Verbose('Working Directory is:' + $CurrentPath)
        #Start logging
        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            Start-Logging -Path $CurrentPath -Name $Domain
        }
        #Get a domain controller to execute all AD commands on
        try {
            $DomainController = (Get-ADDomainController -Discover -Domain $Domain -Service "PrimaryDC" -ErrorAction Stop).Hostname.Value
            Write-Verbose('Executing AD commands on: ' + $DomainController)
        }
        catch {
            Write-Error($_.Exception.Message)
            exit
        }
        #Get branch information XML document
        try {
            [xml]$XmlDocument = Get-Content -Path ($CurrentPath + '\BRANCHES.XML') -ErrorAction Stop
            $ADA = $XmlDocument.companies.$Company
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning('Unable to Find BRANCHES.XML, no Branch information will be added')
        }
        #variables to know if a EMS Credential has been set and is a known good
        $ADCredSet = $false
        $EMSCredSet = $false
        $ADSyncCredSet = $false
        #Check if the current user has permissions to make changes in AD
        if (!(Assert-ADPermission -Server $DomainController -AdminGroups $AdminGroups)) {
            Write-Verbose('Requesting Active credentials')
            # Skip this if WhatIf is specified
            if (!$WhatIfPreference) {
                # Request credentials from the user
                [pscredential]$ADCredentials = Get-Credential -Message 'Active Directory Credentials' -UserName ($Domain + '\')
                # Split the username from the domain so it can be fed into some functions later
                if ($ADCredentials.UserName -match '\\') {
                    $ADCredSamAccountName = $ADCredentials.UserName.Split('\')[1]
                }
                else { $ADCredSamAccountName = $ADCredentials.UserName }
                # Exit if no credentials provided
                if (!$ADCredentials) {
                    Write-Error('No AD credentials provided.')
                    exit
                    # If the new credentials are valid continue
                }
                if (Assert-ADPermission -Server $DomainController -AdminGroups $AdminGroups -Credential $ADCredentials -SamAccountName $ADCredSamAccountName) {
                    $ADCredSet = $true
                    # Check the provided credentials against other systems to cut down on amount of credentials that need to be entered in
                    if ($M365DeploymentType -eq 'Hybrid') {
                        if ((Assert-EMSPermission -Server $EMSServer -Credential $ADCredentials) -and ($M365DeploymentType -eq 'Hybrid')) {
                            $EMSCredentials = $ADCredentials
                            $EMSCredSet = $True
                        }
                    }
                    if (Assert-ADSyncPermission -Server $ADSyncServer -Credential $ADCredentials) {
                        $ADSyncCredentials = $ADCredentials
                        $ADSyncCredSet = $true
                    }               
                }
                else {
                    Write-Error('Exiting; Provided active directory credentials insufficient.')
                    exit                    
                }
            }
        }
        #Check if the current user or provided credentials are sufficient to get into the EMS Server
        if ($M365DeploymentType -eq 'Hybrid') {
            if (!(Assert-EMSPermission -Server $EMSServer) -and !$EMSCredentials) {
                Write-Verbose('Requesting Exchange management credentials.')
                if (!$WhatIfPreference) {
                    [pscredential]$EMSCredentials = Get-Credential -Message 'Exchange Management Credentials for '+$Server+' required'
                    if (!$EMSCredentials) {
                        Write-Error('No EMS credentials provided.')
                        exit
                    }
                    $EMSCredSet = $true
                }
            }
            elseif ($EMSCredentials -and !$EMSCredSet) {
                if (!(Assert-EMSPermission -Server $EMSServer -Credential $EMSCredentials)) {
                    Write-Verbose('Requesting Exchange management credentials.')
                    if (!$WhatIfPreference) {
                        $EMSCredentials = $null
                        [pscredential]$EMSCredentials = Get-Credential -Message 'Exchange Management Credentials for '+$Server+' required'
                        if (!$EMSCredentials) {
                            Write-Error('No EMS credentials provided.')
                            exit
                        }
                        $EMSCredSet = $true
                    }
                }
            }
        }
        #Check if the function is being used in a pipeline
        #Ask for ADSync credentials if it is
        if ($PSCmdlet.MyInvocation.ExpectingInput -and !$ADSyncCredentials -and !$ADSyncCredSet) {
            Write-Verbose('Pipeline input detected, requesting credentials for: ' + $ADSyncServer)
            if (!$WhatIfPreference) {
                [pscredential]$ADSyncCredentials = Get-Credential -Message ('Enter Credentials for: ' + $ADSyncServer)
                if (!$ADSyncCredentials) {
                    Write-Error('No ADSync credentials provided.')
                    exit
                }
                $ADSyncCredSet = $true
            }
        }
    }
    process {
        #region DataValidation
        #Create the username variable from the first and lastname.
        if ($Firstname -and $Lastname) {
            Write-Verbose('Setting Username')
            $SamAccountName = ($Firstname + '.' + $Lastname).ToLower()
            #Logic is lastname isnt specified.
        }
        elseif (!$Lastname) {
            $SamAccountName = $Firstname.ToLower()
            Write-Warning('No Lastname. Username will be set to Firstname')
        }
        if (!$PSCmdlet.MyInvocation.ExpectingInput) {
            Start-Logging -Path $CurrentPath -Name $SamAccountName
        }
        #Create the DisplayName for the user
        if ($Firstname -and $Lastname) {
            Write-Verbose('Creating Displayname')
            $DisplayName = $Firstname + ' ' + $Lastname
            #Logic is lastname isnt specified.
        }
        elseif (!$Lastname) {
            $DisplayName = $Firstname
            Write-Warning('No Lastname. Display name will be set to Firstname value')
        }
        #More data collection only if we arnt in a pipeline
        if ($Interactive -and !$PSCmdlet.MyInvocation.ExpectingInput) {
            Write-Verbose('Entering Interactive for user: ' + $SamAccountName)
            if (!$Branch) {
                Write-Verbose('No User Branch Entered')
                if ($ADA) {
                    $Branch = Show-CompanyBranches -Branches $ADA
                }
            }
            if (!$Title) {
                $Title = Read-Host 'User title'
            }
            if (!$Manager) {
                do {
                    $Finished = $false
                    try {
                        $Manager = Read-Host("Manager (first.lastname)") -ErrorAction Stop
                        $Finished = $true
                    }
                    catch [System.Management.Automation.ValidationMetadataException] {
                        Write-Warning('Invalid Input; username must be valid')
                        $Finished = $false
                    }
                    if (!$Manager) {
                        $Finished = $true
                    }
                    elseif (!(Assert-ADUExists -SamAccountName $Manager -Server $DomainController) -and $Finished -eq $true -and !$WhatIfPreference) {
                        $Finished = $false
                    }
                } until ($Finished -eq $true)
            }
            if (!$OfficePhone) {
                do {
                    $Finished = $false
                    try {
                        $OfficePhone = Read-Host("Office Phone Number") -ErrorAction Stop
                        $Finished = $true
                    }
                    catch [System.Management.Automation.ValidationMetadataException] {
                        Write-Warning('Invalid Input | Must be 4 numbers or blank')
                        $Finished = $false
                    }
                    if (!$OfficePhone -match '^[0-9]{10,10}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished = $false
                    }
                } until ($Finished -eq $true)
            }
            if (!$MobilePhone) {
                do {
                    $Finished = $false
                    try {
                        $MobilePhone = Read-Host("Mobile Phone Number") -ErrorAction Stop
                        $Finished = $true
                    }
                    catch [System.Management.Automation.ValidationMetadataException] {
                        Write-Warning('Invalid Input | Must be 10 numbers or blank')
                        $Finished = $false
                    }
                    if (!$MobilePhone -match '^[0-9]{4,4}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished = $false
                    }
                } until ($Finished -eq $true)
            }
            if (!$M365License) {
                do {
                    $Finished = $false
                    try {
                        $M365License = Read-Host("Office 365 License type") -ErrorAction Stop
                        $Finished = $true
                    }
                    catch [System.Management.Automation.ValidationMetadataException] {
                        Write-Warning('Invalid Input | Must E1 or E2 or E3 or blank')
                        $Finished = $false
                    }
                    if (!$M365License -match '^[E][0-3]{1}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished = $false
                    }
                } until ($Finished -eq $true)
            }
            if (!$FileServerAccess) {
                if (!(Test-UserContinue -Message 'File server access not granted. Press enter to confirm, or type any key (then press enter) to grant file access')) {
                    $fileserveraccess = $true
                    Write-Verbose('File server access set to True')
                }
                else {
                    $FileServerAccess = $false
                    Write-Verbose('File server access set to False')
                }
            }
            if (!(Test-UserContinue -Message 'User will be added to branch DL. Press enter to confirm, or type any other key (then press enter) to cancel')) {
                $DistributionList = $false
                Write-Verbose('user will not be added to Branch DL')
            }
            else {
                $DistributionList = $true
            }
            # Convert the string variables to booleans
            [boolean]$DistributionList = [system.convert]::ToBoolean($DistributionList)
            [boolean]$FileServerAccess = [system.convert]::ToBoolean($FileServerAccess)            
            # Splat containing Parameters for Testing Interactive Prompts
            $SplatTestInteractivePrompts = @{
                FileServerAccess = $FileServerAccess
                M365License      = $M365License
            }
            # Conditions to add items to the splat depending on input
            if ($InteractivePrompts) { $SplatTestInteractivePrompts.Add('InteractivePrompts', $InteractivePrompts) }
            if ($AutoMemberOf) { $SplatTestInteractivePrompts.Add('AutoMemberOf', $AutoMemberOf) }
            # Only Execute the Prompts if their is aleast one of the below
            if ($InteractivePrompts -or $AutoMemberOf) {
                # Store the results in the a variable
                [Array]$ResultsIP = @(Test-InteractivePrompts @SplatTestInteractivePrompts | Where-Object { $_ })
                If ($ResultsIP) {
                    $MemberOf.AddRange($ResultsIP)
                }
            }
        }
        #Check we can get the branch name.
        if (!$ADA.$Branch.name) {
            Write-Warning('Branch entered cannot be found, all values relying on it will be null') -ErrorAction Continue
        }
        #Turn the MemberOf variable to an array
        if ($MemberOf -contains ',' -and $MemberOf) {
            Write-Verbose('User is a MemberOf multiple groups, parsing groups.')
            [System.Collections.ArrayList]$MemberOf = $MemberOf.Split(',')          
        }
        elseif ($MemberOf -and $MemberOf -eq [System.String]) {
            [System.Collections.ArrayList]$MemberOf = @($MemberOf)
        }
        if ($PSCmdlet.MyInvocation.ExpectingInput) {
            [boolean]$DistributionList = [system.convert]::ToBoolean($DistributionList)
            [boolean]$FileServerAccess = [system.convert]::ToBoolean($FileServerAccess)    
        }
        #If FileServerAccess was set to True
        if ($FileServerAccess) {
            $null = $MemberOf.Add($ADA.$Branch.drive_group)
            Write-Verbose('Adding FileServerAccess to; ' + $ADA.$Branch.drive_group)
        }
        #If Distribution Group set to True
        if ($DistributionGroup) {
            $null = $MemberOf.Add($ADA.$Branch.distro)
            Write-Verbose('Adding Branch Distribution Group; ' + $ADA.$Branch.distro)
        }
        #If !Manager is Specified from Default
        if (!$Manager) {
            Write-Verbose('Alternate manager not specified, using branch default')
            $Manager = $ADA.$Branch.manager
        }
        #If file server access isnt granted dont add the logon script
        if (!$FileServerAccess) {
            $logonscript = $false
        }
        elseif ($FileServerAccess) {
            Write-Verbose('Adding login script from Selected Branch')
            $logonscript = $ADA.$Branch.logonscript
        }
        if ($MemberOf.count -gt 1) { $MemberOf = $MemberOf | Sort-Object -Property @{Expression = { $_.Trim() } } -Unique }
        
        #Set variables for the Splat
        [string]$UserprincipalName = $SamAccountName + $EmailDomain
        #region Splatter
        #Assembled Splat for Exchange Command
        [HashTable]$SplatExchange = @{
            Name                         = $DisplayName
            Password                     = $Password
            UserPrincipalName            = $UserprincipalName
            Alias                        = $SamAccountName
            DisplayName                  = $DisplayName
            Firstname                    = $Firstname
            Lastname                     = $Lastname
            OnPremisesOrganizationalUnit = $ADA.$Branch.ou
            SamAccountName               = $SamAccountName
            Archive                      = $true
            DomainController             = $DomainController
            Whatif                       = $WhatIfPreference
        }
        #Set the AD Attributes for the new user
        #This splat is used when a cloud deployed is set
        [HashTable]$SplatADNewUser = @{
            Name              = $DisplayName
            AccountPassword   = $Password
            UserPrincipalName = $UserprincipalName
            DisplayName       = $DisplayName
            GivenName         = $Firstname
            Surname           = $Lastname
            Path              = $ADA.$Branch.ou
            SamAccountName    = $SamAccountName
            Server            = $DomainController
            Whatif            = $WhatIfPreference
            Office            = $ADA.$Branch.office
            State             = $ADA.$Branch.state
            Company           = $ADA.$Branch.company
            Manager           = $Manager
            Department        = $ADA.$Branch.department
            City              = $ADA.$Branch.city
            Country           = $ADA.$Branch.country
            ScriptPath        = $logonscript
            PostalCode        = $ADA.$Branch.post_code
            POBox             = $ADA.$Branch.po_box
            StreetAddress     = $ADA.$Branch.street
            OfficePhone       = $OfficePhone
            MobilePhone       = $MobilePhone
            Title             = $Title
            Enabled           = $true
            EmailAddress      = $UserprincipalName
        }
        #Set the AD Attributes for the new user
        #this splat isused when a Hybrid deployment is specified
        [HashTable]$SplatADAttributes = @{
            server        = $DomainController
            Identity      = $SamAccountName
            Office        = $ADA.$Branch.office
            State         = $ADA.$Branch.state
            Company       = $ADA.$Branch.company
            Manager       = $Manager
            Department    = $ADA.$Branch.department
            City          = $ADA.$Branch.city
            Country       = $ADA.$Branch.country
            ScriptPath    = $logonscript
            PostalCode    = $ADA.$Branch.post_code
            POBox         = $ADA.$Branch.po_box
            StreetAddress = $ADA.$Branch.street
            OfficePhone   = $OfficePhone
            MobilePhone   = $MobilePhone
            Title         = $Title
            Whatif        = $WhatIfPreference
        }
        #Splat containing AD groups the user will be added to
        [HashTable]$SplatADGroups = @{
            Identity = $SamAccountName
            Groups   = $MemberOf
            Server   = $DomainController
            Whatif   = $WhatIfPreference
        }
        #Splat for Get ad user after initial creation
        [HashTable]$SplatADGetUser = @{
            Server     = $DomainController
            Identity   = $SamAccountName
            Properties = "Office", "State", "Company", "Manager", "Department", "City", "Country", "ScriptPath", "PostalCode", "POBox", "StreetAddress", "OfficePhone", "MobilePhone", "Title"
        }
        #Splat for Checking if the AD User is synced
        [HashTable]$SplatADUserSynced = @{
            SamAccountName = $SamAccountName
            Server         = $DomainController
            Whatif         = $WhatIfPreference
        }
        #endregion Splatter
        #if no OU is set. Set one. Cannot continue otherwise
        if (!$SplatExchange.OnPremisesOrganizationalUnit) {
            $SplatExchange.OnPremisesOrganizationalUnit = $FallbackUserOU
            Write-Warning('No user OU Set! | Placing them in: ' + $FallbackUserOU)
        }
        #We've got to remove any null or empty values from the hastable
        Write-Verbose("Cleaning AD splat of empty values")
        foreach ($Key in @($SplatADAttributes.Keys) ) {
            if (-not $SplatADAttributes[$Key]) {
                $SplatADAttributes.Remove($Key)
                Write-Verbose("SplatADAttributes: Removed Empty Key: " + $Key)
            }

        }
        foreach ($Key in @($SplatADNewUser.Keys) ) {
            if (-not $SplatADNewUser[$Key]) {
                $SplatADNewUser.Remove($Key)
                Write-Verbose("SplatADNewUser: Removed Empty Key: " + $Key)
            }

        }        
        #endregion DataValidation
        #region DataConfirmation
        #Chance to confirm some account details
        if ($Interactive -and !$PSCmdlet.MyInvocation.ExpectingInput) {
            Write-Verbose('------------------------------')
            Write-Verbose('Active Directory Details')
            Write-Verbose('------------------------------')
            if ($M365DeploymentType -eq 'Hybrid') { $SplatADAttributes | Format-table -Verbose }else { $SplatADNewUser | Format-table -Verbose }
            Write-Verbose ('------------------------------')
            Write-Verbose('AD Group Details')
            Write-Verbose('------------------------------')
            $MemberOf | Format-List -Verbose
            Write-Verbose('------------------------------')
            if ($M365DeploymentType -eq 'Hybrid') {
                Write-Verbose('Exchange Details')
                Write-Verbose('------------------------------')
                $SplatExchange | Format-table -Verbose
                Write-Verbose('------------------------------')
            }
            if (!(Test-UserContinue -Message 'Above are the details for the user to be created, if the details are correct proceed otherwise cancel')) {
                Write-Verbose('User Cancelled Terminating')
                Stop-Transcript
                Exit
            }
        }
        #endregion DataConfirmation
        #Check if the current user has permissions to make changes in AD
        if ($ADCredSet) {
            Write-Verbose('Adding provided Active Credentials credentials to Splats')
            $SplatADAttributes.Add('Credential', $ADCredentials)
            $SplatADGetUser.Add('Credential', $ADCredentials)
            $SplatADGroups.Add('Credential', $ADCredentials)
            $SplatADUserSynced.Add('Credential', $ADCredentials)
            $SplatADNewUser.Add('Credential', $ADCredentials)
        }
        #All Variables have been collected and formatted how we wanted. Now lets make the account.
        #region Hybrid
        if ($M365DeploymentType -eq 'Hybrid') {
            if (!(Assert-EMSUExists -SamAccountName $SamAccountName -Server $EMSServer -Credential $EMSCredentials -WhatIf:$WhatIfPreference)) {
                Write-Verbose('This user will be created using Microsoft 365 Hybrid deployment.')
                Write-Verbose($SamAccountName + ' does not exists on EMS; proceeding')
                if ($PSCmdlet.ShouldProcess($EMSServer, 'New-RemoteMailbox -Password "' + $SplatExchange.Password + '" -Name "' + $SplatExchange.Name + '" UserprincipalName "' + $SplatExchange.UserPrincipalName + '" Alias "' + $SplatExchange.Alias + '" DisplayName "' + $SplatExchange.DisplayName + '" Firstname "' + $SplatExchange.Firstname + '" Lastname "' + $SplatExchange.Lastname + '" OnPremisesOrganizationalUnit "' + $SplatExchange.OnPremisesOrganizationalUnit + '" SamAccountName "' + $SplatExchange.SamAccountName + '" Archive "' + $SplatExchange.Archive + '" DomainController "' + $SplatExchange.DomainController)) {
                    New-RemoteMailbox @SplatExchange -ErrorAction Stop
                }
                #Wait for the user to Sync then set user attributes
                if ((Wait-ADUSynced @SplatADUserSynced) -or $WhatIfPreference) {
                    Write-Verbose('Found "' + $SamAccountName + '" in AD updating user Attributes')
                    if ($PSCmdlet.ShouldProcess($DomainController, 'Set-ADUser -Server "' + $SplatADAttributes.Server + '" -Identity "' + $SplatADAttributes.Identity + '" -Office "' + $SplatADAttributes.Offic + '" -State "' + $SplatADAttributes.State + '" -Company "' + $SplatADAttributes.Company + '" -Manager "' + $SplatADAttributes.Manager + '" -Department "' + $SplatADAttributes.Department + '" -City "' + $SplatADAttributes.City + '" -Country "' + $SplatADAttributes.Country + '" -ScriptPath "' + $SplatADAttributes.ScriptPath + '" -PostalCode "' + $SplatADAttributes.PostalCode + '" -POBox "' + $SplatADAttributes.POBox + '" -StreetAddress "' + $SplatADAttributes.StreetAddress + '" -OfficePhone "' + $SplatADAttributes.OfficePhone + '" -MobilePhone "' + $SplatADAttributes.MobilePhone + '" -Title "' + $SplatADAttributes.Title)) {                
                        Set-ADUser @SplatADAttributes
                        Get-ADUser @SplatADGetUser
                    }
                    #Add the user to specified groups
                    if ($MemberOf) {
                        Set-ADUGroups @SplatADGroups
                    }
                    else {
                        Write-Verbose('No groups specified')
                    }
                }
                #Start an Delta Sync on AzureAD Connect
                $CurrentUser = (whoami /UPN)
                if (!$CurrentUser.contains($EmailDomain)) {
                    Write-Verbose('RunAs User Email Domain does not contain: ' + $EmailDomain)
                    Write-Verbose('AzureAD Connection Credentials will need to be manually entered')
                    Test-AADConnected -CredentialPrompt -WhatIf:$false
                }
                Write-Verbose('Starting AzureAD Connect Sync')
                if ((Sync-Directories -Server $ADSyncServer -Credential $ADSyncCredentials -AzureActiveDirectory -ErrorAction Stop -Whatif:$WhatIfPreference) -or $WhatIfPreference) {
                    if ((Wait-AADUSynced -UserPrincipalName $UserprincipalName -Whatif:$WhatIfPreference) -or $WhatIfPreference) {
                        if ($M365License) {
                            Write-Verbose('Trying to assign a ' + $M365License + ' License to ; ' + $UserprincipalName)
                            if ( !(Set-AADULicense -UserPrincipalName $UserprincipalName -LicenseType $M365License -Whatif:$WhatIfPreference) -and $Interactive) {
                                Test-UserContinue -Message 'No Microsoft 365 License assigned. Press any key to continue'
                            }
                        }
                        Write-Verbose('Setting user MFA')                      
                        Set-MSolUMFA -UserPrincipalName $UserprincipalName -StrongAuthenticationRequiremets $StrongAuthenticationRequiremets -Whatif:$WhatIfPreference
                    }
                }
                else {
                    Write-Verbose('No license specified for user, nothing will be assigned')
                }
            }
            else {
                Write-Warning($SamAccountName + ' already exists on EMS; skipping')
            }
        }
        #endregion Hybrid
        #Region Cloud
        if (!(Assert-ADUExists -SamAccountName $SamAccountName -Server $DomainController -Credential $EMSCredentials -WhatIf:$WhatIfPreference) -and ($M365DeploymentType -eq 'Cloud')) {
            Write-Verbose('This user will be created using Microsoft 365 Cloud deployment.')
            Write-Verbose($SamAccountName + ' does not exists on AD; proceeding')
            if ($PSCmdlet.ShouldProcess($DomainController, 'New-ADuser -Password "' + $SplatADNewUser.AccountPassword + '" -Name "' + $SplatADNewUser.Name + '" UserprincipalName "' + $SplatADNewUser.UserPrincipalName + '" DisplayName "' + $SplatADNewUser.DisplayName + '" GivenName "' + $SplatADNewUser.GivenName + '" Surname "' + $SplatADNewUser.Surname + '" Path "' + $SplatADNewUser.Path + '" SamAccountName "' + $SplatADNewUser.SamAccountName + '" Server "' + $SplatADNewUser.Server + ' -Office "' + $SplatADNewUser.Office + '" -State "' + $SplatADNewUser.State + '" -Company "' + $SplatADNewUser.Company + '" -Manager "' + $SplatADNewUser.Manager + '" -Department "' + $SplatADNewUser.Department + '" -City "' + $SplatADNewUser.City + '" -Country "' + $SplatADNewUser.Country + '" -ScriptPath "' + $SplatADNewUser.ScriptPath + '" -PostalCode "' + $SplatADNewUser.PostalCode + '" -POBox "' + $SplatADNewUser.POBox + '" -StreetAddress "' + $SplatADNewUser.StreetAddress + '" -OfficePhone "' + $SplatADNewUser.OfficePhone + '" -MobilePhone "' + $SplatADNewUser.MobilePhone + '" -Title "' + $SplatADNewUser.Title)) {
                New-ADUser @SplatADNewUser -ErrorAction Stop
                Get-ADUser @SplatADGetUser
            }
            #Wait for user to Sync to Active Directory
            if ((Wait-ADUSynced @SplatADUserSynced) -or $WhatIfPreference) {
                if ($MemberOf) {
                    Set-ADUGroups @SplatADGroups
                }
                else {
                    Write-Verbose('No groups specified')
                }
            }
            #Start an Delta Sync on AzureAD Connect
            $CurrentUser = (whoami /UPN)
            if (!$CurrentUser.contains($EmailDomain)) {
                Write-Verbose('RunAs User Email Domain does not contain: ' + $EmailDomain)
                Write-Verbose('AzureAD Connection Credentials will need to be manually entered')
                Test-AADConnected -CredentialPrompt -whatif:$False
            }
            Write-Verbose('Starting AzureAD Connect Sync')
            if ((Sync-Directories -Server $ADSyncServer -Credential $ADSyncCredentials -AzureActiveDirectory -ErrorAction Stop -Whatif:$WhatIfPreference) -or $WhatIfPreference) {
                if ((Wait-AADUSynced -UserPrincipalName $UserprincipalName -Whatif:$WhatIfPreference) -or $WhatIfPreference) {
                    if ($M365License) {
                        Write-Verbose('Trying to assign a ' + $M365License + ' License to ; ' + $UserprincipalName)
                        if ( !(Set-AADULicense -UserPrincipalName $UserprincipalName -LicenseType $M365License -Whatif:$WhatIfPreference) -and $Interactive) {
                            Test-UserContinue -Message 'No Microsoft 365 License assigned. Press any key to continue'
                        }
                    }
                    Write-Verbose('Setting user MFA')                      
                    Set-MSolUMFA -UserPrincipalName $UserprincipalName -StrongAuthenticationRequiremets $StrongAuthenticationRequiremets -Whatif:$WhatIfPreference
                }
            }
            else {
                Write-Verbose('No license specified for user, nothing will be assigned')
            }
        }
        else {
            Write-Warning($SamAccountName + ' already exists in AD; skipping')
        }
        #endregion Cloud
    }
    end { Stop-Transcript }
}