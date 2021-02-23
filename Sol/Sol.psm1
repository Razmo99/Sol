function Test-AADConnected{
    <#
    .SYNOPSIS
    Checks if a connection to AzureAD is Present
    .DESCRIPTION
    Checks if a connection to AzureAD is Present. If its not initiate one.
    This is a Boolean function, and should be used as such
    .PARAMETER UserPrincipalName
    UserprincipalName to connect to AzureAD With
    .PARAMETER CredentialPromp
    Switch to allow manual entry of Credentials
    .PARAMETER NoRetry
    If an error occurs doesnt prompt to retry
    .OUTPUTS
    system.boolean $True for connected $False for not
    .INPUTS
    system.string UserprincipalName
    #>
    #Requires -module AzureAD
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$UserPrincipalName,
        [Parameter(Mandatory=$false)][switch]$CredentialPrompt,
        [Parameter(Mandatory=$false)][switch]$NoRetry
    )
    Begin{}
    Process{
        [HashTable]$ConnectAADSplat = @{}
        if ($UserPrincipalName) {
            $ConnectAADSplat = @{
                AccountId = $UserPrincipalName
                ErrorAction = 'Stop'
            }
        }elseif ($CredentialPrompt) {
            $ConnectAADSplat = @{
                ErrorAction = 'Stop'
            }
        }else{
            $ConnectAADSplat = @{
                AccountId = (whoami /UPN)
                ErrorAction = 'Stop'
            }
        }
        try{
            if((Get-AzureADCurrentSessionInfo -ErrorAction Stop).Environment.Name -eq 'AzureCloud') {
                Write-Verbose('AzureAD Session open continuing')
            }else{
                return $false
            }
        }
        catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            try{
                Write-Verbose('Connecting to Azure AD.')
                Connect-AzureAD @ConnectAADSplat | Out-Null
            }
            catch {
                Write-Error($_.Exception.Message)
                if(!$NoRetry){
                    $response = read-host "Press enter to try again or any other key (and then enter) to abort"
                    $aborted = ! [bool]$response
                    if(!$aborted){
                        Write-Warning('Aborted by user.')
                        return $false
                    }else{
                        Test-AADConnected
                    }
                }
            }

        }
    }
    End{
        #Check User have perms
        $AADCurrentSessionInfo = (Get-AzureADCurrentSessionInfo -ErrorAction Stop).Account.id
        $AADDirectoryRole = (Get-AzureADDirectoryRole | Where-Object -Property DisplayName -eq 'Global Administrator').ObjectId
        if(!(Get-AzureADDirectoryRoleMember -ObjectId $AADDirectoryRole).UserPrincipalName.contains($AADCurrentSessionInfo)){
            Write-Warning('Insufficient Permissions')
            Disconnect-AzureAD
            Write-Verbose('Prompting for alternative credential.')
            Test-AADConnected -CredentialPrompt
        }else{
            return $true
        }        
    }
}

function Test-MSolConnected {
    <#
    .SYNOPSIS
    Checks if a connection to Msol is Present
    .DESCRIPTION
        Just runs a command if it doesnt error return true
    .OUTPUTS
        system.boolean
    .INPUTS
     None
    #>
    try {
        Get-MsolCompanyInformation -ErrorAction Stop | Out-Null
        return $true         
    }catch {
        return $false
    }
}

function Test-UserContinue {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage='Just a message about what we are skipping or entering info for.')][String]$Message
    )
    if ($Message) {
        $response = read-host $Message
    }else{
    $response = read-host "Press enter to confirm; or any other key (and then enter) to exit."
    }
    $aborted = ! [bool]$response
    if(!$aborted){
        return $false
    }else{
        return $true
    }
}

function Set-MSolUMFA{
    <#
    .SYNOPSIS
    Sets MFA Status on a User
    .DESCRIPTION
    Checks if a connection to Msol is Present. If its not initiate one.
    Checks the UserPrincipalName Exists to Msol, if it does sets the StrongAuthenticationRequirements
    .PARAMETER UserPrincipalName
    UserprincipalName Use to Set MFA Enforced on
    .PARAMETER StrongAuthenticationRequirements
    StrongAuthenticationRequirements Required level of MFA
    .OUTPUTS
    system.boolean
    .INPUTS
    system.string UserprincipalName
    system.string StrongAuthenticationRequirements Level of MFA to set
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateSet('Enabled','Disabled','Enforced')][String]$StrongAuthenticationRequirements
    )
    begin{
        # Check if connected to Msol Session already
        if(!$WhatIfPreference){
            if (!(Test-MSolConnected)) {
                Write-Verbose('No existing Msol session detected')
                try {
                    Write-Verbose('Initiating Connection to Msol')
                    Connect-MsolService -ErrorAction Stop
                    Write-Verbose('Connected to Msol successfully')
                }catch{
                    return Write-Error($_.Exception.Message)
                }
            }
        }
    }
    Process{
        # Get the time and calc 2 min to the future
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(1)
        $Finished=$false
        #Loop to check if the user exists already
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "StrongAuthenticationRequirements = "+$StrongAuthenticationRequirements)) {
            do {
                $TimeNow = Get-Date
                #Primary check for success condition
                if (Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue) {
                    $Finished = $true
                    Write-Verbose('Found '+$UserPrincipalName+' In Msol')
                    Write-Verbose('Attempting to Set MFA Status to: '+$StrongAuthenticationRequirements)
                    # Set some variables for MFA enforcement
                    $st = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
                    $st.RelyingParty = "*"
                    $st.State = $StrongAuthenticationRequirements
                    $sta = @($st)
                    # Execute final command
                    try {
                        Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationRequirements $sta -ErrorAction Stop
                        Write-Verbose('Set MFA Command Executed')
                        return $true
                    }
                    catch {
                        Write-Error($_.Exception.Message)
                    }                
                # if 1 minutes passes we just tap out and return false
                }elseif($TimeNow -ge $TimeEnd){
                    $Finished = $true
                    Write-Verbose('Failed to find user in Msol')
                    Write-Warning('MFA Will not be set')
                    return $false
                }else {
                    Start-Sleep -Seconds 5
                    Write-Verbose('Sleeping 5 second')
                } 
            } until ($Finished -eq $true) 
        }      
    }
    End{}
}

function Import-EMS {
    <#
    .SYNOPSIS
    Checks if a connection to Exchange Management Shell is Present
    .DESCRIPTION
    Checks if a connection to Exchange Management Shell is Present. If its not initiate one.
    This is a Boolean function, and should be used as such
    .PARAMETER Server
    Server FQDN that has Exchange Management Shell installed on.
    .PARAMETER Credential
    Credentials for the PSSession
    .PARAMETER EMSAuth
    Type of Auth to use when inititating the PSSession
    .OUTPUTS
    system.boolean $True for connected $False for not
    .INPUTS
    None
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [parameter(Mandatory=$true)][String]$Server,
        [parameter(Mandatory=$false)][String][Validateset('Default','Basic','Credssp','Digest','Kerberos','Negotiate','NegotiateWithImplicitCredential')]$EMSAuth = "Kerberos",
        [parameter(Mandatory=$false)][pscredential]$Credential
    )
    #Try to Import the EMS Module for Later use
    $CheckExistingSession = Get-PSSession | Where-Object {$_.State -eq 'Opened' -and $_.ConfigurationName -eq 'Microsoft.Exchange'}
    #Check if a PSsession is already open.
    if (!$CheckExistingSession) {
        Try{
            #Splatter for New PS Session
            [hashtable]$SplatNewPSSession = @{
                ConfigurationName = 'Microsoft.Exchange'
                ConnectionUri = 'http://'+$Server+'/Powershell'
                Authentication = $EMSAuth
                ErrorAction = 'Stop'
            }
            #Add Credentials if presented
            if ($Credential) {
                Write-Verbose('Credentials provided')
                $SplatNewPSSession.Add('Credential',$Credential)
            }
            #Whatif functionality
            if ($PSCmdlet.ShouldProcess($Server, 'Import-PSSession')) {
                Write-Verbose ('Attempting to Connect to '+ $Server +' Using '+ $EMSAuth +' For Authentication')
                $EMS = New-PSSession @SplatNewPSSession
                Write-Verbose ('Importing Modules')
                #This is done to get the imported functions into the global name space
                Import-Module(Import-PSSession $EMS -DisableNameChecking -AllowClobber -ErrorAction Stop -CommandName Get-RemoteMailbox,New-RemoteMailbox) -Global
                return $true
            }

        }
        #Catch for creds with out permission
        catch [System.Management.Automation.Remoting.PSRemotingTransportException]{
            #check the exception message to see if it was an access denied
            if ($_.Exception.Message.contains("AuthZ-CmdletAccessDeniedException")) {
                Write-Warning("Failed to connect to EMS server with logged in account creds prompting for alternative creds")
                $EMSCreds = Get-Credential -Message "Enter EMS Admin Credentials"
                #Try import EMS Modules again with provided credentials | same try catch as above
                try {
                    if ($PSCmdlet.ShouldProcess($Server, 'Import-PSSession')) {
                        Write-Verbose ('Attempting to Connect to '+ $Server +' Using '+ $EMSAuth +' For Authentication')
                        $EMS = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri ('http://'+$Server+'/Powershell') -Authentication $EMSAuth -ErrorAction Stop -Credential $EMSCreds
                        Write-Verbose ('Importing Modules')
                        Import-Module(Import-PSSession $EMS -DisableNameChecking -AllowClobber -ErrorAction Stop -CommandName Get-RemoteMailbox,New-RemoteMailbox) -Global
                        return $true
                    }
                }
                catch {
                    #We don't get a 3rd chance.
                    write-Error($_.Exception.Message)
                    return $false  
                }
            #If we dont get what we expect terminate
            }else {
                Write-Error("unhandled error :(")
                exit
            }
        }
        Catch{
            Write-Warning('Failed to connect to Exchange Server ' + $Server)
            write-warning($_.Exception.Message)
            return $false
        }
    }
    # We should be connect to EMS at this point. Lets check
    if ($PSCmdlet.ShouldProcess("LocalHost", "Get-Command New-RemoteMailbox")) {
        [bool]$CheckEMSCommandPresent = Get-Command New-RemoteMailbox -ErrorAction SilentlyContinue
        if(!$CheckEMSCommandPresent){
            Write-Verbose('Unable to get EMS Commands')
            if ($CheckExistingSession) {
                Write-Verbose('Removing stale PSSession')
                $CheckExistingSession | Remove-PSSession
                [HashTable]$SplatRetry = @{Server=$Server}
                if($Credential){$SplatNewPSSession.Add('Credential',$Credential)}
                Import-EMS @SplatRetry
            }
            return $false
        }elseif($CheckExistingSession) {
            Write-Verbose('EMS Session Already Present')
            return $true
        }
    }

}

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
    #Requires  -module AzureAD
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Alias('Email')][string]$UserPrincipalName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateSet('E1','E2','E3')][String]$LicenseType,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$CountryCode='AU'
    )
    Begin{
        #Ensure AzureAD is Connected
        if (!(Test-AADConnected -whatif:$false)) {
            Write-Error('No AzureAD Connection')
            return
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
            Write-Verbose(($LicenseInfo.prepaidunits.enabled).ToString() + ' PrePaid | '+ ($LicenseInfo.consumedunits).ToString() + ' Consumed')
            return
        }else {
            Write-Error -Message 'Unhandled Exception'
        }
    }
    End{}
}

Function Get-AADULicense{
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
    #Requires  -module AzureAD
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName
    )
    Begin{        
        if (!(Test-AADConnected -whatif:$false)) {
        Write-Error -Message 'No AzureAD Connection'
        return
        }
        $SkuInfo = Get-AzureADSubscribedSku
    }
    Process{
        [System.Collections.ArrayList]$LicenseArray=@()
        $AssignedLicenses = (Get-AzureADUser -ObjectId $UserPrincipalName).AssignedLicenses
        foreach($License in $AssignedLicenses){
            if ($SkuInfo.SkuId -contains $License.SkuID) {
                $Key = $SkuInfo.SkuId.IndexOf($License.SkuId)
                $null = $LicenseArray.Add($SkuInfo[$Key].SkuPartNumber)
            }   
        }
        [PSCustomObject]@{
            UserPrincipalName=$UserPrincipalName
            SkuPartNumber=$LicenseArray
        }
        #>
    }
    End{}
}

function Show-CompanyBranches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do{
        Write-Host('Branches')
        Write-Host('--------')
        Write-Host(($Branches.selectNodes("//name") | Format-Table -HideTableHeaders | Out-String).Trim())
        $UserBranch = Read-Host -Prompt 'Enter User Branch?'
        if ($Branches.$UserBranch.name -contains $UserBranch) {
        }else {
            Write-Warning('Could not find a match try again;')
        }  
    } until ($Branches.$UserBranch.name -contains $UserBranch)
    Write-Host('-------------- Verify Details ----------------')
    Write-Host(($Branches.$UserBranch | Format-List | Out-String).Trim())
    Write-host('-------------- Verify Details ----------------')
    #Provide oppertunity to abort the script if the details are incorrect etc
    $response = read-host "Press enter to continue or any other key (and then enter) to abort"
    $aborted = ! [bool]$response
    if(!$aborted){
        Write-Warning('Script Aborted Exiting')
        Exit
    }else{
        return $UserBranch
    }

}

function Assert-ADUExists {
    <#
    .SYNOPSIS
    Asserts if a user exists in Active Directory
    .DESCRIPTION
    Asserts if a user exists in Active Directory, 
    returns true if they do, and false if they do not.
    .PARAMETER SamAccountName
        system.string Attribute of the Active Directory account to match
        E.G 'firstname.lastname'
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER Credential
        pscredentials Used to authenticate to the designated Domain Controller
    .INPUTS
        system.string for SamAccountName
        System.pscredential for Credential
        system.string for server
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    #Requires -module ActiveDirectory
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$SamAccountName,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    begin {}
    process {
        $SplatADGetUser =@{
            ErrorAction = 'SilentlyContinue'
            Server = $Server
            Filter = { SamAccountName -eq $SamAccountName }
        }
        #WhatIf 
        if ($PSCmdlet.ShouldProcess($Server, 'Get-ADUser Filter { SamAccountName '+$SamAccountName+' }')) {
            #if Provided add credentials to the splat
            if ($Credential) {$SplatADGetUser.Add("Credential",$Credential)}
            #Test if the provided person already exists on ActiveDirectory
            if ([bool] (Get-ADUser @SplatADGetUser)) {
                Write-Verbose ('Found '+$SamAccountName+' in AD')
                return $true
            }else {
                Write-Verbose (' could not find '+$SamAccountName+' in AD')
                return $false
            }  
        }
    }
    end {}
}

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
    #Requires -module AzureAD
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName
    )
    begin {
        if (!(Test-AADConnected -whatif:$false)) {
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

function Assert-EMSUExists {
    <#
    .SYNOPSIS
    Asserts if a user exists in Active Directory
    .DESCRIPTION
    Asserts if a user exists in Active Directory, 
    returns true if they do, and false if they do not.
    .PARAMETER SamAccountName
        system.string Attribute of the Active Directory account to match
        E.G 'firstname.lastname'
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER Credential
        pscredentials Used to authenticate to the designated Exchange Management Server
    .INPUTS
        system.string for SamAccountName
        System.pscredential for Credential
        system.string for server
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$SamAccountName,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    
    begin {
        #if Provided add credentials to the splat
        [hashtable]$SplatImportEMS =@{
            Server=$Server
        }
        if ($Credential) {$SplatImportEMS.Add("Credential",$Credential)}
        if(!$WhatIfPreference){
            if (!(Import-EMS @SplatImportEMS -whatif:$false)) {
                Write-Error -Message 'No EMS Connection'
                return
            }
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Get-RemoteMailbox')) {
        #Test if the provided person already exists on Exchange
            [bool]$GetRM = Get-RemoteMailbox $SamAccountName -ErrorAction SilentlyContinue
            if($GetRM){ Write-Verbose($SamAccountName + ' already has a mailbox in Exchange') 
            return $true
            }else {
                Write-Verbose ('User '+$SamAccountName+' could not be found in Exchange')
                return $false
            }
        }
    }
    
    end {}
}

function Assert-SufficientPermission {
    <#
    .SYNOPSIS
    Asserts the current user is parts of the specified admin groups
    .DESCRIPTION
    retreives the current users AD Groups and matches it against the provided admin groups for a match
    returns true for a match and false for no match
    .PARAMETER AdminGroups
        ADGroup Names to match against
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .INPUTS
        system.array for Admin Groups
        system.string for server
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    #Requires -module ActiveDirectory
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$Server,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][array]$AdminGroups
    )
    $SamAccountName = (whoami).split('\')
    $SplatGetADPrince =@{
        Identity = $SamAccountName[1]
        Server = $Server
        ErrorAction = 'stop'
    }
    if ($PSCmdlet.ShouldProcess($SamAccountName, "Compare-Object"+$AdminGroups)) {
        try {
            #Get the groups that the current user is a member of
            $MemberOf = Get-ADPrincipalGroupMembership @SplatGetADPrince  | Select-Object SamAccountName
            #Compare the groups agains the provided admin groups
            $ComparedResults = Compare-Object -ReferenceObject $AdminGroups -DifferenceObject $MemberOf.samaccountname -IncludeEqual
            #Check each result for a match
            foreach($Result in $ComparedResults){
                # if a match is found return true and break the loop
                if ($Result.SideIndicator -eq "==") {
                    Write-Verbose('User has sufficient perms continuing')
                    return $true
                    break
                }
            }
        }catch [Microsoft.ActiveDirectory.Management.ADException]{
            #Evidently the user doesnt have access to AD, as they are unable to get what groups they are a memeber of
            Write-Verbose('User has insufficient perms continuing')
            return $false
        }catch{
            #Just a catch in the event of something unexpect happens
            Write-Error($_.Exception.Message)
        }
        # If the foreach loop doesnt return/break the function return false as no match was found
        return $false
        Write-Verbose('User has insufficient perms continuing')
    }
}

function Sync-Directories{
    <#
    .SYNOPSIS
    Sync AD or AAD with each other
    .DESCRIPTION
    Can sync all domain controllers in a forest, Can also start a delta sync on Azure Active Directory Connector
    .PARAMETER Credentials
        ADGroup Names to match against
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER ActiveDirectory
        Switch to sync ActiveDirectory
    .PARAMETER AzureActiveDirectory
        Switch to Sync Azure Active Directory Connector
    .INPUTS
        None.
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0,Mandatory=$false)][pscredential]$Credential,
        [Parameter(Mandatory=$true)][string]$Server,
        [switch]$AzureActiveDirectory,
        [switch]$ActiveDirectory
    )
    if (!$WhatIfPreference) {
        if (!$Credential) {
            $Credential = Get-Credential -Message ('Enter Credentials for '+$Server)
            if (!$Credential) {
                return Write-Error('No Credentials Provided')
            }
        }
    }
    if($ActiveDirectory) {
        $ADReplicate = {
            $DCSession = New-PSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $DCSession -ScriptBlock { 
                Import-Module -Name 'ActiveDirectory'
                Write-Output ('Syncing all DC held on '+$Server)
                repadmin.exe /syncall /AdeP | Out-Null
                Write-Output 'SyncAll Completed'
            }
            Remove-PSSession $DCSession
        }
        Write-Verbose('Syncing Domain Controllers')
        if ($PSCmdlet.ShouldProcess($Server, "repadmin.exe /syncall /AdeP")) {
            if((Invoke-Command $ADReplicate -ErrorAction Stop).Result -eq 'Success'){
                return $true
            }else{
                return $false
            }    
        }
    }elseif($AzureActiveDirectory){
        $AADConnectSync = {
            $AADConnectSession = New-PSSession -ComputerName $Server -Credential $Credential
            Invoke-Command -Session $AADConnectSession -ScriptBlock {
                $VerbosePreference='Continue'
                Import-Module -Name 'ADSync' -Function Get-ADSyncConnectorRunStatus,Start-ADSyncSyncCycle
                $TimeStart = Get-Date
                $TimeEnd = $timeStart.addminutes(2)
                $Finished=$false
                do {
                    $TimeNow = Get-Date
                    if (!(Get-ADSyncConnectorRunStatus)) {
                        try{
                            Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
                            $Finished = $true
                            return $true
                        }catch [System.Management.Automation.RuntimeException]{
                            Write-Verbose('Sync is already running. Cannot start a new run till this one completes.')
                            $Finished = $false
                        }catch{
                            Write-Verbose($_.Exception.Message)
                        }
                    }elseif($TimeNow -ge $TimeEnd){
                        $Finished = $true
                        Write-Warning('Searched for 2 minute Exiting...')
                        Write-Warning('Azure AD is still Busy.')
                        Write-Error('User Creation will no continue past this point')
                        return $false
                    }else {
                        Write-Verbose('Sleeping 10 second')
                        Start-Sleep -Seconds 10
                    }
                } until ($Finished -eq $true)
            }
            Remove-PSSession $AADConnectSession
        }
        if ($PSCmdlet.ShouldProcess($Server, "Start-ADSyncSyncCycle -PolicyType Delta")) {
            Write-Verbose('Syncing ADConnect')
            $PSIResult = Invoke-Command $AADConnectSync -ErrorAction Stop
            if ($PSIResult) {
                return $true
            }else{
                return $false
            }

        }

    }elseif(!$AzureActiveDirectory -and !$ActiveDirectory) {
        return Write-Error('No System switch specified')
    }else{
        return $false
    }
}

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
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$SamAccountName,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    Begin{}
    Process{
        #Hash table for the assert user function.
        [HashTable]$SplatUserExists= @{
            SamAccountName = $SamAccountName
            Server = $Server
            ErrorAction = 'SilentlyContinue'
        }
        #If Credentials add them to the splat
        if($Credentials){$SplatUserExists.Add('Credential',$Credential)}
    
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(1)
        $Finished=$false
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Check UserSynced")) {
            do {
                $TimeNow = Get-Date
                if (Assert-ADUExists @SplatUserExists) {
                    $Finished = $true
                    Write-Verbose('Found '+$SamAccountName+' In AD')
                    return $true
                }elseif($TimeNow -ge $TimeEnd){
                    $Finished = $true
                    Write-Warning('Searched for 1 minute Exiting...')
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

function Read-UserConfirm{
    <#
    .SYNOPSIS
    Prompts user to continue
    .DESCRIPTION
    Displays a message and asks the user to:
    "Press enter to confirm; or any other key (and then enter) to exit"
    .PARAMETER Message
        system.string
        Just a message about what we are skipping of entering info for
    .INPUTS
        None.
    .OUTPUTS
        system.boolean
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][String]$Message
    )
    if ($Message) {
        $response = read-host $Message
    }else{
    $response = read-host 'Press enter to confirm; or any other key (and then enter) to exit'
    }
    $aborted = ! [bool]$response
    if(!$aborted){
        return $false
    }else{
        return $true
    }
}

function Set-ADUGroups {
    <#
    .SYNOPSIS
    Adds the user to the specific groups
    .DESCRIPTION
    Adds the specified user to multiple groups.

    .PARAMETER Identity
        system.string Attribute of the Active Directory account to match
        E.G 'firstname.lastname'
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER Groups
        System.Array All groups the user is to be added to
        Must be the sAMAccountName Attribute of the AD Groups
    .PARAMETER Credential
        pscredentials Used to authenticate to the designated Domain Controller
    .INPUTS
        system.string for Identity
        System.Array for Groups
        system.string for Server
    .OUTPUTS
        returns one or Multiple PSCustomObjects depending on input.
        Contains MemberOf & Identity Properties
        MemberOf is an array of PSCustomObjects containing the properties: SamAccountName & Result.
            SamAccountName of the groups inputed to the command
            Result of the command Boolean
        Identity the same Identity that was input to the function
    #>
    #Requires  -module ActiveDirectory
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][String]$Identity,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Array]$Groups,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    Begin{}
    Process{
        #Let the console know what we are doing
        Write-Verbose($Identity+' will be added to the below groups')
        $Groups | ForEach-Object {Write-Verbose($_)}
        Write-Verbose('Trying to Set AD Groups for user; '+$Identity)
        #Splat for Get AD Users Groups
        [HashTable]$SplatGetADPrince = @{
            Server = $Server
            Identity = $Identity
            ErrorAction = 'Stop'
        }
        #Splat for Set AD User Groups
        [HashTable]$SplatSetADPrince = @{
            Server = $Server
            Identity = $Identity
            Memberof = ''
            ErrorAction = 'Stop'
        }
        if($Credential){
            Write-Verbose('Admin credentials provided.')
            $SplatSetADPrince.Add('Credential',$Credential)
            $SplatGetADPrince.Add('Credential',$Credential)
        }
        [PSCustomObject]$Results=@{
            Identity=$Identity
            MemberOf=@()
        }
        # Finally do a loop to add each group to the user writing output to the console
        foreach($Group in $Groups){
            $TimeStart = Get-Date
            $TimeEnd = $timeStart.addminutes(0.5)
            $SplatSetADPrince['Memberof']=$Group
            if ($PSCmdlet.ShouldProcess($Identity, 'Add-ADPrincipalGroupMembership -MemberOf "'+$Group)) {
                do {
                    $TimeNow = Get-Date
                    $Finished=$false
                    try {
                        if (!(Get-ADPrincipalGroupMembership @SplatGetADPrince | Select-Object SamAccountName | Where-Object -Property SamAccountName -Value $Group -EQ)) {
                            Write-Verbose('User is not a memberof "'+$Group+'" procceding to add them. ')
                            try {
                                    Add-ADPrincipalGroupMembership @SplatSetADPrince
                                    Write-Verbose('Successfully Added user; '+$Identity+' To Group; '+$Group)
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$True
                                }
                                $Finished=$true                 
                            }catch [System.Management.Automation.MethodException]{
                                Write-Error('Provided credentials have insufficient permissions to change user groups')
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$False
                                }
                                break
                            }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                                Write-Error("Cannot Find "+$Group+" Skipping")
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$False
                                }
                                $Finished=$true
                            }catch {
                                Write-Error($_.Exception.Message)
                                break
                            }
                        }else{
                            Write-Verbose('User is already a MemberOf '+$Group+' Skipping')
                            $Results.MemberOf += [PSCustomObject]@{
                                SamAccountName=$Group
                                Result=$True
                            }
                            $Finished=$true
                        }
                    }catch [Microsoft.ActiveDirectory.Management.ADException]{
                        Write-Warning('Provided credentials have insufficient permissions to change user groups')
                        break
                    }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                        $Finished=$false
                        Write-Verbose('User Not Found | Sleeping')
                        Start-Sleep 3
                    }catch{
                        write-error($_.Exception.Message)
                        break
                    }
                    if($TimeNow -ge $TimeEnd){
                        $Finished = $true
                        Write-Warning('Searched for 30 seconds Exiting.')
                    }
                } until ($Finished)
            }
        }
        if($Results.MemberOf){
            Write-Verbose('Returning Results')
            [PSCustomObject]$Results
        }
    }
    End{}
}

function Start-Logging{
    <#
    .SYNOPSIS
        Creates a spot to store transcripts from scripts
    .DESCRIPTION
        Creates a folder called logs at the specified Path, then stores transcripts from script execution. 
        These are prefixed with the $Name variable then a timestamp.
        It will need a specified Number of logs default being 50, any logs older then this will be deleted
    .PARAMETER Path
        system.string file path to store the logs in
    .PARAMETER Name
        system.string name to prefix the log with
        E.G firstname.lastname or the name of the script
    .PARAMETER NumberOfLogsToKeep
        system.string 
    .INPUTS
        system.string for Path
        system.string for Name
    .OUTPUTS
        None.
    #>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true,HelpMessage='Must Be $MyInvocation.MyCommand.Path')][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$false)][int]$NumberOfLogsToKeep=50
	)
    #Region Logging Variables
    $LogPath = Join-Path -Path $Path -ChildPath 'Logs'
    $TimeStamp = Get-Date -Format yyyy-MM-dd_HHmmss
    $LogFileName = '{0}_{1}.log' -f $Name, $TimeStamp
    $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName
    #Change this value to how many log files you want to keep
    If(Test-Path -Path $LogPath){
        #Make some cleanup and keep only the most recent ones
        $Filter = '*_????-??-??_??????.log'
        Get-ChildItem -Path $Filter |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -Skip $NumberOfLogsToKeep |
        Remove-Item -Verbose
    }else{
        #No logs to clean but create the Logs folder
        New-Item -Path $LogPath -ItemType Directory -Verbose
    }
    Start-Transcript -Path $Logfile
    #endregion Logging Variables
}

function New-CompanyUser {
    #Requires  -module ActiveDirectory
    #Requires  -module AzureAD
    #Requires  -module MSOnline
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateLength(1,20)][string]$Firstname,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String]$Lastname,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][SecureString]$Password,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][ValidatePattern('^[0-9]{4,4}$|^(?![\s\S])')][String]$OfficePhone,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][ValidatePattern('^[0-9]{10,10}$|^(?![\s\S])')][String]$MobilePhone,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String]$Title,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String]$Manager,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String]$Branch,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][validateset('E1','E2','E3','')][string]$M365License,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][validateset('TRUE','FALSE')][string]$FileServerAccess,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][System.Collections.ArrayList]$MemberOf=@(),
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][validateset('Enabled','Disabled','Enforced')][String]$StrongAuthenticationRequirements,        
        [Parameter(Mandatory=$true)][String]$Domain,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][validateset('TRUE','FALSE')][string]$DistributionList='TRUE',
        [Parameter(Mandatory=$false)][PSCredential]$EMSCredentials,
        [Parameter(Mandatory=$true)][String]$EMSServer,
        [Parameter(Mandatory=$false)][PSCredential]$ADCredentials,
        [Parameter(Mandatory=$false)][Boolean]$Interactive=$true,
        [Parameter(Mandatory=$false)][System.Collections.ArrayList]$AdminGroups,
        [Parameter(Mandatory=$false)][PSCredential]$ADSyncCredentials,
        [Parameter(Mandatory=$true)][String]$ADSyncServer,
        [Parameter(Mandatory=$true)][String]$EmailDomain,
        [Parameter(Mandatory=$true)][String]$FallbackUserOU,
        [Parameter(Mandatory=$true)][String]$Company

    )
    begin {
        $CurrentPath = Split-Path -Path $PSCmdlet.MyInvocation.PSCommandPath -Parent
        Write-Verbose('Working Directory is:'+$CurrentPath)
        #Start Logging 
        if ($PSCmdlet.MyInvocation.ExpectingInput){
        Start-Logging -Path $CurrentPath -Name $Domain
        }
        #Find a DomainController to execute all AD Commands on
        try {
            $DomainController = (Get-ADDomainController -Discover -Domain $Domain -Service "PrimaryDC" -ErrorAction Stop).Hostname.Value
            Write-Verbose('Executing AD commands on: '+ $DomainController)
        }
        catch {
            Write-Error($_.Exception.Message)
            exit
        }
        #Check for XML Doc Path | Some stuff to handle if the file doesnt exist
        try {
            [xml]$XmlDocument = Get-Content -Path ($CurrentPath + '\BRANCHES.XML') -ErrorAction Stop
            $ADA = $XmlDocument.$Company
        }
        catch [System.Management.Automation.ItemNotFoundException]{
            Write-Warning('Unable to Find BRANCHES.XML, no Branch information will be added')
        }
        #Check if the current user has permissions to make changes in AD
        if (!(Assert-SufficientPermission -Server $DomainController -AdminGroups $AdminGroups)) {
            Write-Verbose('requesting creds with required perms')
            if(!$WhatIfPreference){
                [pscredential]$Creds = Get-Credential -Message 'AD Credentials with sufficient privilages required' -UserName ($Domain+'\')
                if(!$Creds){
                    Write-Error('No AD credentials provided.')
                    exit
                }
            }
        }
        #Detect if the function is being used in a pipeline
        if ($PSCmdlet.MyInvocation.ExpectingInput -and !$ADSyncCredentials) {
            Write-Verbose('Pipeline input detected, requesting credentials for: '+$ADSyncServer)
            [pscredential]$ADSyncCredentials = Get-Credential -Message ('Enter Credentials for: '+$ADSyncServer)
            if(!$ADSyncCredentials){
                Write-Error('No ADSync credentials provided.')
                exit
            }
        }
    }
    process {
        #region DataValidation
        #Create the Username Variable from the First and Lastname.
        if ($Firstname -and $Lastname) {
            Write-Verbose('Setting Username')
            $SamAccountName = ($Firstname + '.' + $Lastname).ToLower()
        #Logic is lastname isnt specified.
        }elseif (!$Lastname) {
            $SamAccountName = $Firstname.ToLower()
            Write-Warning('No Lastname. Username will be set to Firstname')
        }
        if (!$PSCmdlet.MyInvocation.ExpectingInput){
            Start-Logging -Path $CurrentPath -Name $SamAccountName
            }
        #Create the DisplayName for the user
        if ($Firstname -and $Lastname) {
            Write-Verbose('Creating Displayname')
            $DisplayName = $Firstname + ' ' + $Lastname
        #Logic is lastname isnt specified.
        }elseif (!$Lastname) {
            $DisplayName = $Firstname
            Write-Warning('No Lastname. Display name will be set to Firstname value')
        }
        #More data collection only if we arnt in a pipeline
        if ($Interactive -and !$PSCmdlet.MyInvocation.ExpectingInput) {
            Write-Verbose('Entering Interactive for user: '+$SamAccountName)
            if (!$Branch) {
                Write-Verbose('No User Branch Entered')
                $Branch = Show-CompanyBranches -Branches $ADA
            }
            if (!$Title) {
                $Title = Read-Host 'User title'
            }
            if (!$Manager) {
                do {
                    $Finished=$false
                    try {
                        $Manager = Read-Host("Manager (first.lastname)") -ErrorAction Stop
                        $Finished=$true
                    }
                    catch [System.Management.Automation.ValidationMetadataException]{
                        Write-Warning('Invalid Input; username must be valid')
                        $Finished =$false
                    }
                    if (!$Manager) {
                        $Finished=$true
                    }
                    elseif (!(Assert-ADUExists -SamAccountName $Manager -Server $DomainController) -and $Finished -eq $true -and !$WhatIfPreference) {
                        $Finished =$false
                    }
                } until ($Finished -eq $true)
            }
            if (!$OfficePhone) {
                   do {
                    $Finished=$false
                    try {
                        $OfficePhone = Read-Host("Office Phone Number") -ErrorAction Stop
                        $Finished =$true
                    }
                    catch [System.Management.Automation.ValidationMetadataException]{
                        Write-Warning('Invalid Input | Must be 4 numbers or blank')
                        $Finished =$false
                    }
                    if (!$OfficePhone -match '^[0-9]{10,10}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished =$false
                    }
                } until ($Finished -eq $true)
            }
            if (!$MobilePhone) {
                do {
                    $Finished=$false
                    try {
                        $MobilePhone = Read-Host("Mobile Phone Number") -ErrorAction Stop
                        $Finished =$true
                    }
                    catch [System.Management.Automation.ValidationMetadataException]{
                        Write-Warning('Invalid Input | Must be 10 numbers or blank')
                        $Finished =$false
                    }
                    if (!$MobilePhone -match '^[0-9]{4,4}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished =$false
                    }
                } until ($Finished -eq $true)
            }
            if (!$M365License) {
                do {
                    $Finished=$false
                    try {
                        $M365License = Read-Host("Microsoft 365 License type:") -ErrorAction Stop
                        $Finished =$true
                    }
                    catch [System.Management.Automation.ValidationMetadataException]{
                        Write-Warning('Invalid Input | Must E1 or E2 or E3 or blank')
                        $Finished =$false
                    }
                    if (!$M365License -match '^[E][0-3]{1}$|^(?![\s\S])' -and $Finished -eq $true) {
                        $Finished =$false
                    }
                } until ($Finished -eq $true)
            }
            if (!$FileServerAccess) {
                if (!(Test-UserContinue -Message 'File server access not granted. Press enter to confirm, or type any key (then press enter) to grant file access')) {
                    $fileserveraccess=$true
                    Write-Verbose('File server access set to True')
                }else{
                    $FileServerAccess=$false
                    Write-Verbose('File server access set to False')
                }
            }
            if (!(Test-UserContinue -Message 'User will be added to branch DL. Press enter to confirm, or type any other key (then press enter) to cancel')) {
                $DistributionList=$false
                Write-Verbose('user will not be added to Branch DL')
            }else {
                $DistributionList=$true
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
        #Convert the string variables to booleans
        [boolean]$DistributionList = [system.convert]::ToBoolean($DistributionList)
        [boolean]$FileServerAccess = [system.convert]::ToBoolean($FileServerAccess)
        #If FileServerAccess was set to True
        if ($FileServerAccess) {
            $null = $MemberOf.Add($ADA.$Branch.drive_group)
            Write-Verbose('Adding FileServerAccess to; '+$ADA.$Branch.drive_group)
        }
        #If Distribution Group set to True
        if($DistributionGroup){
            $null = $MemberOf.Add($ADA.$Branch.distro)
            Write-Verbose('Adding Branch Distribution Group; '+$ADA.$Branch.distro)
        }
        #If !Manager is Specified from Default
        if (!$Manager) {
            Write-Verbose('Alternate manager not specified, using branch default')
            $Manager = $ADA.$Branch.manager
        }
        #Set variables for the Splat
        [string]$UserprincipalName = $SamAccountName + $EmailDomain
        #region Splatter
        #Assembled Splat for Exchange Command
        [HashTable]$SplatExchange = @{
            Name = $DisplayName
            Password = $Password
            UserPrincipalName = $UserprincipalName
            Alias = $SamAccountName
            DisplayName = $DisplayName
            Firstname = $Firstname
            Lastname = $Lastname
            OnPremisesOrganizationalUnit = $ADA.$Branch.ou
            SamAccountName = $SamAccountName
            Archive = $true
            DomainController=$DomainController
            Whatif = $WhatIfPreference
        }
        #Set the AD Attributes for the new user
        [HashTable]$SplatActiveDirectory = @{
            server = $DomainController
            Identity = $SamAccountName
            Office = $ADA.$Branch.office
            State = $ADA.$Branch.state
            Company = $ADA.$Branch.company
            Manager = $Manager
            Department = $ADA.$Branch.department
            City = $ADA.$Branch.city
            Country = $ADA.$Branch.country
            ScriptPath = $ADA.$Branch.logonscript
            PostalCode = $ADA.$Branch.post_code
            POBox = $ADA.$Branch.po_box
            StreetAddress = $ADA.$Branch.street
            OfficePhone = $OfficePhone
            MobilePhone = $MobilePhone
            Title = $Title
            Whatif = $WhatIfPreference
        }
        #Splat containing AD groups the user will be added to
        [HashTable]$SplatADGroups = @{
            Identity = $SamAccountName
            Groups = $MemberOf
            Server = $DomainController
            Whatif = $WhatIfPreference
        }
        #Splat for Get ad user after initial creation
        [HashTable]$SplatADGetUser = @{
            Server = $DomainController
            Identity = $SamAccountName
            Properties = "Office","State","Company","Manager","Department","City","Country","ScriptPath","PostalCode","POBox","StreetAddress","OfficePhone","MobilePhone","Title"
        }
        #Splat for Checking if the AD User is synced
        [HashTable]$SplatADUserSynced = @{
            SamAccountName = $SamAccountName
            Server  = $DomainController
            Whatif = $WhatIfPreference
        }
        #endregion Splatter
        #if no OU is set. Set one. Cannot continue otherwise
        if (!$SplatExchange.OnPremisesOrganizationalUnit) {
            $SplatExchange.OnPremisesOrganizationalUnit = $FallbackUserOU
            Write-Warning('No user OU Set! | Placing them in: '+$FallbackUserOU)
        }
        #We've got to remove any null or empty values from the hastable
        Write-Verbose("Cleaning AD splat of empty values")
        foreach($Key in @($SplatActiveDirectory.Keys) ){
            if (-not $SplatActiveDirectory[$Key]) {
                $SplatActiveDirectory.Remove($Key)
                Write-Verbose("Removed Empty Key: "+$Key)
            }
        }
        #endregion DataValidation
        #region DataConfirmation
        #Chance to confirm some account details
        if ($Interactive) {
            Write-Verbose('------------------------------')
            Write-Verbose('Active Directory Details')
            Write-Verbose('------------------------------')
            $SplatActiveDirectory | Format-table -Verbose
            Write-Verbose ('------------------------------')
            Write-Verbose('AD Group Details')
            Write-Verbose('------------------------------')
            $MemberOf | Format-List -Verbose
            Write-Verbose('------------------------------')
            Write-Verbose('Exchange Details')
            Write-Verbose('------------------------------')
            $SplatExchange | Format-table -Verbose
            Write-Verbose('------------------------------')
            if(!(Test-UserContinue -Message 'Above are the details for the user to be created, if the details are correct proceed otherwise cancel')){
                Write-Verbose('User Cancelled Terminating')
                Stop-Transcript
                Exit
            }
        }
        #endregion DataConfirmation
        #Check if the current user has permissions to make changes in AD
        if (!(Assert-SufficientPermission -Server $DomainController -AdminGroups $AdminGroups) -and $Creds) {
            Write-Verbose('Adding provided credentials to Splats')
            $SplatActiveDirectory.Add('Credential',$Creds)
            $SplatADGetUser.Add('Credential',$Creds)
            $SplatADGroups.Add('Credential',$Creds)
            $SplatADUserSynced.Add('Credential',$Creds)
        }
        #All Variables have been collected and formatted how we wanted. Now lets make the account.
        if(!(Assert-EMSUExists -SamAccountName $SamAccountName -Server $EMSServer -Credential $EMSCredentials -WhatIf:$WhatIfPreference)){
            Write-Verbose($SamAccountName+' does not exists on EMS; proceeding')
            if ($PSCmdlet.ShouldProcess($EMSServer, 'New-RemoteMailbox -Password "'+$SplatExchange.Password+'" -Name "'+$SplatExchange.Name+'" UserprincipalName "'+$SplatExchange.UserPrincipalName+'" Alias "'+$SplatExchange.Alias+'" DisplayName "'+$SplatExchange.DisplayName+'" Firstname "'+$SplatExchange.Firstname+'" Lastname "'+$SplatExchange.Lastname+'" OnPremisesOrganizationalUnit "'+$SplatExchange.OnPremisesOrganizationalUnit+'" SamAccountName "'+$SplatExchange.SamAccountName+'" Archive "'+$SplatExchange.Archive+'" DomainController "'+$SplatExchange.DomainController)) {
                New-RemoteMailbox @SplatExchange -ErrorAction Stop
            }
            #Wait for the user to Sync then set user attributes
            if ((Wait-ADUSynced @SplatADUserSynced) -or $WhatIfPreference) {
                Write-Verbose('Found "'+$SamAccountName+'" in AD updating user Attributes')
                if ($PSCmdlet.ShouldProcess($DomainController, 'Set-ADUser -Server "'+$SplatActiveDirectory.Server+'" -Identity "'+$SplatActiveDirectory.Identity+'" -Office "'+$SplatActiveDirectory.Offic+'" -State "'+$SplatActiveDirectory.State+'" -Company "'+$SplatActiveDirectory.Company+'" -Manager "'+$SplatActiveDirectory.Manager+'" -Department "'+$SplatActiveDirectory.Department+'" -City "'+$SplatActiveDirectory.City+'" -Country "'+$SplatActiveDirectory.Country+'" -ScriptPath "'+$SplatActiveDirectory.ScriptPath+'" -PostalCode "'+$SplatActiveDirectory.PostalCode+'" -POBox "'+$SplatActiveDirectory.POBox+'" -StreetAddress "'+$SplatActiveDirectory.StreetAddress+'" -OfficePhone "'+$SplatActiveDirectory.OfficePhone+'" -MobilePhone "'+$SplatActiveDirectory.MobilePhone+'" -Title "'+$SplatActiveDirectory.Title)) {                
                Set-ADUser @SplatActiveDirectory
                Get-ADUser @SplatADGetUser
                }
                if($MemberOf){
                    Set-ADUGroups @SplatADGroups
                }else {
                    Write-Verbose('No groups specified')
                }
            }
            #Add the user to specified groups

            #Start an Delta Sync on AzureAD Connect
            Write-Verbose('Starting AzureAD Connect Sync')
                    if((Sync-Directories -Server $ADSyncServer -Credential $ADSyncCredentials -AzureActiveDirectory -ErrorAction Stop -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                        if((Wait-AADUSynced -UserPrincipalName $UserprincipalName -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                            if($M365License){
                                Write-Verbose('Trying to assign a '+$M365License+' License to ; '+$UserprincipalName)
                                if( !(Set-AADULicense -UserPrincipalName $UserprincipalName -LicenseType $M365License -Whatif:$WhatIfPreference) -and $Interactive){
                                    Test-UserContinue(-Message 'No Microsoft 365 License assigned. Press any key to continue.')
                                }                                
                            }
                            Write-Verbose('Setting user MFA')                      
                            Set-MSolUMFA -UserPrincipalName $UserprincipalName -StrongAuthenticationRequirements $StrongAuthenticationRequirements -Whatif:$WhatIfPreference
                        }
                }else{
                    Write-Verbose('No license specified for user, nothing will be assigned')
                }
        }else{
            Write-Warning($SamAccountName+' already exists on EMS; skipping')
        }
    }
    end {Stop-Transcript}
}