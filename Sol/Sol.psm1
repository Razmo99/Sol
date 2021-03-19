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
        [Parameter(HelpMessage='Just a message about what we are skipping of entering info for')][String]$Message
    )
    if ($Message) {
        $response = read-host $Message
    }else{
    $response = read-host "Press enter to confirm; or any other key (and then enter) to exit"
    }
    $aborted = ! [bool]$response
    if(!$aborted){
        return $false
    }else{
        return $true
    }
}

function Test-EMSConnected {
    <#
    .SYNOPSIS
    Checks if a connection to EMS is Present
    .DESCRIPTION
        Checks to see if an active ps session is present and if the command New-RemoteMailbox is available.
        If it is not it checked for a stale session and removes it.
        returns true if the command can be retreived false otherwise
    .OUTPUTS
        system.boolean
    .INPUTS
     None
    #>    
    $CheckExistingSession = Get-PSSession | Where-Object {$_.State -eq 'Opened' -and $_.ConfigurationName -eq 'Microsoft.Exchange'}
    [bool]$CheckEMSCommandPresent = Get-Command New-RemoteMailbox -ErrorAction SilentlyContinue
    if(!$CheckEMSCommandPresent){
        Write-Verbose('Unable to get EMS Commands')
        if ($CheckExistingSession) {
            Write-Verbose('Removing stale PSSession')
            $CheckExistingSession | Remove-PSSession
        }
        return $false
    }elseif($CheckExistingSession) {
        Write-Verbose('EMS Session Already Present')
        return $true
    }
}

function Test-UserPrompt {
    param (
        [Parameter(Mandatory=$true)][String]$Message,
        [Parameter(Mandatory=$false)][boolean]$Inverse=$false
    )
    # If prompt is inverse (!)bang it
    if($Inverse){
        $TestUser = !(Test-UserContinue -Message $Message)
    # else normal
    }else{
        $TestUser = Test-UserContinue -Message $Message
    }
    return $TestUser      
}

function Test-Prompts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][HashTable]$Prompts
    )
    [HashTable]$Results=@{}
    Write-Verbose('Processing prompts without Requirements')
    # Iterate over the Prompts
    foreach ($key in $Prompts.keys) {
        $Prompt = $Prompts[$Key]
        if(Test-UserPrompt -Message $Prompt.Message -Inverse:$Prompt.Inverse){
            # stick the groups into out results object
            [Void] $Results.Add($Key,$Prompts[$Key])
        }
    }
    return $Results
}

function Test-PromptM365AndFileServerAccess {
    <#
    .SYNOPSIS
    Test Prompts for M365 and File Server Access
    
    .DESCRIPTION
    Removes prompts that require FileServerAccess or a specific M365 License
    
    .PARAMETER Prompts
    System.HashTable - Contains prompt That have requirements for M365 License or FileServerAccess
    
    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    #>    
    param (
        [Parameter(Mandatory=$true)][HashTable]$Prompts,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License=''
    )
    Write-Verbose('Processing prompts without Requirements on other prompts')
    [HashTable]$Results=@{}
    # Iterate over all DPrompts with Requirements
    foreach ($key in $Prompts.keys) {     
        # Bool to tell if the Prompt should be displayed to the user
        $CriterialMet = $true
        # If the Prompt has FileServerAccess AND FileServerAccess is assigned to the user proceed
        if(!$FileServerAccess){
            # If promp FileServerAccess is False Criteria not met
            if($Prompts.$key.Requirements.FileServerAccess -eq $true){
                Write-Verbose($key+': Criterial Failed: '+'File Server Access')
                $CriterialMet = $false
            }
        # If the Prompt has M365License AND user has M365License
        }
        if($Prompts.$key.Requirements.M365License){
            # If the License is not within the M365 Array Criteria not met
            if(($Prompts.$key.Requirements.M365License -notcontains $M365License) -and !($Prompts.$key.Requirements.M365License -contains 'Any')){
                Write-Verbose($key+': Criterial Failed: '+'Microsoft 365 License')
                $CriterialMet=$false
            }       
        } 
        if($CriterialMet){
            if(Test-UserPrompt -Message $Prompts.$Key.Message -Inverse:$Prompts.$Key.Inverse){
                # stick the groups into out results object
                [Void] $Results.Add($key,$Prompts.$Key)
            }
        }             
    }
    return $Results        
}

function Test-PromptsWRequsOTHPrompts {
    <#
    .SYNOPSIS
    Test Prompts With Requirements On Other Prompts
    
    .DESCRIPTION
    Removes prompts that require FileServerAccess or a specific M365 License
    Removes Prompts that require other prompts but the prompt does not exist
    
    .PARAMETER Prompts
    System.HashTable - Contains prompt That have requirements on other prompts
    
    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    
    .PARAMETER ResultsWOReqs
    System.HashTable - Contains prompt Results that do not have requirements
    #>
    param (
        [Parameter(Mandatory=$true)][HashTable]$Prompts,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License='',
        [Parameter(Mandatory=$true)][HashTable]$ResultsWOReqs
    )
    [HashTable]$Results=@{}
    $MissingRequirements=New-Object System.Collections.Queue
    # Iterate over all DPrompts with Dependancies
    Write-Verbose('Processing prompts with requirements on other prompts')
    foreach ($key in $Prompts.keys) {
        # Bool to tell if the Prompt should be displayed to the user
        $CriterialMet = $true
        # If the Prompt has FileServerAccess AND FileServerAccess is assigned to the user proceed
        if(!$FileServerAccess){
            # If promp FileServerAccess is False Criteria not met
            if($Prompts.$key.Requirements.FileServerAccess -eq $true){
                Write-Verbose($key+': Criterial Failed | Missing File Server Access')
                $CriterialMet = $false
            }
        # If the Prompt has M365License AND user has M365License
        }
        if($Prompts.$key.Requirements.M365License){
            # If the License is not within the M365 Array Criteria not met
            if(($Prompts.$key.Requirements.M365License -notcontains $M365License) -and !($Prompts.$key.Requirements.M365License -contains 'Any')){
                Write-Verbose($key+': Criterial Failed | Missing Microsoft 365 License '+$Prompts.$key.Requirements.M365License)
                $CriterialMet=$false
            }       
        } 
        # If the prompts has requirements
        if($Prompts.$Key.Requirements.Prompts){
            # Foreach requirements
            foreach($Req in $Prompts.$Key.Requirements.Prompts){
                if($Prompts.Keys -notcontains $Req){
                    $MissingRequirements.Enqueue($Req)
                }
            }
            While($MissingRequirements -gt 0){
                $CurrentReq = $MissingRequirements.Dequeue()
                if($ResultsWOReqs.keys -contains $CurrentReq){
                    Write-Verbose($key + ': Found Requirement "' + $CurrentReq+'"')
                    $NewReqs = New-Object System.Collections.ArrayList(,$Prompts.$Key.Requirements.Prompts)
                    $NewReqs.remove($CurrentReq)
                    $Prompts.$Key.Requirements.Prompts = $NewReqs
                }else{
                    Write-Verbose($Key+': Criterial Failed | Missing Requirement: '+$CurrentReq)
                    $CriterialMet=$false
                }
            }
        }
        if($CriterialMet){
            Write-Verbose($Key+': Criteria Met')
            [void] $Results.Add($Key,$Prompts[$Key])
        }
    }
    return $Results 
}

function Set-MSolUMFA{
    <#
    .SYNOPSIS
    Sets MFA Status on a User
    .DESCRIPTION
    Checks if a connection to Msol is Present. If its not initiate one.
    Checks the UserPrincipalName Exists to Msol, if it does sets the StrongAuthenticationRequiremets
    .PARAMETER UserPrincipalName
    UserprincipalName Use to Set MFA Enforced on
    .PARAMETER StrongAuthenticationRequiremets
    StrongAuthenticationRequiremets Required level of MFA
    .OUTPUTS
    system.boolean
    .INPUTS
    system.string UserprincipalName
    system.string StrongAuthenticationRequiremets Level of MFA to set
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateSet('Enabled','Disabled','Enforced')][String]$StrongAuthenticationRequiremets
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
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "StrongAuthenticationRequiremets = "+$StrongAuthenticationRequiremets)) {
            do {
                $TimeNow = Get-Date
                #Primary check for success condition
                if (Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue) {
                    $Finished = $true
                    Write-Verbose('Found '+$UserPrincipalName+' In Msol')
                    Write-Verbose('Attempting to Set MFA Status to Enforced')
                    # Set some variables for MFA enforcement
                    $st = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
                    $st.RelyingParty = "*"
                    $st.State = $StrongAuthenticationRequiremets
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
                # if 1 minutes passes we just tap out and exit the script
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
                Write-Error($_.Exception.Message)
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
        Test-EMSConnected
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
            Write-Verbose($LicenseInfo.prepaidunits.enabled.ToString() + ' PrePaid | '+ $LicenseInfo.consumedunits.ToString() + ' Consumed')
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

function Get-ClonedObject {
    
    param($DeepCopyObject)
    $memStream = new-object IO.MemoryStream
    $formatter = new-object Runtime.Serialization.Formatters.Binary.BinaryFormatter
    $formatter.Serialize($memStream,$DeepCopyObject)
    $memStream.Position=0
    $formatter.Deserialize($memStream)
}

function Get-TopologicalSort {
    # Function from https://stackoverflow.com/questions/8982782/does-anyone-have-a-dependency-graph-and-topological-sorting-code-snippet-for-pow
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [hashtable] $edgeList
    )

    # Make sure we can use HashSet
    Add-Type -AssemblyName System.Core

    # Clone it so as to not alter original
    $currentEdgeList = [hashtable] (Get-ClonedObject $edgeList)

    # algorithm from http://en.wikipedia.org/wiki/Topological_sorting#Algorithms
    $topologicallySortedElements = New-Object System.Collections.ArrayList
    $setOfAllNodesWithNoIncomingEdges = New-Object System.Collections.Queue

    $fasterEdgeList = @{}

    # Keep track of all nodes in case they put it in as an edge destination but not source
    $allNodes = New-Object -TypeName System.Collections.Generic.HashSet[object] -ArgumentList (,[object[]] $currentEdgeList.Keys)
    $MissingSourceNodes=New-Object System.Collections.Queue
    # Iterate over all Keys in Edge List

    function Assert-Nodes {
        foreach($currentNode in $currentEdgeList.Keys) {
            $currentDestinationNodes = [array] $currentEdgeList[$currentNode]
            # If the current node's array is empty, meaning it has no incoming edges
            if($currentDestinationNodes.Length -eq 0) {
                $setOfAllNodesWithNoIncomingEdges.Enqueue($currentNode)
            }
            # Iterate over nodes and make sure it exists in all nodes otherwise enqueue to remove it.
            foreach($currentDestinationNode in $currentDestinationNodes) {
                if(!$allNodes.Contains($currentDestinationNode)) {
                if($currentEdgeList.ContainsKey($currentDestinationNode)){
                    [void] $allNodes.add($currentDestinationNode)
                }else{
                $MissingSourceNodes.Enqueue($currentNode)
                Write-Verbose($CurrentNode+': Criteria Not Met | Destination Node Missing for: '+$currentDestinationNode)
                }
                }
            }

            # Take this time to convert them to a HashSet for faster operation
            $currentDestinationNodes = New-Object -TypeName System.Collections.Generic.HashSet[object] -ArgumentList (,[object[]] $currentDestinationNodes )
            [void] $fasterEdgeList.Add($currentNode, $currentDestinationNodes)
        }
    }
    Assert-Nodes
    While ($MissingSourceNodes.count -gt 0){
    # This is so nasty
    $currentMissingNode = $MissingSourceNodes.Dequeue()
    $currentEdgeList.Remove($currentMissingNode)
    $allNodes.Clear()
    $setOfAllNodesWithNoIncomingEdges.Clear()
    $fasterEdgeList.Clear()
    Assert-Nodes
    }

    $currentEdgeList = $fasterEdgeList

    while($setOfAllNodesWithNoIncomingEdges.Count -gt 0) {        
        $currentNode = $setOfAllNodesWithNoIncomingEdges.Dequeue()
        [void] $currentEdgeList.Remove($currentNode)
        [void] $topologicallySortedElements.Add($currentNode)

        foreach($currentEdgeSourceNode in $currentEdgeList.Keys) {
            $currentNodeDestinations = $currentEdgeList[$currentEdgeSourceNode]
            if($currentNodeDestinations.Contains($currentNode)) {
                [void] $currentNodeDestinations.Remove($currentNode)

                if($currentNodeDestinations.Count -eq 0) {
                    [void] $setOfAllNodesWithNoIncomingEdges.Enqueue($currentEdgeSourceNode)
                }                
            }
        }
  }

  if($currentEdgeList.Count -gt 0) {
      throw "Graph has at least one cycle!"
  }

  return $topologicallySortedElements
}

function Convert-InteractivePromptsForTopologicalSort{
    <#
    .SYNOPSIS
    Converts Promtps to a format that is accepeted by the Get-TopologicalSort function
    .PARAMETER Prompts
    System.HashTable - Prompts to be converted
    #>
    param(
        [Parameter(Mandatory=$true)][HashTable]$Prompts
    )
    [HashTable]$Results=@{}

    foreach ($InteractivePrompt in $Prompts.GetEnumerator()) {
        if($InteractivePrompt.value.Requirements.Prompts){
            $Results[$InteractivePrompt.Name]=$InteractivePrompt.value.Requirements.Prompts
        }else{
            $Results[$InteractivePrompt.Name]=@()
        }
    }
    return $Results
}
function Resolve-Prompts {
    <#
    .SYNOPSIS
    Resolves the provided prompts using Topological sorting till completion
    .DESCRIPTION
    Passes inputted prompts to the user to get answers.
    Then re calculates the topological sorting based off the answers till all prompts are exhausted
    
    .PARAMETER Prompts
    System.Hashtable - Prompts that have been converted for Topological Sorting
    
    .PARAMETER OriginalPrompts
    System.Hashtable - Unmodified Original Prompts with all metadata
    #>
    [CmdletBinding()]param(

        [parameter(Mandatory=$true)][HashTable]$Prompts,
        [parameter(Mandatory=$true)][HashTable]$OriginalPrompts
    )
    # Clone the prompts as to not modify the source
    $currentPrompts = [HashTable] (Get-ClonedObject $Prompts)
    # This is a queue so that as answers are received the currentPrompts can be updated and then reproccessed
    $PromptsQueue = New-Object System.Collections.Queue
    # Kick it all off by Enqueueing the current prompts
    $PromptsQueue.Enqueue((Get-TopologicalSort $currentPrompts))
    # This Array contains the names of prompts that returned true
    [HashTable]$PromptAnswers = @{}
    # Primary While Loop keep Iterating aslong as the queue is not empty.
    While($PromptsQueue.Count -gt 0){
        # Dequeue The current Prompts
        $PromptsDequeue = $PromptsQueue.Dequeue()
        # Iterate over the prompts to be tested
        Foreach($Key in $PromptsDequeue){
            # If the Prompt has not been answered
            if ($PromptAnswers.keys -notcontains $Key){
                # Test the User
                $TestUser = Test-UserPrompt -Message $OriginalPrompts.$Key.message -Inverse:$OriginalPrompts.$Key.inverse
                if ($TestUser){
                    # If the prompt is answered true add the prompt to Answers
                    [void ]$PromptAnswers.Add($key,$OriginalPrompts.$Key)
                }else{
                    # If the prompt is answered false remove the prompt in question from the current prompts.
                    $currentPrompts.Remove($Key)
                    # Re que the current Prompts for another round
                    $PromptsQueue.Enqueue((Get-TopologicalSort $currentPrompts))
                    # Break the loop and reset it
                    break
                }
            }
        }
    }
    return $PromptAnswers
}
function Resolve-AutoMemberOf{
    <#
    .SYNOPSIS
    Resolves the requirements of non-prompting MemberOf entries
    
    .DESCRIPTION
    Iterates over the AutoMemberOf Parameter. If any requirements are present it checks them against the other inputed parameters. 
    If the AutoMemberOf Item requires another prompt a key lookup is performed on the "InteractivePromptAnswers" parameter.
    
    .EXAMPLE
    Resolve-AutoMemberOf -FileServerAccess:$False -M365License 'E1' -AutoMemberOf @{'Email'=@{MemberOf=@('Email');Requirements=@{Prompts=@('EmailAccess');FileServerAccess=$True}}} -InteractivePromptAnswers @{'EmailAccess'=@{MemberOf=@('testGroup')}}
    .PARAMETER InteractivePromptAnswer
        System.HashTable - Contains all the Answers to the Interactive Prompts preseneted to the user.
        Used to resolve requirements "AutoMemberOf" may have.
    .PARAMETER AutoMemberOf
        System.HashTable - Contains all No Prompting Groups to add the user to with conditions.
    .PARAMETER FileServerAccess
        System.Boolean - Has the user been assigned FileServerAccess.
        Default is False
    .PARAMETER M365License
        System.String - Type of License the user has been assigned if any.
        Default is ''
    .OUTPUTS
        System.HashTable - Contains Entires from AutoMemberOf that have met requirements
    #>
    [CmdletBinding()]param(
        [parameter(Mandatory=$true)][HashTable]$InteractivePromptAnswers,
        [Parameter(Mandatory=$true)][HashTable]$AutoMemberOf,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License=''
    )
    [HashTable]$Results=@{}
    Write-Verbose('Processing AutoMemberOf entries')
    # Iterate over all AutoMember Items
    foreach ($key in $AutoMemberOf.keys) {
        # If this item doesn have requirements add it to the results
        if(!$AutoMemberOf.$key.Requirements){
            Write-Verbose($key+': Criteria Met')
            [void] $Results.Add($key,$AutoMemberOf[$Key])
        }elseif($AutoMemberOf.$key.Requirements){
            $CriterialMet=$true
            if(!$FileServerAccess){
                # If item FileServerAccess is False Criteria not met
                if($AutoMemberOf.$key.Requirements.FileServerAccess -eq $true){
                    Write-Verbose($key+': Criterial Failed | File Server Access')
                    $CriterialMet = $false
                }
            # If the item has M365License AND user has M365License
            }
            if($AutoMemberOf.$key.Requirements.M365License){
                # If the License is not within the M365 Array Criteria not met
                if(($AutoMemberOf.$key.Requirements.M365License -notcontains $M365License) -and !($AutoMemberOf.$key.Requirements.M365License -contains 'Any')){
                    Write-Verbose($key+': Criterial Failed | Microsoft 365 License')
                    $CriterialMet=$false
                }       
            }
            # Does this item depend on other prompts          
            if($AutoMemberOf.$key.Requirements.prompts){
                # Iterate over each prompt it depends on
                foreach ($req in $AutoMemberOf.$key.Requirements.prompts) {
                    # If the Interactive Prompts does not contain this item Criteria not met
                    if($InteractivePromptAnswers.keys -notcontains $req){
                        Write-Verbose($key+': Criterial Failed | Missing req: '+$req)
                        $CriterialMet=$false                        
                    }
                }                    
            }
            # Add the item to the results to be returned
            if($CriterialMet){
                Write-Verbose($key+': Criteria Met')
                [void] $Results.Add($key,$AutoMemberOf[$Key])
            }
        }
    }
    return $Results 
}

function Show-CompanyBranches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do{
        Write-Host('Branches')
        Write-Host('--------')
        $Branches.ChildNodes | ForEach-Object {$_.Name} | Write-Host 
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

function Assert-EMSPermission {
    <#
    .SYNOPSIS
        Asserts the current user can create a PSSession to the specified server
    .DESCRIPTION
        tries to create a New-PSSession to the specified server
        returns true for a match and false for no match
    .PARAMETER Server
        system.string Exchange Management server to assert against
    .PARAMETER EMSAuth
        Type of Auth to use when inititating the PSSession        
    .INPUTS
        system.string for EMSAuth
        system.string for server
    .OUTPUTS
        system.boolean
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$Server,
        [parameter(Mandatory=$false)][String][Validateset('Default','Basic','Credssp','Digest','Kerberos','Negotiate','NegotiateWithImplicitCredential')]$EMSAuth = "Kerberos",
        [parameter(Mandatory=$false)][pscredential]$Credential
    )
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
    try {
        if ($PSCmdlet.ShouldProcess($Server, "Testing New-PSSession on:")) {
            $Session = New-PSSession @SplatNewPSSession
            $Session | Remove-PSSession
            return $true
        }
        if ($WhatIfPreference){return $true}
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException]{
        if ($_.Exception.Message.contains("AuthZ-CmdletAccessDeniedException")) {
            return $false
        }else{
            Write-Error($_.Exception.Message)
        }
    }
    catch {
        Write-Error($_.Exception.Message)
    }
}

function Assert-ADSyncPermission{
    <#
    .SYNOPSIS
        Asserts the current user can create a PSSession to the specified server
    .DESCRIPTION
        tries to create a New-PSSession to the specified server
        returns true for a match and false for no match
    .PARAMETER Server
        system.string Exchange Management server to assert against    
    .INPUTS
        system.pscredentials for Credential
        system.string for server
    .OUTPUTS
        system.boolean
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$Server,
        [parameter(Mandatory=$false)][pscredential]$Credential
    )
    [hashtable]$SplatNewPSSession = @{
        ComputerName = $Server
        ErrorAction = 'Stop'
    }
    #Add Credentials if presented
    if ($Credential) {
        Write-Verbose('Credentials provided')
        $SplatNewPSSession.Add('Credential',$Credential)
    }
    try {
        $Session = New-PSSession @SplatNewPSSession
        $Session | Remove-PSSession
        return $true
    }
    catch [System.Management.Automation.ErrorRecord]{
        if ($_.Exception.Message.contains('Access is denied')){
            return $false
        }else{
            Write-Error($_.Exception.Message)
        }
    }
    catch{
        Write-Error($_.Exception.Message)
    } 
}

function Assert-ADPermission {
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

function Test-InteractivePrompts {
    <#
    .SYNOPSIS
    Presents the inputted prompts to the use.
    
    .DESCRIPTION
    Presents Interactive prompts in a Topologicaly sorted order based on each prompts unique requirements
    
    .PARAMETER InteractivePrompts
    System.HashTable - Contains all Interactive Prompts to present to the user for Answers
    
    .PARAMETER AutoMemberOf
    System.HashTable - Contains all No Prompting Groups to add the user to with conditions.
    
    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    #>
    [CmdletBinding()]param(
        [parameter(Mandatory=$true)][HashTable]$InteractivePrompts,
        [Parameter(Mandatory=$false)][HashTable]$AutoMemberOf=@{},
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License=''   
    )
    # Prompts without Requirements
    [HashTable]$PWOReqs=@{}
    $InteractivePrompts.keys | ForEach-Object {if($InteractivePrompts.$_.Requirements -eq $null){$PWOReqs[$_]=$InteractivePrompts[$_]}}
    # Prompts with Requirements and without Requirements on other Prompts
    [HashTable]$PWReqsWOReqsOTHP=@{}
    $InteractivePrompts.keys | ForEach-Object {if(($InteractivePrompts.$_.Requirements -ne $null) -and ($InteractivePrompts.$_.Requirements.Prompts -eq $null)){$PWReqsWOReqsOTHP[$_]=$InteractivePrompts[$_]}}
    # Prompts with Requirements and with Requirements on other Prompts
    [HashTable]$PWReqsWReqsOTHP=@{}
    $InteractivePrompts.keys | ForEach-Object {if(($InteractivePrompts.$_.Requirements -ne $null) -and ($InteractivePrompts.$_.Requirements.Prompts -ne $null)){$PWReqsWReqsOTHP[$_]=$InteractivePrompts[$_]}}

    # RESULTS
    # Results With Requirements
    [HashTable]$ResultsWOReqs=@{}
    # Results With Requirements On Other Prompts
    [HashTable]$ResultsWReqsWReqsOTHP=@{}
    # Combination of the Above Results
    [HashTable]$CombinedResults=@{}
    # The Final Results that will be returned
    [System.Collections.ArrayList]$Results=@()
    
    # If Prompts without Requirements process them.
    if ($PWOReqs){
        $Test_PWOReqs=Test-Prompts -Prompts $PWOReqs
        if($Test_PWOReqs){
            # Add any results to the result variables
            $Test_PWOReqs.GetEnumerator() | ForEach-Object {$ResultsWOReqs.Add($_.key,$_.Value)}
        }
    }
    # If Prompts with Requirements and without Requirements on other Prompts exist lets process them.
    if($PWReqsWOReqsOTHP){
        $Test_PWReqsWOReqsOTHP=Test-PromptM365AndFileServerAccess -Prompts $PWReqsWOReqsOTHP -M365License $M365License -FileServerAccess $FileServerAccess
        if($Test_PWReqsWOReqsOTHP){
            # Add any results to the result variables
            $Test_PWReqsWOReqsOTHP.GetEnumerator() | ForEach-Object {$ResultsWOReqs.Add($_.key,$_.Value)}
        }
    }
    # Prompts with Requirements and with Requirements on other Prompts exist lets process them.
    if($PWReqsWReqsOTHP){
        $Test_PWReqsWReqsOTHP=Test-PromptsWRequsOTHPrompts -prompts $PWReqsWReqsOTHP -FileServerAccess $FileServerAccess -M365License $M365License -ResultsWOReqs $ResultsWOReqs
        if($Test_PWReqsWReqsOTHP){
            # Convert any results for Topological sorting
            $Convert_Prompts=Convert-InteractivePromptsForTopologicalSort $Test_PWReqsWReqsOTHP
            # Topologicaly sort and resolve the prompts
            $Resolve_PWReqsWReqsOTHP=Resolve-Prompts -Prompts $Convert_Prompts -OriginalPrompts $InteractivePrompts
            if ($Resolve_PWReqsWReqsOTHP) {
                # Add any results to the result variables
                $Resolve_PWReqsWReqsOTHP.GetEnumerator() | ForEach-Object {$ResultsWReqsWReqsOTHP.Add($_.key,$_.Value)}
            }
        }
    }
    # Combine ant results into one Variable
    $ResultsWOReqs.GetEnumerator() | ForEach-Object {$CombinedResults.Add($_.key,$_.Value)}
    $ResultsWReqsWReqsOTHP.GetEnumerator() | ForEach-Object {$CombinedResults.Add($_.key,$_.Value)}
    
    # Iterate over all results
    foreach ($CR in $CombinedResults.keys) {
        # Add each Group to the results variable, if it is not already present
        foreach ($Group in $CombinedResults.$CR.MemberOf) {
            If($Results -notcontains $Group){
                [void] $Results.Add($Group)
            }
        }
    }

    # If any AutoMember of provided resolve them
    if($AutoMemberOf){
        $Resolve_AutoMemberOf=Resolve-AutoMemberOf -InteractivePromptAnswers $CombinedResults -AutoMemberOf $AutoMemberOf -M365License $M365License -FileServerAccess:$FileServerAccess
        If($Resolve_AutoMemberOf){
            # Iterate over all results
            foreach ($RAMO in $Resolve_AutoMemberOf.keys) {
                # Add each Group to the results variable, if it is not already present
                foreach ($Group in $Resolve_AutoMemberOf.$RAMO.MemberOf) {
                    If($Results -notcontains $Group){
                        [void] $Results.Add($Group)
                    }
                }
            }          
        }
    }
    return $Results
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][HashTable]$AutoMemberOf=@{},
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][HashTable]$InteractivePrompts=@{},
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][validateset('Enabled','Disabled','Enforced')][String]$StrongAuthenticationRequiremets,        
        [Parameter(Mandatory=$true)][String]$Domain,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][validateset('TRUE','FALSE')][string]$DistributionList='TRUE',
        [Parameter(Mandatory=$false)][PSCredential]$EMSCredentials,
        [Parameter(Mandatory=$false)][String]$EMSServer,
        [Parameter(Mandatory=$false)][PSCredential]$ADCredentials,
        [Parameter(Mandatory=$false)][Boolean]$Interactive=$true,
        [Parameter(Mandatory=$false)][System.Collections.ArrayList]$AdminGroups,
        [Parameter(Mandatory=$false)][PSCredential]$ADSyncCredentials,
        [Parameter(Mandatory=$true)][String]$ADSyncServer,
        [Parameter(Mandatory=$true)][String]$EmailDomain,
        [Parameter(Mandatory=$true)][String]$FallbackUserOU,
        [Parameter(Mandatory=$true)][String]$Company,
        [Parameter(Mandatory=$false)][String][validateset('Hybrid','Cloud')]$M365DeploymentType='Hybrid'

    )
    begin {
        $CurrentPath = Split-Path -Path $PSCmdlet.MyInvocation.PSCommandPath -Parent
        Write-Verbose('Working Directory is:'+$CurrentPath)
        #Start Logging 
        if ($PSCmdlet.MyInvocation.ExpectingInput){
        Start-Logging -Path $CurrentPath -Name $Domain
        }
        #Grab a DomainController to execute all AD Commands on
        try {
            $DomainController = (Get-ADDomainController -Discover -Domain $Domain -Service "PrimaryDC" -ErrorAction Stop).Hostname.Value
            Write-Verbose('Executing AD commands on: '+ $DomainController)
        }
        catch {
            Write-Error($_.Exception.Message)
            exit
        }
        #Create Quick call for XML Doc Path | Some stuff to handle if the file doesnt exist
        try {
            [xml]$XmlDocument = Get-Content -Path ($CurrentPath + '\BRANCHES.XML') -ErrorAction Stop
            $ADA = $XmlDocument.companies.$Company
        }
        catch [System.Management.Automation.ItemNotFoundException]{
            Write-Warning('Unable to Find BRANCHES.XML, no Branch information will be added')
        }
        #Var to know if a EMS Credential has been set and is a known good
        $ADCredSet=$true
        $EMSCredSet=$false
        $ADSyncCredSet=$false
        #Check if the current user has permissions to make changes in AD
        if (!(Assert-ADPermission -Server $DomainController -AdminGroups $AdminGroups)) {
            Write-Verbose('Requesting credentials with required perms')
            if(!$WhatIfPreference){
                [pscredential]$ADCredentials = Get-Credential -Message 'AD Credentials with sufficient privilages required' -UserName ($Domain+'\')
                if(!$ADCredentials){
                    Write-Error('No AD credentials provided.')
                    exit
                $ADCredSet=$true
                }else{
                    #Check the provided credentials against other systems to cut down on amount of credentials that need to be entered in
                    if($M365DeploymentType -eq 'Hybrid'){
                        if (Assert-EMSPermission -Server $EMSServer -Credential $ADCredentials -and $M365DeploymentType -eq 'Hybrid'){
                            $EMSCredentials = $ADCredentials
                            $EMSCredSet=$True
                        }
                    }
                    if (Assert-ADSyncPermission -Server $ADSyncServer -Credential $ADCredentials){
                        $ADSyncCredentials = $ADCredentials
                        $ADSyncCredSet = $true
                    }                    
                }
            }
        }
        #Detect if the current user or provided credentials are sufficient to get into the EMS Server
        if($M365DeploymentType -eq 'Hybrid'){
            if (!(Assert-EMSPermission -Server $EMSServer) -and !$EMSCredentials) {
                Write-Verbose('Requesting Exchange management credentials.')
                if (!$WhatIfPreference) {
                    [pscredential]$EMSCredentials = Get-Credential -Message 'Exchange Management Credentials for '+$Server+' required'
                    if (!$EMSCredentials){
                        Write-Error('No EMS credentials provided.')
                        exit
                    }
                    $EMSCredSet=$true
                }
            }elseif($EMSCredentials -and !$EMSCredSet){
                if (!(Assert-EMSPermission -Server $EMSServer -Credential $EMSCredentials)){
                    Write-Verbose('Requesting Exchange management credentials.')
                    if (!$WhatIfPreference) {
                        $EMSCredentials = $null
                        [pscredential]$EMSCredentials = Get-Credential -Message 'Exchange Management Credentials for '+$Server+' required'
                        if (!$EMSCredentials){
                            Write-Error('No EMS credentials provided.')
                            exit
                        }
                        $EMSCredSet=$true
                    }
                }
            }
        }
        #Detect if the function is being used in a pipeline
        if ($PSCmdlet.MyInvocation.ExpectingInput -and !$ADSyncCredentials -and !$ADSyncCredSet) {
            Write-Verbose('Pipeline input detected, requesting credentials for: '+$ADSyncServer)
            [pscredential]$ADSyncCredentials = Get-Credential -Message ('Enter Credentials for: '+$ADSyncServer)
            if(!$ADSyncCredentials){
                Write-Error('No ADSync credentials provided.')
                exit
            }
            $ADSyncCredSet=$true
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
                        $M365License = Read-Host("Office 365 License type") -ErrorAction Stop
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
            # Convert the string variables to booleans
            [boolean]$DistributionList = [system.convert]::ToBoolean($DistributionList)
            [boolean]$FileServerAccess = [system.convert]::ToBoolean($FileServerAccess)            
            # Splat containing Parameters for Testing Interactive Prompts
            $SplatTestInteractivePrompts=@{
                FileServerAccess=$FileServerAccess
                M365License=$M365License
            }
            # Conditions to add items to the splat depending on input
            if($InteractivePrompts){$SplatTestInteractivePrompts.Add('InteractivePrompts',$InteractivePrompts)}
            if($AutoMemberOf){$SplatTestInteractivePrompts.Add('AutoMemberOf',$AutoMemberOf)}
            # Only Execute the Prompts if their is aleast one of the below
            if($InteractivePrompts -or $AutoMemberOf){
                # Store the results in the a variable
                $ResultsIP = Test-InteractivePrompts @SplatTestInteractivePrompts
                If($ResultsIP){$MemberOf.AddRange($ResultsIP)}
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
        #If file server access isnt granted dont add the logon script
        if (!$FileServerAccess){
            $logonscript = $false
        }elseif($FileServerAccess){
            Write-Verbose('Adding login script from Selected Branch')
            $logonscript = $ADA.$Branch.logonscript
        }
        $MemberOf = $MemberOf | Sort-Object -Property @{Expression={$_.Trim()}} -Unique
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
        #This splat is used when a cloud deployed is set
        [HashTable]$SplatADNewUser = @{
            Name = $DisplayName
            AccountPassword = $Password
            UserPrincipalName = $UserprincipalName
            DisplayName = $DisplayName
            GivenName = $Firstname
            Surname = $Lastname
            Path = $ADA.$Branch.ou
            SamAccountName = $SamAccountName
            Server=$DomainController
            Whatif = $WhatIfPreference
            Identity = $SamAccountName
            Office = $ADA.$Branch.office
            State = $ADA.$Branch.state
            Company = $ADA.$Branch.company
            Manager = $Manager
            Department = $ADA.$Branch.department
            City = $ADA.$Branch.city
            Country = $ADA.$Branch.country
            ScriptPath = $logonscript
            PostalCode = $ADA.$Branch.post_code
            POBox = $ADA.$Branch.po_box
            StreetAddress = $ADA.$Branch.street
            OfficePhone = $OfficePhone
            MobilePhone = $MobilePhone
            Title = $Title                
        }
        #Set the AD Attributes for the new user
        #this splat isused when a Hybrid deployment is specified
        [HashTable]$SplatADAttributes = @{
            server = $DomainController
            Identity = $SamAccountName
            Office = $ADA.$Branch.office
            State = $ADA.$Branch.state
            Company = $ADA.$Branch.company
            Manager = $Manager
            Department = $ADA.$Branch.department
            City = $ADA.$Branch.city
            Country = $ADA.$Branch.country
            ScriptPath = $logonscript
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
        foreach($Key in @($SplatADAttributes.Keys) ){
            if (-not $SplatADAttributes[$Key]) {
                $SplatADAttributes.Remove($Key)
                Write-Verbose("SplatADAttributes: Removed Empty Key: "+$Key)
            }

        }
        foreach($Key in @($SplatADNewUser.Keys) ){
            if (-not $SplatADNewUser[$Key]) {
                $SplatADNewUser.Remove($Key)
                Write-Verbose("SplatADNewUser: Removed Empty Key: "+$Key)
            }

        }        
        #endregion DataValidation
        #region DataConfirmation
        #Chance to confirm some account details
        if ($Interactive) {
            Write-Verbose('------------------------------')
            Write-Verbose('Active Directory Details')
            Write-Verbose('------------------------------')
            if($M365DeploymentType -eq 'Hybrid'){$SplatADAttributes | Format-table -Verbose}else{$SplatADNewUser | Format-table -Verbose}
            Write-Verbose ('------------------------------')
            Write-Verbose('AD Group Details')
            Write-Verbose('------------------------------')
            $MemberOf | Format-List -Verbose
            Write-Verbose('------------------------------')
            if($M365DeploymentType -eq 'Hybrid'){
                Write-Verbose('Exchange Details')
                Write-Verbose('------------------------------')
                $SplatExchange | Format-table -Verbose
                Write-Verbose('------------------------------')
            }
            if(!(Test-UserContinue -Message 'Above are the details for the user to be created, if the details are correct proceed otherwise cancel')){
                Write-Verbose('User Cancelled Terminating')
                Stop-Transcript
                Exit
            }
        }
        #endregion DataConfirmation
        #Check if the current user has permissions to make changes in AD
        if (!(Assert-ADPermission -Server $DomainController -AdminGroups $AdminGroups) -and $ADCredentials) {
            Write-Verbose('Adding provided credentials to Splats')
            $SplatADAttributes.Add('Credential',$ADCredentials)
            $SplatADGetUser.Add('Credential',$ADCredentials)
            $SplatADGroups.Add('Credential',$ADCredentials)
            $SplatADUserSynced.Add('Credential',$ADCredentials)
            $SplatADNewUser.Add('Credential',$ADCredentials)
        }
        #All Variables have been collected and formatted how we wanted. Now lets make the account.
        if($M365DeploymentType -eq 'Hybrid'){
            if(!(Assert-EMSUExists -SamAccountName $SamAccountName -Server $EMSServer -Credential $EMSCredentials -WhatIf:$WhatIfPreference)){
                Write-Verbose('This user will be created using Microsoft 365 Hybrid deployment.')
                Write-Verbose($SamAccountName+' does not exists on EMS; proceeding')
                if ($PSCmdlet.ShouldProcess($EMSServer, 'New-RemoteMailbox -Password "'+$SplatExchange.Password+'" -Name "'+$SplatExchange.Name+'" UserprincipalName "'+$SplatExchange.UserPrincipalName+'" Alias "'+$SplatExchange.Alias+'" DisplayName "'+$SplatExchange.DisplayName+'" Firstname "'+$SplatExchange.Firstname+'" Lastname "'+$SplatExchange.Lastname+'" OnPremisesOrganizationalUnit "'+$SplatExchange.OnPremisesOrganizationalUnit+'" SamAccountName "'+$SplatExchange.SamAccountName+'" Archive "'+$SplatExchange.Archive+'" DomainController "'+$SplatExchange.DomainController)) {
                    New-RemoteMailbox @SplatExchange -ErrorAction Stop
                }
                #Wait for the user to Sync then set user attributes
                if ((Wait-ADUSynced @SplatADUserSynced) -or $WhatIfPreference) {
                    Write-Verbose('Found "'+$SamAccountName+'" in AD updating user Attributes')
                    if ($PSCmdlet.ShouldProcess($DomainController, 'Set-ADUser -Server "'+$SplatADAttributes.Server+'" -Identity "'+$SplatADAttributes.Identity+'" -Office "'+$SplatADAttributes.Offic+'" -State "'+$SplatADAttributes.State+'" -Company "'+$SplatADAttributes.Company+'" -Manager "'+$SplatADAttributes.Manager+'" -Department "'+$SplatADAttributes.Department+'" -City "'+$SplatADAttributes.City+'" -Country "'+$SplatADAttributes.Country+'" -ScriptPath "'+$SplatADAttributes.ScriptPath+'" -PostalCode "'+$SplatADAttributes.PostalCode+'" -POBox "'+$SplatADAttributes.POBox+'" -StreetAddress "'+$SplatADAttributes.StreetAddress+'" -OfficePhone "'+$SplatADAttributes.OfficePhone+'" -MobilePhone "'+$SplatADAttributes.MobilePhone+'" -Title "'+$SplatADAttributes.Title)) {                
                    Set-ADUser @SplatADAttributes
                    Get-ADUser @SplatADGetUser
                    }
                    #Add the user to specified groups
                    if($MemberOf){
                        Set-ADUGroups @SplatADGroups
                    }else {
                        Write-Verbose('No groups specified')
                    }
                }
                #Start an Delta Sync on AzureAD Connect
                $CurrentUser = (whoami /UPN)
                if (!$CurrentUser.contains($EmailDomain)){
                    Write-Verbose('RunAs User Email Domain does not contain: '+$EmailDomain)
                    Write-Verbose('AzureAD Connection Credentials will need to be manually entered')
                    Test-AADConnected -CredentialPrompt -WhatIf:$false
                }
                Write-Verbose('Starting AzureAD Connect Sync')
                if((Sync-Directories -Server $ADSyncServer -Credential $ADSyncCredentials -AzureActiveDirectory -ErrorAction Stop -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                    if((Wait-AADUSynced -UserPrincipalName $UserprincipalName -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                        if($M365License){
                            Write-Verbose('Trying to assign a '+$M365License+' License to ; '+$UserprincipalName)
                            if( !(Set-AADULicense -UserPrincipalName $UserprincipalName -LicenseType $M365License -Whatif:$WhatIfPreference) -and $Interactive){
                                Test-UserContinue -Message 'No Microsoft 365 License assigned. Press any key to continue'
                            }
                        }
                        Write-Verbose('Setting user MFA')                      
                        Set-MSolUMFA -UserPrincipalName $UserprincipalName -StrongAuthenticationRequiremets $StrongAuthenticationRequiremets -Whatif:$WhatIfPreference
                    }
                }else{
                    Write-Verbose('No license specified for user, nothing will be assigned')
                }
            }else{
                Write-Warning($SamAccountName+' already exists on EMS; skipping')
            }
        }
        if(!(Assert-ADUExists -SamAccountName $SamAccountName -Server $DomainController -Credential $EMSCredentials -WhatIf:$WhatIfPreference) -and ($M365DeploymentType -eq 'Cloud')){
            Write-Verbose('This user will be created using Microsoft 365 Cloud deployment.')
            Write-Verbose($SamAccountName+' does not exists on AD; proceeding')
            if ($PSCmdlet.ShouldProcess($DomainController, 'New-ADuser -Password "'+$SplatExchange.Password+'" -Name "'+$SplatExchange.Name+'" UserprincipalName "'+$SplatExchange.UserPrincipalName+'" DisplayName "'+$SplatExchange.DisplayName+'" GivenName "'+$SplatExchange.GivenName+'" Surname "'+$SplatExchange.Surname+'" Path "'+$SplatExchange.Path+'" SamAccountName "'+$SplatExchange.SamAccountName+'" Server "'+$SplatExchange.Server+'Set-ADUser -Server "'+$SplatADNewUser.Server+'" -Identity "'+$SplatADNewUser.Identity+'" -Office "'+$SplatADNewUser.Offic+'" -State "'+$SplatADNewUser.State+'" -Company "'+$SplatADNewUser.Company+'" -Manager "'+$SplatADNewUser.Manager+'" -Department "'+$SplatADNewUser.Department+'" -City "'+$SplatADNewUser.City+'" -Country "'+$SplatADNewUser.Country+'" -ScriptPath "'+$SplatADNewUser.ScriptPath+'" -PostalCode "'+$SplatADNewUser.PostalCode+'" -POBox "'+$SplatADNewUser.POBox+'" -StreetAddress "'+$SplatADNewUser.StreetAddress+'" -OfficePhone "'+$SplatADNewUser.OfficePhone+'" -MobilePhone "'+$SplatADNewUser.MobilePhone+'" -Title "'+$SplatADNewUser.Title)) {
                New-ADUser @SplatADNewUser -ErrorAction Stop
                Get-ADUser @SplatADGetUser
            }
            #Wait for user to Sync to Active Directory
            if ((Wait-ADUSynced @SplatADUserSynced) -or $WhatIfPreference) {
                if($MemberOf){
                    Set-ADUGroups @SplatADGroups
                }else {
                    Write-Verbose('No groups specified')
                }
            }
            #Start an Delta Sync on AzureAD Connect
            $CurrentUser = (whoami /UPN)
            if (!$CurrentUser.contains($EmailDomain)){
                Write-Verbose('RunAs User Email Domain does not contain: '+$EmailDomain)
                Write-Verbose('AzureAD Connection Credentials will need to be manually entered')
                Test-AADConnected -CredentialPrompt -whatif:$False
            }
            Write-Verbose('Starting AzureAD Connect Sync')
            if((Sync-Directories -Server $ADSyncServer -Credential $ADSyncCredentials -AzureActiveDirectory -ErrorAction Stop -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                if((Wait-AADUSynced -UserPrincipalName $UserprincipalName -Whatif:$WhatIfPreference) -or $WhatIfPreference){
                    if($M365License){
                        Write-Verbose('Trying to assign a '+$M365License+' License to ; '+$UserprincipalName)
                        if( !(Set-AADULicense -UserPrincipalName $UserprincipalName -LicenseType $M365License -Whatif:$WhatIfPreference) -and $Interactive){
                            Test-UserContinue -Message 'No Microsoft 365 License assigned. Press any key to continue'
                        }
                    }
                    Write-Verbose('Setting user MFA')                      
                    Set-MSolUMFA -UserPrincipalName $UserprincipalName -StrongAuthenticationRequiremets $StrongAuthenticationRequiremets -Whatif:$WhatIfPreference
                }
            }else{
                Write-Verbose('No license specified for user, nothing will be assigned')
            }
        }else{
            Write-Warning($SamAccountName+' already exists in AD; skipping')
        }
    }
    end {Stop-Transcript}
}