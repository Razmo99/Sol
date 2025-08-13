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
