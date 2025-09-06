function Import-EMS {
    <#
    .SYNOPSIS
        Establishes Exchange Management Shell connection and imports required cmdlets
    .DESCRIPTION
        Checks for existing EMS connection, creates new session if needed, and imports
        Exchange cmdlets into global scope for use throughout the module
    .PARAMETER Server
        Exchange server FQDN to connect to
    .PARAMETER EMSAuth
        Authentication method to use when creating the PSSession
    .PARAMETER Credential
        Optional credentials for authentication
    .OUTPUTS
        System.Boolean - True if connected and cmdlets imported, False otherwise
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [String]$EMSAuth = "Kerberos",

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    Process {
        # Check for existing EMS session
        $ExistingSession = Get-PSSession | Where-Object {
            $_.State -eq 'Opened' -and $_.ConfigurationName -eq 'Microsoft.Exchange'
        }

        if ($ExistingSession) {
            Write-Log -Level Debug -Message 'EMS session already exists'
            return Test-EMSConnected
        }

        # Guard: WhatIf check
        if (!$PSCmdlet.ShouldProcess($Server, 'Import-PSSession')) { return $false }

        try {
            Write-Log -Level Debug -Message "Connecting to Exchange server $Server using $EMSAuth authentication"

            # Create EMS session with credential prompting enabled
            $EMS = New-ManagedPSSession -ConnectionUri "http://$Server/Powershell" -ConfigurationName 'Microsoft.Exchange' -Authentication $EMSAuth -Credential $Credential -PromptForCredentials

            Write-Log -Level Debug -Message 'Importing Exchange cmdlets into global scope'
            Import-Module (Import-PSSession $EMS -DisableNameChecking -AllowClobber -ErrorAction Stop -CommandName Get-RemoteMailbox, New-RemoteMailbox) -Global

            return $true
        }
        catch {
            Write-Log -Level Error -Message "Failed to import EMS from $Server`: $($_.Exception.Message)" -ExceptionInfo $_
            return $false
        }
    }
}