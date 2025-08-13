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
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$Server,
        [parameter(Mandatory = $false)][String][Validateset('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]$EMSAuth = "Kerberos",
        [parameter(Mandatory = $false)][pscredential]$Credential
    )
    Begin {}
    Process {
        [hashtable]$SplatNewPSSession = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = 'http://' + $Server + '/Powershell'
            Authentication    = $EMSAuth
            ErrorAction       = 'Stop'
        }
        #Add Credentials if presented
        if ($Credential) {
            Write-Log -Level Debug -Message 'Exchange Management Credentials provided'
            $SplatNewPSSession.Add('Credential', $Credential)
        }
        try {
            if ($PSCmdlet.ShouldProcess($Server, "Testing New-PSSession on:")) {
                $Session = New-PSSession @SplatNewPSSession
                $Session | Remove-PSSession
                return $true
            }
            if ($WhatIfPreference) { return $true }
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            if ($_.Exception.Message.contains("AuthZ-CmdletAccessDeniedException")) {
                return $false
            }
            else {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
        }
        catch {
            Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
        }
    }
    End {}
}
