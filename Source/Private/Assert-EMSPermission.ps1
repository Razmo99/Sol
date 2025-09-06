function Assert-EMSPermission {
    <#
    .SYNOPSIS
        Asserts the current user can create a PSSession to the specified Exchange server
    .DESCRIPTION
        Tests Exchange Management Shell connectivity by creating and immediately removing a PSSession
    .PARAMETER Server
        Exchange Management server to test against
    .PARAMETER EMSAuth
        Authentication method to use when creating the PSSession
    .PARAMETER Credential
        Optional credentials for authentication
    .OUTPUTS
        System.Boolean - True if connection succeeds, False if access denied
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [String]$EMSAuth = "Kerberos",

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    Process {
        # Guard: WhatIf handling
        if ($WhatIfPreference) { return $true }

        try {
            $Session = New-ManagedPSSession -ConnectionUri "http://$Server/Powershell" -ConfigurationName 'Microsoft.Exchange' -Authentication $EMSAuth -Credential $Credential
            Remove-PSSession -Session $Session
            return $true
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            if ($_.Exception.Message -match 'AuthZ-CmdletAccessDeniedException') {
                return $false
            }
            Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            return $false
        }
        catch {
            Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            return $false
        }
    }
}
