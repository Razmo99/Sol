function New-ManagedPSSession {
    <#
    .SYNOPSIS
        Creates a PowerShell session with standardized error handling and credential management
    .DESCRIPTION
        Wraps New-PSSession with enhanced error handling and optional credential prompting.
        Supports all New-PSSession parameters via dynamic parameter passthrough.
    .PARAMETER PromptForCredentials
        Switch to prompt for credentials if authentication fails
    .OUTPUTS
        System.Management.Automation.Runspaces.PSSession
    .EXAMPLE
        New-ManagedPSSession -ComputerName "Server01" -PromptForCredentials
    .EXAMPLE
        New-ManagedPSSession -ConnectionUri "http://exchange01/powershell" -ConfigurationName "Microsoft.Exchange"
    .EXAMPLE
        # All New-PSSession parameters available with IntelliSense:
        New-ManagedPSSession -ComputerName "DC01" -Authentication Kerberos -SessionOption $SessionOptions
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param (
        [Parameter(Mandatory = $false)]
        [Switch]$PromptForCredentials
    )

    DynamicParam {
        return Get-DynamicParameters -CommandName 'New-PSSession'
    }

    Process {
        # Extract New-PSSession parameters using our utility
        $SessionParameters = Get-DynamicParameterValues -CommandName 'New-PSSession' -BoundParameters $PSBoundParameters

        # Determine target for logging
        $TargetName = if ($SessionParameters.ContainsKey('ConnectionUri')) {
            $SessionParameters['ConnectionUri']
        } elseif ($SessionParameters.ContainsKey('ComputerName')) {
            $SessionParameters['ComputerName']
        } else {
            'localhost'
        }

        # Guard: WhatIf check
        if (!$PSCmdlet.ShouldProcess($TargetName, "Creating PSSession")) { return }

        # First attempt
        try {
            Write-Log -Level Debug -Message "Creating PSSession to $TargetName"
            $Session = New-PSSession @SessionParameters
            Write-Log -Level Debug -Message "Successfully created PSSession to $TargetName"
            return $Session
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            # Guard: Only handle auth failures if prompting is enabled and no credential was provided
            if (!($_.Exception.Message -match 'AuthZ-CmdletAccessDeniedException|Access.*denied')) {
                Write-Log -Level Error -Message "PSRemoting transport error: $($_.Exception.Message)" -ExceptionInfo $_
                throw
            }

            if (!$PromptForCredentials -or $SessionParameters.ContainsKey('Credential')) {
                Write-Log -Level Error -Message "Access denied connecting to $TargetName" -ExceptionInfo $_
                throw
            }

            # Prompt for alternative credentials
            Write-Log -Level Warning -Message "Authentication failed for $TargetName, prompting for credentials"
            $AlternativeCredential = Get-Credential -Message "Enter credentials for $TargetName"

            if (!$AlternativeCredential) {
                Write-Log -Level Error -Message "No alternative credentials provided"
                throw
            }

            # Guard: WhatIf check for retry
            if (!$PSCmdlet.ShouldProcess($TargetName, "Creating PSSession with alternative credentials")) { return }

            # Second attempt with alternative credentials
            $SessionParameters['Credential'] = $AlternativeCredential
            Write-Log -Level Debug -Message "Retrying PSSession creation with alternative credentials"
            $Session = New-PSSession @SessionParameters
            Write-Log -Level Debug -Message "Successfully created PSSession with alternative credentials"
            return $Session
        }
        catch {
            Write-Log -Level Error -Message "Failed to create PSSession to $TargetName`: $($_.Exception.Message)" -ExceptionInfo $_
            throw
        }
    }
}