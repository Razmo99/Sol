function Test-ManagedPSSession {
    <#
    .SYNOPSIS
        Tests if a PSSession is active and optionally validates specific functionality
    .DESCRIPTION
        Validates PSSession state and optionally tests command availability
    .PARAMETER Session
        PSSession object to test
    .PARAMETER ConfigurationName
        Expected configuration name for validation
    .PARAMETER TestCommand
        Optional command to test session functionality
    .OUTPUTS
        System.Boolean
    .INPUTS
        System.Management.Automation.Runspaces.PSSession
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory = $false)]
        [String]$ConfigurationName,

        [Parameter(Mandatory = $false)]
        [String]$TestCommand
    )

    Process {
        # Guard: Check session state
        if ($Session.State -ne 'Opened') {
            Write-Log -Level Debug -Message "PSSession is not in Opened state. Current state: $($Session.State)"
            return $false
        }

        # Guard: Validate configuration name if specified
        if ($ConfigurationName -and $Session.ConfigurationName -ne $ConfigurationName) {
            Write-Log -Level Debug -Message "PSSession configuration mismatch. Expected: $ConfigurationName, Actual: $($Session.ConfigurationName)"
            return $false
        }

        # Guard: Test specific command if provided
        if ($TestCommand) {
            try {
                $CommandTest = Invoke-Command -Session $Session -ScriptBlock { Get-Command $using:TestCommand -ErrorAction Stop } -ErrorAction Stop
                if (!$CommandTest) {
                    Write-Log -Level Debug -Message "Test command '$TestCommand' not found in session"
                    return $false
                }
            }
            catch {
                Write-Log -Level Debug -Message "Test command '$TestCommand' failed: $($_.Exception.Message)"
                return $false
            }
        }

        Write-Log -Level Debug -Message "PSSession validation passed"
        return $true
    }
}