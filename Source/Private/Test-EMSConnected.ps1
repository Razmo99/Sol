function Test-EMSConnected {
    <#
    .SYNOPSIS
        Tests if Exchange Management Shell connection is active and functional
    .DESCRIPTION
        Verifies EMS session exists, is open, and required cmdlets are available.
        Removes stale sessions if cmdlets are unavailable.
    .OUTPUTS
        System.Boolean - True if EMS is connected and functional, False otherwise
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]
    param()

    Process {
        # Find EMS session
        $EMSSession = Get-PSSession | Where-Object {
            $_.State -eq 'Opened' -and $_.ConfigurationName -eq 'Microsoft.Exchange'
        } | Select-Object -First 1

        # Check if EMS cmdlets are available
        $EMSCommandAvailable = Get-Command New-RemoteMailbox -ErrorAction SilentlyContinue

        if (!$EMSCommandAvailable) {
            Write-Log -Level Debug -Message 'EMS cmdlets not available'
            if ($EMSSession) {
                Write-Log -Level Debug -Message 'Removing stale EMS session'
                Remove-PSSession -Session $EMSSession
            }
            return $false
        }

        # Test session is functional using utility
        if ($EMSSession -and (Test-ManagedPSSession -Session $EMSSession -ConfigurationName 'Microsoft.Exchange' -TestCommand 'New-RemoteMailbox')) {
            Write-Log -Level Debug -Message 'EMS session is active and functional'
            return $true
        }

        Write-Log -Level Debug -Message 'EMS session validation failed'
        return $false
    }
}
