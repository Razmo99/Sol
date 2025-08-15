function Wait-UntilTrue {
    <#
    .SYNOPSIS
    Generic function that waits until a condition becomes true with timeout.
    .DESCRIPTION
    Repeatedly executes a condition scriptblock until it returns $true or timeout is reached.
    Uses configurable sleep intervals between checks.
    .PARAMETER Condition
        ScriptBlock that returns a boolean value to check
    .PARAMETER TimeoutSeconds
        Maximum time to wait in seconds (default: 120)
    .PARAMETER SleepSeconds
        Interval between condition checks in seconds (default: 5)
    .PARAMETER Context
        Descriptive name for logging purposes (default: "condition")
    .PARAMETER SuccessMessage
        Message to log when condition becomes true
    .PARAMETER TimeoutMessage
        Message to log when timeout is reached
    .INPUTS
        None
    .OUTPUTS
        System.Boolean
        Returns $true if condition becomes true, $false if timeout reached
    .EXAMPLE
    # Simple condition check
    Wait-UntilTrue -Condition { Test-Path "C:\temp\file.txt" } -TimeoutSeconds 30
    
    .EXAMPLE
    # Using variables from parent scope - requires $using: scope modifier
    $UserName = "john.doe"
    $Domain = "contoso.com"
    
    Wait-UntilTrue -Condition { 
        Get-ADUser -Identity $using:UserName -Server $using:Domain -ErrorAction SilentlyContinue 
    } -TimeoutSeconds 60 -Context "AD user sync for $UserName"
    
    .EXAMPLE
    # Using splat parameters from parent scope
    $SplatParams = @{
        Identity = "john.doe"
        Server = "contoso.com"
        ErrorAction = "SilentlyContinue"
    }
    
    Wait-UntilTrue -Condition { Get-ADUser @using:SplatParams } `
                   -TimeoutSeconds 120 `
                   -Context "User validation"
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$Condition,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120,
        
        [Parameter(Mandatory = $false)]
        [int]$SleepSeconds = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$Context = "condition",
        
        [Parameter(Mandatory = $false)]
        [string]$SuccessMessage,
        
        [Parameter(Mandatory = $false)]
        [string]$TimeoutMessage
    )
    
    Begin {}
    
    Process {
        $TimeEnd = (Get-Date).AddSeconds($TimeoutSeconds)
        
        if ($PSCmdlet.ShouldProcess($Context, "Wait for condition")) {
            while ($true) {
                try {
                    if (& $Condition) {
                        if ($SuccessMessage) {
                            Write-Log -Level Debug -Message $SuccessMessage
                        } else {
                            Write-Log -Level Debug -Message "Condition '{0}' became true" -Arguments $Context
                        }
                        return $true
                    }
                }
                catch {
                    Write-Log -Level Debug -Message "Condition check failed: {0}" -Arguments $_.Exception.Message
                }
                
                if ((Get-Date) -ge $TimeEnd) {
                    if ($TimeoutMessage) {
                        Write-Log -Level Warning -Message $TimeoutMessage
                    } else {
                        Write-Log -Level Warning -Message "Timeout reached after {0} seconds waiting for '{1}'" -Arguments $TimeoutSeconds, $Context
                    }
                    return $false
                }
                
                Write-Log -Level Debug -Message "Sleeping {0} seconds..." -Arguments $SleepSeconds
                Start-Sleep -Seconds $SleepSeconds
            }
        }
    }
    
    End {}
}