function ConvertTo-CommandString {
    <#
    .SYNOPSIS
    Converts a hashtable of parameters to an executable PowerShell command string.

    .DESCRIPTION
    Takes a command name and hashtable of parameters and generates a properly formatted
    PowerShell command string that can be copied and pasted for execution.
    
    Use [ordered] hashtables to preserve parameter order as they appear in PowerShell help:
    $params = [ordered]@{ Identity = "user1"; Server = "dc1" }

    .PARAMETER CommandName
    The PowerShell command name (e.g., "Get-ADUser", "New-RemoteMailbox").

    .PARAMETER Parameters
    Hashtable or ordered hashtable containing parameter names and values.
    Use [ordered]@{} to preserve the natural parameter order of PowerShell commands.

    .PARAMETER IncludeWhatIf
    Include -WhatIf parameter in output even when present in the hashtable.
    By default, -WhatIf is excluded from the generated command string.

    .EXAMPLE
    $params = [ordered]@{ Identity = "john.doe"; Server = "dc1.contoso.com" }
    ConvertTo-CommandString -CommandName "Get-ADUser" -Parameters $params
    # Output: Get-ADUser -Identity "john.doe" -Server "dc1.contoso.com"

    .EXAMPLE
    $params = @{ Name = "Test User"; Password = $securePassword; Enabled = $true }
    ConvertTo-CommandString -CommandName "New-ADUser" -Parameters $params
    # Output: New-ADUser -Enabled -Name "Test User" -Password $SecurePassword
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CommandName,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeWhatIf
    )
    
    $commandParts = [System.Collections.Generic.List[string]]::new()
    $commandParts.Add($CommandName)
    
    # Use ordered hashtable keys to preserve parameter order as specified by user
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        
        # Skip WhatIf unless explicitly requested
        if ($key -eq 'Whatif' -and !$IncludeWhatIf) {
            continue
        }
        
        # Handle null values
        if ($null -eq $value) {
            continue
        }

        # Handle different parameter value types
        switch ($value.GetType().Name) {
            'String' {
                if ([string]::IsNullOrWhiteSpace($value)) {
                    continue
                }
                $commandParts.Add("-$key `"$value`"")
            }
            'Boolean' {
                if ($value) {
                    $commandParts.Add("-$key")
                }
            }
            'SecureString' {
                $commandParts.Add("-$key `$SecurePassword")
            }
            'Int32' {
                $commandParts.Add("-$key $value")
            }
            { $_ -in 'Hashtable', 'OrderedDictionary' } {
                $hashPairs = [System.Collections.Generic.List[string]]::new()
                # Preserve order for OrderedDictionary, sort for regular Hashtable
                $hashKeys = if ($value -is [System.Collections.Specialized.OrderedDictionary]) {
                    $value.Keys
                } else {
                    $value.Keys | Sort-Object
                }
                foreach ($hashKey in $hashKeys) {
                    $hashPairs.Add("$hashKey='$($value[$hashKey])'")
                }
                $hashString = "@{" + ($hashPairs -join "; ") + "}"
                $commandParts.Add("-$key $hashString")
            }
            'Object[]' {
                $arrayItems = $value | ForEach-Object { "'$_'" }
                $arrayString = "@(" + ($arrayItems -join ", ") + ")"
                $commandParts.Add("-$key $arrayString")
            }
            'ArrayList' {
                $arrayItems = $value | ForEach-Object { "'$_'" }
                $arrayString = "@(" + ($arrayItems -join ", ") + ")"
                $commandParts.Add("-$key $arrayString")
            }
            default {
                if ($null -ne $value) {
                    # Handle other collection types
                    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                        $arrayItems = $value | ForEach-Object { "'$_'" }
                        $arrayString = "@(" + ($arrayItems -join ", ") + ")"
                        $commandParts.Add("-$key $arrayString")
                    } else {
                        $commandParts.Add("-$key `"$value`"")
                    }
                }
            }
        }
    }
    
    return ($commandParts -join ' ')
}