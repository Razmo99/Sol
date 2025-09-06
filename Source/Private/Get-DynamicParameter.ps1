using namespace System.Management.Automation
using namespace System.Collections.Generic

function Get-DynamicParameter {
    <#
    .SYNOPSIS
        Creates dynamic parameters for wrapping PowerShell commands with full IntelliSense support
    .DESCRIPTION
        Generates a RuntimeDefinedParameterDictionary containing all parameters from the specified
        command, enabling wrapper functions to provide complete parameter passthrough with IntelliSense
    .PARAMETER CommandName
        Name of the command to generate dynamic parameters for
    .PARAMETER ExcludeParameters
        Array of parameter names to exclude from the dynamic parameters
    .PARAMETER IncludeCommonParameters
        Switch to include PowerShell common parameters (Verbose, Debug, etc.)
    .OUTPUTS
        System.Management.Automation.RuntimeDefinedParameterDictionary
    .EXAMPLE
        # Basic wrapper function with full parameter passthrough
        function Get-MyChildItem {
            [CmdletBinding()]
            param (
                [Switch]$LogResults
            )

            DynamicParam {
                return Get-DynamicParameter -CommandName 'Get-ChildItem'
            }

            Process {
                # Simple one-liner parameter extraction
                $ChildItemParams = Get-DynamicParameterValue -CommandName 'Get-ChildItem' -BoundParameters $PSBoundParameters

                # Call original command with enhanced functionality
                $Results = Get-ChildItem @ChildItemParams

                if ($LogResults) {
                    Write-Log -Level Debug -Message "Found $($Results.Count) items"
                }

                return $Results
            }
        }

        # Usage: Get-MyChildItem -Path C:\temp -Filter "*.txt" -LogResults
        # All Get-ChildItem parameters available with IntelliSense!

    .EXAMPLE
        # Exclude specific parameters you want to handle differently
        DynamicParam {
            return Get-DynamicParameter -CommandName 'Get-ADUser' -ExcludeParameters @('Server', 'Credential')
        }
    #>
    [CmdletBinding()]
    [OutputType([RuntimeDefinedParameterDictionary])]
    param (
        [Parameter(Mandatory = $true)]
        [String]$CommandName,

        [Parameter(Mandatory = $false)]
        [String[]]$ExcludeParameters = @(),

        [Parameter(Mandatory = $false)]
        [Switch]$IncludeCommonParameters
    )

    Process {
        try {
            # Get command metadata
            $Command = Get-Command -Name $CommandName -ErrorAction Stop
            $DynamicParams = @{}

            # Get common parameter names from the PowerShell framework
            $CommonParameterNames = [string[]][Internal.CommonParameters].GetProperties().Name

            # Use generic list for performance
            $ExcludeList = [List[String]]::new()
            $ExcludeList.AddRange($ExcludeParameters)

            if (!$IncludeCommonParameters) {
                $ExcludeList.AddRange($CommonParameterNames)
            }

            # Create dynamic parameters for each command parameter
            foreach ($Parameter in $Command.Parameters.Values) {
                # Skip excluded parameters
                if ($ExcludeList.Contains($Parameter.Name)) {
                    continue
                }

                # Create runtime parameter with all original attributes
                $RuntimeParam = [RuntimeDefinedParameter]::new(
                    $Parameter.Name,
                    $Parameter.ParameterType,
                    $Parameter.Attributes
                )

                $DynamicParams.Add($Parameter.Name, $RuntimeParam)
            }

            Write-Log -Level Debug -Message "Generated {0} dynamic parameters for command '{1}'" -Arguments $DynamicParams.Count, $CommandName
            $Result = [RuntimeDefinedParameterDictionary]::new()
            foreach ($Key in $DynamicParams.Keys) {
                $Result.Add($Key, $DynamicParams[$Key])
            }
            return $Result
        }
        catch {
            Write-Log -Level Error -Message "Failed to generate dynamic parameters for command '{0}': {1}" -Arguments $CommandName, $_.Exception.Message -ExceptionInfo $_
            return [RuntimeDefinedParameterDictionary]::new()
        }
    }
}