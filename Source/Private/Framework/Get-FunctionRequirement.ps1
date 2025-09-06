using namespace System.Collections.Generic
using namespace System.Management.Automation

function Get-FunctionRequirement {
    <#
    .SYNOPSIS
    Analyzes a function's parameter requirements for workflow dependency mapping.

    .DESCRIPTION
    Uses PowerShell reflection to examine a function's parameters and determine
    what inputs are required. Returns structured information about mandatory
    and optional parameters with their types for workflow validation.

    .PARAMETER FunctionName
    The name of the function to analyze.

    .INPUTS
    System.String. Function name to analyze.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable containing parameter information with the structure:
    - MandatoryParameters: Array of parameter objects with Name, Type, and IsMandatory
    - OptionalParameters: Array of parameter objects with Name, Type, and IsMandatory
    - AllParameters: Combined array of all parameters

    .EXAMPLE
    Get-FunctionRequirement -FunctionName "New-CompanyADUser"

    Returns parameter analysis for the specified function.

    .NOTES
    This function is part of the Sol orchestration framework's introspection engine.
    It supports the static validation system by providing parameter metadata.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FunctionName
    )

    begin {
        Write-Log -Level Debug -Message 'Starting function requirements analysis for {0}' -Arguments $FunctionName
    }

    process {
        if ($PSCmdlet.ShouldProcess($FunctionName, 'Analyze Function Requirements')) {
            try {
                $functionInfo = Get-Command -Name $FunctionName -CommandType Function -ErrorAction Stop

                $mandatoryParams = [List[hashtable]]::new()
                $optionalParams = [List[hashtable]]::new()

                foreach ($param in $functionInfo.Parameters.Values) {
                    $isMandatory = $param.Attributes | Where-Object { $_ -is [ParameterAttribute] -and $_.Mandatory }

                    $paramInfo = @{
                        Name = $param.Name
                        Type = $param.ParameterType
                        IsMandatory = [bool]$isMandatory
                    }

                    if ($paramInfo.IsMandatory) {
                        $mandatoryParams.Add($paramInfo)
                        Write-Log -Level Debug -Message 'Found mandatory parameter: {0} ({1})' -Arguments @($param.Name, $param.ParameterType.Name)
                    } else {
                        $optionalParams.Add($paramInfo)
                        Write-Log -Level Debug -Message 'Found optional parameter: {0} ({1})' -Arguments @($param.Name, $param.ParameterType.Name)
                    }
                }

                $allParams = [List[hashtable]]::new()
                $allParams.AddRange($mandatoryParams)
                $allParams.AddRange($optionalParams)

                $result = @{
                    MandatoryParameters = $mandatoryParams.ToArray()
                    OptionalParameters = $optionalParams.ToArray()
                    AllParameters = $allParams.ToArray()
                }

                Write-Log -Level Debug -Message 'Function analysis complete: {0} mandatory, {1} optional parameters' -Arguments @($mandatoryParams.Count, $optionalParams.Count)
                return $result
            }
            catch {
                Write-Log -Level Error -Message 'Failed to analyze function {0}' -Arguments $FunctionName -ExceptionInfo $_
                throw "Function requirements analysis failed for '$FunctionName': $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Log -Level Debug -Message 'Function requirements analysis completed for {0}' -Arguments $FunctionName
    }
}