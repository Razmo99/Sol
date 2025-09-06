using namespace System.Collections.Generic
using namespace System.Management.Automation

function Get-FunctionOutput {
    <#
    .SYNOPSIS
    Analyzes a function's ProducesOutput attributes for workflow dependency mapping.

    .DESCRIPTION
    Uses PowerShell reflection to examine a function's ProducesOutput attributes
    and determine what outputs the function provides. Returns structured information
    about declared outputs with their names and types for workflow validation.

    .PARAMETER FunctionName
    The name of the function to analyze.

    .INPUTS
    System.String. Function name to analyze.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable containing output information with the structure:
    - OutputDeclarations: Array of output objects with OutputName and OutputType
    - OutputNames: Array of output names for quick lookup
    - HasOutputs: Boolean indicating if function has any outputs

    .EXAMPLE
    Get-FunctionOutput -FunctionName "New-CompanyADUser"

    Returns output analysis for the specified function.

    .NOTES
    This function is part of the Sol orchestration framework's introspection engine.
    It supports the static validation system by providing output metadata.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FunctionName
    )

    begin {
        Write-Log -Level Debug -Message 'Starting function output analysis for {0}' -Arguments $FunctionName
    }

    process {
        if ($PSCmdlet.ShouldProcess($FunctionName, 'Analyze Function Outputs')) {
            try {
                $functionInfo = Get-Command -Name $FunctionName -CommandType Function -ErrorAction Stop

                $outputDeclarations = [List[hashtable]]::new()
                $outputNames = [List[string]]::new()

                $producesOutputAttribs = $functionInfo.ScriptBlock.Attributes | Where-Object { $_ -is [ProducesOutputAttribute] }

                foreach ($attrib in $producesOutputAttribs) {
                    $outputInfo = @{
                        OutputName = $attrib.OutputName
                        OutputType = $attrib.OutputType
                    }

                    $outputDeclarations.Add($outputInfo)
                    $outputNames.Add($attrib.OutputName)

                    Write-Log -Level Debug -Message 'Found output declaration: {0} ({1})' -Arguments @($attrib.OutputName, $attrib.OutputType.Name)
                }

                $result = @{
                    OutputDeclarations = $outputDeclarations.ToArray()
                    OutputNames = $outputNames.ToArray()
                    HasOutputs = $outputDeclarations.Count -gt 0
                }

                Write-Log -Level Debug -Message 'Function output analysis complete: {0} outputs found' -Arguments $outputDeclarations.Count
                return $result
            }
            catch {
                Write-Log -Level Error -Message 'Failed to analyze function outputs for {0}' -Arguments $FunctionName -ExceptionInfo $_
                throw "Function output analysis failed for '$FunctionName': $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Log -Level Debug -Message 'Function output analysis completed for {0}' -Arguments $FunctionName
    }
}