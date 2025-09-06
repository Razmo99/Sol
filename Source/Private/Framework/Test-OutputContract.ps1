using namespace System.Management.Automation

function Test-OutputContract {
    <#
    .SYNOPSIS
    Validates function outputs against their ProducesOutput declarations.

    .DESCRIPTION
    Checks that function return values match the types declared in their
    ProducesOutput attributes. Reports warnings for contract violations
    but does not attempt type coercion.

    .PARAMETER FunctionInfo
    The CommandInfo object for the function that was executed.

    .PARAMETER Result
    The hashtable result returned by the function.

    .INPUTS
    System.Management.Automation.CommandInfo. Function metadata.
    System.Collections.Hashtable. Function execution result.

    .OUTPUTS
    System.Boolean
    Returns $true if all output contracts are valid, $false otherwise.

    .NOTES
    This function is part of the Sol orchestration framework's validation system.
    It ensures functions honor their declared output contracts.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [CommandInfo]$FunctionInfo,

        [Parameter(Mandatory)]
        [hashtable]$Result
    )

    $functionName = $FunctionInfo.Name
    $contractValid = $true

    $outputAttributes = $FunctionInfo.ScriptBlock.Attributes | Where-Object { $_ -is [ProducesOutputAttribute] }
    
    if ($outputAttributes.Count -eq 0) {
        Write-Log -Level Debug -Message 'Function {0} has no ProducesOutput declarations to validate' -Arguments $functionName
        return $true
    }

    foreach ($outputAttr in $outputAttributes) {
        $outputName = $outputAttr.OutputName
        $expectedType = $outputAttr.OutputType
        
        if (-not $Result.ContainsKey($outputName)) {
            Write-Log -Level Warning -Message 'Missing declared output in {0}: {1} ({2})' -Arguments @($functionName, $outputName, $expectedType.Name)
            $contractValid = $false
            continue
        }

        $actualValue = $Result[$outputName]
        
        if ($null -ne $actualValue -and $actualValue -isnot $expectedType) {
            Write-Log -Level Warning -Message 'Output contract violation in {0}: {1} declared as {2} but returned {3}' -Arguments @($functionName, $outputName, $expectedType.Name, $actualValue.GetType().Name)
            $contractValid = $false
            continue
        }
        
        Write-Log -Level Debug -Message 'Output contract validated: {0}.{1} ({2})' -Arguments @($functionName, $outputName, $expectedType.Name)
    }

    return $contractValid
}