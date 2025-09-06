using namespace System.Collections
using namespace System.Management.Automation

function Invoke-ParameterValidation {
    <#
    .SYNOPSIS
    Validates and prepares parameters for workflow function invocation.

    .DESCRIPTION
    Performs type validation and basic input sanitization on context values
    before mapping them to function parameters. Returns a hashtable of
    validated parameters ready for function splatting.

    .PARAMETER FunctionInfo
    The CommandInfo object for the function being validated.

    .PARAMETER WorkflowContext
    The current workflow context containing available values.

    .INPUTS
    System.Management.Automation.CommandInfo. Function metadata.
    System.Collections.IDictionary. Workflow context.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable of validated parameters for function invocation.

    .NOTES
    This function is part of the Sol orchestration framework's execution engine.
    It provides input validation and sanitization before function execution.
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [CommandInfo]$FunctionInfo,

        [Parameter(Mandatory)]
        [IDictionary]$WorkflowContext
    )

    $params = @{}
    $functionName = $FunctionInfo.Name

    foreach ($param in $FunctionInfo.Parameters.Values) {
        $paramName = $param.Name

        # Skip common PowerShell parameters
        if ($paramName -in @('WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')) {
            continue
        }

        if (-not $WorkflowContext.ContainsKey($paramName)) {
            continue
        }

        $contextValue = $WorkflowContext[$paramName]
        $expectedType = $param.ParameterType

        # Validate parameter type
        if ($null -ne $contextValue -and $expectedType -ne [object]) {
            if (-not ($contextValue.GetType() -eq $expectedType -or $contextValue -is $expectedType)) {
                Write-Log -Level Warning -Message 'Parameter {0} type mismatch in {1}: expected {2}, got {3}' -Arguments @($paramName, $functionName, $expectedType.Name, $contextValue.GetType().Name)
                continue
            }
        }

        # Basic input sanitization for string parameters
        if ($expectedType -eq [string] -and $null -ne $contextValue) {
            $stringValue = $contextValue.ToString()
            if ($stringValue -match '[;&|`$(){}[\]<>]') {
                Write-Log -Level Warning -Message 'Parameter {0} contains potentially unsafe characters and will be sanitized' -Arguments $paramName
                $stringValue = $stringValue -replace '[;&|`$(){}[\]<>]', ''
                $contextValue = $stringValue
            }
        }

        $params[$paramName] = $contextValue
        Write-Log -Level Debug -Message 'Validated parameter {0} = {1} (type: {2})' -Arguments @($paramName, $contextValue, $expectedType.Name)
    }

    return $params
}