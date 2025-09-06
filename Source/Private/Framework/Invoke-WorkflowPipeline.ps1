using namespace System.Collections.Generic
using namespace System.Collections
using namespace System.Management.Automation

function Invoke-WorkflowPipeline {
    <#
    .SYNOPSIS
    Executes a workflow pipeline with automatic context management.

    .DESCRIPTION
    Executes a sequence of workflow functions with automatic parameter mapping
    and context management. Functions are executed in order with outputs from
    previous functions automatically mapped to inputs of subsequent functions.

    .PARAMETER WorkflowFunctions
    Array of function names to execute in order.

    .PARAMETER Context
    Initial context hashtable containing inputs for the workflow.

    .INPUTS
    System.String[]. Array of function names.
    System.Collections.IDictionary. Initial context.

    .OUTPUTS
    System.Collections.Hashtable
    Returns the final context with all accumulated outputs from the workflow.

    .EXAMPLE
    $workflow = @('Connect-ToMicrosoftGraph', 'New-CompanyADUser')
    $context = @{ FirstName = 'John'; LastName = 'Smith'; M365TenantId = '12345' }
    Invoke-WorkflowPipeline -WorkflowFunctions $workflow -Context $context

    Executes the workflow functions in sequence with context management.

    .NOTES
    This function is part of the Sol orchestration framework's execution engine.
    It provides automatic context management and parameter mapping between functions.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string[]]$WorkflowFunctions,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [IDictionary]$Context
    )

    begin {
        Write-Log -Level INFO -Message 'Starting workflow pipeline execution with {0} functions' -Arguments $WorkflowFunctions.Count

        if ($Context.Count -eq 0) {
            Write-Log -Level WARNING -Message 'Context is empty - functions may fail if they require inputs'
        }

        # Pre-validate all workflow functions exist (fail-fast approach)
        $functionInfos = @{}
        foreach ($functionName in $WorkflowFunctions) {
            try {
                $functionInfos[$functionName] = Get-Command -Name $functionName -CommandType Function -ErrorAction Stop
                Write-Log -Level Debug -Message 'Validated workflow function: {0}' -Arguments $functionName
            }
            catch {
                Write-Log -Level Error -Message 'Workflow function {0} not found' -Arguments $functionName -ExceptionInfo $_
                throw "Workflow validation failed: Function '$functionName' not found or not accessible"
            }
        }

        $workflowContext = @{}
        foreach ($key in $Context.Keys) {
            $workflowContext[$key] = $Context[$key]
        }
    }

    process {
        if ($PSCmdlet.ShouldProcess(($WorkflowFunctions -join ', '), 'Execute Workflow Pipeline')) {

            $executionOrder = 0
            foreach ($functionName in $WorkflowFunctions) {
                $executionOrder++

                Write-Log -Level INFO -Message 'Executing function {0} ({1}/{2})' -Arguments @($functionName, $executionOrder, $WorkflowFunctions.Count)

                try {
                    $functionInfo = $functionInfos[$functionName]

                    # Validate and prepare parameters
                    $params = Invoke-ParameterValidation -FunctionInfo $functionInfo -WorkflowContext $workflowContext

                    # Add WhatIf support if needed
                    if ($WhatIfPreference -and $functionInfo.Parameters.ContainsKey('WhatIf')) {
                        $params['WhatIf'] = $WhatIfPreference
                    }

                    Write-Log -Level Debug -Message 'Invoking {0} with {1} parameters' -Arguments @($functionName, $params.Count)
                    $result = & $functionName @params

                    # Handle function results
                    if ($result -isnot [hashtable]) {
                        Write-Log -Level Debug -Message 'Function {0} returned non-hashtable result, not merged to context' -Arguments $functionName
                        Write-Log -Level INFO -Message 'Function {0} executed successfully' -Arguments $functionName
                        continue
                    }

                    # Validate output contracts
                    $contractValid = Test-OutputContract -FunctionInfo $functionInfo -Result $result
                    if (-not $contractValid) {
                        Write-Log -Level Warning -Message 'Function {0} has output contract violations but execution will continue' -Arguments $functionName
                    }

                    # Merge results to context
                    foreach ($key in $result.Keys) {
                        $workflowContext[$key] = $result[$key]
                        Write-Log -Level Debug -Message 'Added output to context: {0} = {1}' -Arguments @($key, $result[$key])
                    }

                    Write-Log -Level INFO -Message 'Function {0} executed successfully' -Arguments $functionName
                }
                catch {
                    Write-Log -Level Error -Message 'Function {0} failed' -Arguments $functionName -ExceptionInfo $_
                    throw "Workflow failed at function $functionName`: $($_.Exception.Message)"
                }
            }

            Write-Log -Level INFO -Message 'Workflow pipeline execution completed successfully'
            return $workflowContext
        }
    }

    end {
        Write-Log -Level Debug -Message 'Workflow pipeline execution finished with {0} context items' -Arguments $workflowContext.Count
    }
}