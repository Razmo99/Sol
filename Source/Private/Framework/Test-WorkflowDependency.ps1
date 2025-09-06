using namespace System.Collections.Generic
using namespace System.Collections
using namespace System.Management.Automation

function Test-WorkflowDependency {
    <#
    .SYNOPSIS
    Validates workflow function dependencies and execution order.

    .DESCRIPTION
    Processes workflow functions in execution order, building an available outputs pool
    from ProducesOutput attributes and validating that all mandatory parameters can be
    satisfied either from initial context or previous function outputs.

    .PARAMETER WorkflowFunctions
    Array of function names in workflow execution order.

    .PARAMETER InitialContext
    Initial context hashtable containing available inputs.

    .INPUTS
    System.String[]. Array of function names.
    System.Collections.IDictionary. Initial context.

    .OUTPUTS
    System.Collections.Hashtable
    Returns validation results with structure:
    - IsValid: Boolean indicating if workflow is valid
    - MissingInputs: Array of missing input requirements
    - ValidationDetails: Detailed analysis per function
    - RequiredInitialContext: Required context keys for workflow execution

    .EXAMPLE
    Test-WorkflowDependency -WorkflowFunctions @('Connect-ToMicrosoftGraph', 'New-CompanyADUser') -InitialContext @{ M365TenantId = '12345' }

    Validates the workflow dependency chain and identifies any missing inputs.

    .NOTES
    This function is part of the Sol orchestration framework's static validation system.
    It provides comprehensive dependency analysis before workflow execution.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string[]]$WorkflowFunctions,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [IDictionary]$InitialContext
    )

    begin {
        Write-Log -Level INFO -Message 'Starting workflow dependency validation for {0} functions' -Arguments $WorkflowFunctions.Count
    }

    process {
        if ($PSCmdlet.ShouldProcess(($WorkflowFunctions -join ', '), 'Validate Workflow Dependencies')) {
            Write-Log -Level Debug -Message 'Test-WorkflowDependency process block starting'

            $availableOutputs = [List[string]]::new()
            $missingInputs = [List[hashtable]]::new()
            $validationDetails = [List[hashtable]]::new()
            $requiredInitialContext = [List[string]]::new()

            foreach ($key in $InitialContext.Keys) {
                $availableOutputs.Add($key)
            }

            try {
                # Build dependency graph and validate for circular dependencies using existing topological sort
                Write-Log -Level Debug -Message 'Building dependency graph for circular dependency detection'
                $dependencyGraph = @{}
                foreach ($functionName in $WorkflowFunctions) {
                    $functionRequirements = Get-FunctionRequirement -FunctionName $functionName
                    $dependencies = [List[string]]::new()
                    
                    # Find which functions in the workflow provide inputs this function needs
                    foreach ($mandatoryParam in $functionRequirements.MandatoryParameters) {
                        $paramName = $mandatoryParam.Name
                        
                        foreach ($otherFunction in $WorkflowFunctions) {
                            if ($otherFunction -ne $functionName) {
                                $otherFunctionOutputs = Get-FunctionOutput -FunctionName $otherFunction
                                if ($otherFunctionOutputs.OutputNames -contains $paramName) {
                                    if (-not $dependencies.Contains($otherFunction)) {
                                        $dependencies.Add($otherFunction)
                                    }
                                }
                            }
                        }
                    }
                    
                    $dependencyGraph[$functionName] = $dependencies.ToArray()
                }

                # Use existing topological sort for cycle detection and optimal ordering
                Write-Log -Level Debug -Message 'Starting topological sort with dependency graph: {0}' -Arguments ($dependencyGraph | ConvertTo-Json -Compress)
                try {
                    $optimalOrder = Get-TopologicalSort -edgeList $dependencyGraph
                    Write-Log -Level Debug -Message 'Topological sort successful, optimal execution order: {0}' -Arguments ($optimalOrder -join ' -> ')
                }
                catch {
                    # Topological sort throws on circular dependencies
                    Write-Log -Level Error -Message 'Circular dependency detected during topological sort: {0}' -Arguments $_.Exception.Message
                    throw "Circular dependency detected in workflow functions: $($_.Exception.Message)"
                }

                $executionOrder = 0
                foreach ($functionName in $WorkflowFunctions) {
                    $executionOrder++

                    Write-Log -Level Debug -Message 'Validating function {0} ({1}/{2})' -Arguments @($functionName, $executionOrder, $WorkflowFunctions.Count)

                    $functionRequirements = Get-FunctionRequirement -FunctionName $functionName
                    $functionOutputs = Get-FunctionOutput -FunctionName $functionName

                    $functionMissingInputs = [List[hashtable]]::new()

                    foreach ($mandatoryParam in $functionRequirements.MandatoryParameters) {
                        $paramName = $mandatoryParam.Name

                        # Determine parameter source by checking dependency chain first, then initial context
                        $parameterCategory = [ParameterCategory]::MissingFromContext
                        $isParameterSatisfied = $false
                        
                        if ($availableOutputs.Contains($paramName)) {
                            $parameterCategory = [ParameterCategory]::SatisfiedByDependency
                            $isParameterSatisfied = $true
                        }
                        elseif ($InitialContext.ContainsKey($paramName)) {
                            $parameterCategory = [ParameterCategory]::AvailableInContext
                            $isParameterSatisfied = $true
                        }

                        # Track unsatisfied parameters for validation reporting
                        if (-not $isParameterSatisfied) {
                            $missingInput = @{
                                FunctionName = $functionName
                                ParameterName = $paramName
                                ParameterType = $mandatoryParam.Type
                                Category = $parameterCategory
                            }

                            $functionMissingInputs.Add($missingInput)
                            $missingInputs.Add($missingInput)

                            # Build list of required initial context parameters
                            if (-not $requiredInitialContext.Contains($paramName)) {
                                $requiredInitialContext.Add($paramName)
                            }

                            Write-Log -Level WARNING -Message 'Missing input for {0}: {1} ({2})' -Arguments @($functionName, $paramName, $parameterCategory)
                        }
                        else {
                            Write-Log -Level Debug -Message 'Parameter {0} for {1}: {2}' -Arguments @($paramName, $functionName, $parameterCategory)
                        }
                    }

                    $functionDetail = @{
                        FunctionName = $functionName
                        ExecutionOrder = $executionOrder
                        RequiredInputs = $functionRequirements.MandatoryParameters
                        OptionalInputs = $functionRequirements.OptionalParameters
                        ProducedOutputs = $functionOutputs.OutputDeclarations
                        MissingInputs = $functionMissingInputs.ToArray()
                        IsValid = $functionMissingInputs.Count -eq 0
                    }

                    $validationDetails.Add($functionDetail)

                    foreach ($output in $functionOutputs.OutputNames) {
                        if (-not $availableOutputs.Contains($output)) {
                            $availableOutputs.Add($output)
                            Write-Log -Level Debug -Message 'Added {0} to available outputs from {1}' -Arguments @($output, $functionName)
                        }
                    }

                    if ($functionDetail.IsValid) {
                        Write-Log -Level Debug -Message 'Function {0} validation passed' -Arguments $functionName
                    } else {
                        Write-Log -Level WARNING -Message 'Function {0} validation failed with {1} missing inputs' -Arguments @($functionName, $functionMissingInputs.Count)
                    }
                }

                $isValid = $missingInputs.Count -eq 0

                $result = @{
                    IsValid = $isValid
                    MissingInputs = $missingInputs.ToArray()
                    ValidationDetails = $validationDetails.ToArray()
                    RequiredInitialContext = $requiredInitialContext.ToArray()
                    AvailableOutputs = $availableOutputs.ToArray()
                }

                if ($isValid) {
                    Write-Log -Level INFO -Message 'Workflow dependency validation passed'
                } else {
                    Write-Log -Level WARNING -Message 'Workflow dependency validation failed with {0} missing inputs' -Arguments $missingInputs.Count
                }

                return $result
            }
            catch {
                Write-Log -Level Error -Message 'Workflow dependency validation failed' -ExceptionInfo $_
                throw "Workflow dependency validation failed: $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Log -Level Debug -Message 'Workflow dependency validation completed'
    }
}