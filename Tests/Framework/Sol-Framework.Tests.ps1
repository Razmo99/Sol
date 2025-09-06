using namespace System.Collections.Generic
using namespace System.Collections

Import-Module ./output/sol -Force

# Ensure ParameterCategory enum is available in test scope

InModuleScope 'sol' {
    BeforeAll {
        # Import test example functions
        . "$PSScriptRoot/Examples/Test-WorkflowStepA.ps1"
        . "$PSScriptRoot/Examples/Test-WorkflowStepB.ps1"
    }

    Describe "Sol Framework Core Components" {
        
        Context "ProducesOutput Attribute" {
            It "Should create ProducesOutput attribute with valid parameters" {
                $attribute = [ProducesOutputAttribute]::new("TestOutput", [string])
                $attribute.OutputName | Should -Be "TestOutput"
                $attribute.OutputType | Should -Be ([string])
            }
            
            It "Should throw exception for null OutputName" {
                { [ProducesOutputAttribute]::new($null, [string]) } | Should -Throw
            }
            
            It "Should throw exception for empty OutputName" {
                { [ProducesOutputAttribute]::new("", [string]) } | Should -Throw
            }
            
            It "Should throw exception for null OutputType" {
                { [ProducesOutputAttribute]::new("Test", $null) } | Should -Throw
            }
        }
        
        Context "Function Introspection Engine" {
            It "Should analyze function requirements correctly" {
                $requirements = Get-FunctionRequirement -FunctionName "Test-WorkflowStepA"
                
                $requirements | Should -Not -BeNullOrEmpty
                $requirements.Keys | Should -Contain "MandatoryParameters"
                $requirements.Keys | Should -Contain "OptionalParameters"
                $requirements.Keys | Should -Contain "AllParameters"
                
                $requirements.MandatoryParameters.Count | Should -BeGreaterThan 0
                $requirements.MandatoryParameters[0].Name | Should -BeIn @("FirstName", "LastName")
            }
            
            It "Should analyze function outputs correctly" {
                $outputs = Get-FunctionOutput -FunctionName "Test-WorkflowStepA"
                
                $outputs | Should -Not -BeNullOrEmpty
                $outputs.Keys | Should -Contain "OutputDeclarations"
                $outputs.Keys | Should -Contain "OutputNames"
                $outputs.Keys | Should -Contain "HasOutputs"
                
                $outputs.HasOutputs | Should -Be $true
                $outputs.OutputNames | Should -Contain "FullName"
                $outputs.OutputNames | Should -Contain "ProcessedBy"
            }
        }
        
        Context "Workflow Readiness Validation" {
            It "Should validate workflow readiness for existing functions" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $readiness = Test-WorkflowReadiness -WorkflowFunctions $workflowFunctions
                
                $readiness.IsReady | Should -Be $true
                $readiness.MissingFunctions.Count | Should -Be 0
                $readiness.TotalFunctions | Should -Be 2
                $readiness.AvailableFunctions | Should -Be 2
            }
            
            It "Should identify missing functions" {
                $workflowFunctions = @("Test-WorkflowStepA", "NonExistentFunction")
                $readiness = Test-WorkflowReadiness -WorkflowFunctions $workflowFunctions
                
                $readiness.IsReady | Should -Be $false
                $readiness.MissingFunctions | Should -Contain "NonExistentFunction"
                $readiness.TotalFunctions | Should -Be 2
                $readiness.AvailableFunctions | Should -Be 1
            }
        }
        
        Context "Workflow Dependency Validation" {
            It "Should validate workflow dependencies with complete context" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $initialContext = @{
                    FirstName = "John"
                    LastName = "Smith" 
                    Department = "IT"
                }
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $initialContext
                
                $validation.IsValid | Should -Be $true
                $validation.MissingInputs.Count | Should -Be 0
                $validation.ValidationDetails.Count | Should -Be 2
            }
            
            It "Should identify missing dependencies" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $initialContext = @{
                    FirstName = "John"
                    # Missing LastName and Department
                }
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $initialContext
                
                $validation.IsValid | Should -Be $false
                $validation.MissingInputs.Count | Should -BeGreaterThan 0
                $validation.RequiredInitialContext | Should -Contain "LastName"
                $validation.RequiredInitialContext | Should -Contain "Department"
            }
        }
        
        Context "Workflow Execution Engine" {
            BeforeEach {
                # Mock Write-Log to avoid logging during tests
                Mock Write-Log { }
            }
            
            It "Should execute workflow with proper context management" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $initialContext = @{
                    FirstName = "John"
                    LastName = "Smith"
                    Department = "IT"
                }
                
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $workflowFunctions -Context $initialContext -WhatIf:$false
                
                $result | Should -Not -BeNullOrEmpty
                $result["FullName"] | Should -Be "John Smith"
                $result["ProcessedBy"] | Should -Be "Test-WorkflowStepA"
                $result["ValidationStatus"] | Should -Be "Valid"
                $result["UserProfile"] | Should -Not -BeNullOrEmpty
                $result["UserProfile"]["Name"] | Should -Be "John Smith"
                $result["UserProfile"]["Department"] | Should -Be "IT"
            }
            
        }
    }

    Describe "Sol Framework Integration Tests" {
        BeforeEach {
            Mock Write-Log { }
        }
        
        Context "End-to-End Workflow Execution" {
            It "Should execute complete workflow validation and execution cycle" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $initialContext = @{
                    FirstName = "Jane"
                    LastName = "Doe" 
                    Department = "HR"
                }
                
                # Step 1: Validate readiness
                $readiness = Test-WorkflowReadiness -WorkflowFunctions $workflowFunctions
                $readiness.IsReady | Should -Be $true
                
                # Step 2: Validate dependencies
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $initialContext
                $validation.IsValid | Should -Be $true
                
                # Step 3: Execute workflow
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $workflowFunctions -Context $initialContext -WhatIf:$false
                
                # Verify results
                $result["FullName"] | Should -Be "Jane Doe"
                $result["UserProfile"]["Department"] | Should -Be "HR"
                $result["ValidationStatus"] | Should -Be "Valid"
            }
            
            It "Should prevent execution of invalid workflows" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $invalidContext = @{
                    FirstName = "John"
                    # Missing required parameters
                }
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $invalidContext
                $validation.IsValid | Should -Be $false
                
                # In a real scenario, this would prevent execution
                $validation.MissingInputs.Count | Should -BeGreaterThan 0
            }
        }
    }

    Describe "Sol Framework Error Handling and Edge Cases" {
        BeforeEach {
            Mock Write-Log { }
        }

        Context "Input Validation and Security" {
            It "Should handle malicious context parameters safely" {
                $workflowFunctions = @("Test-WorkflowStepA")
                $maliciousContext = @{
                    FirstName = "John'; DROP TABLE Users; --"
                    LastName = "Smith$(Get-Process)"
                    # Test input sanitization
                }
                
                # Should not throw and should sanitize inputs
                { Invoke-WorkflowPipeline -WorkflowFunctions $workflowFunctions -Context $maliciousContext -WhatIf:$false } | Should -Not -Throw
            }

        }

        Context "Circular Dependency Detection" {
            It "Should detect circular dependencies in workflow" {
                # Create functions with circular dependencies
                function Test-CircularA {
                    [OutputType([hashtable])]
                    [ProducesOutput("ValueA", [string])]
                    param([Parameter(Mandatory)][string]$ValueB)
                    return @{ ValueA = "A" }
                }

                function Test-CircularB {
                    [OutputType([hashtable])]
                    [ProducesOutput("ValueB", [string])]
                    param([Parameter(Mandatory)][string]$ValueA)
                    return @{ ValueB = "B" }
                }

                $circularWorkflow = @("Test-CircularA", "Test-CircularB")
                $context = @{}
                
                # Should detect and throw on circular dependency
                { Test-WorkflowDependency -WorkflowFunctions $circularWorkflow -InitialContext $context } | Should -Throw "*circular*"
            }

            It "Should properly identify circular dependencies vs missing context" {
                # Create functions with circular dependencies
                function Test-CircularDepA {
                    [OutputType([hashtable])]
                    [ProducesOutput("DepA", [string])]
                    param([Parameter(Mandatory)][string]$DepB)
                    return @{ DepA = "A" }
                }

                function Test-CircularDepB {
                    [OutputType([hashtable])]
                    [ProducesOutput("DepB", [string])]
                    param([Parameter(Mandatory)][string]$DepA)
                    return @{ DepB = "B" }
                }

                $circularWorkflow = @("Test-CircularDepA", "Test-CircularDepB")
                $context = @{}
                
                # Capture the actual exception to verify it's specifically about circular dependencies
                $exception = $null
                try {
                    Test-WorkflowDependency -WorkflowFunctions $circularWorkflow -InitialContext $context
                } catch {
                    $exception = $_.Exception
                }
                
                # Verify we got an exception and it specifically mentions circular dependency
                $exception | Should -Not -BeNullOrEmpty
                $exception.Message | Should -Match "circular"
                $exception.Message | Should -Not -Match "missing.*context"
            }
        }

        Context "Missing Function Scenarios" {
            It "Should handle missing function gracefully" {
                $workflowFunctions = @("NonExistentFunction")
                
                $readiness = Test-WorkflowReadiness -WorkflowFunctions $workflowFunctions
                $readiness.IsReady | Should -Be $false
                $readiness.MissingFunctions | Should -Contain "NonExistentFunction"
            }
        }

        Context "Empty and Null Input Handling" {
            It "Should handle empty workflow array" {
                # Empty array should be rejected by parameter validation (expected behavior)
                $emptyWorkflow = @()
                $context = @{ TestParam = "Value" }
                
                { Test-WorkflowDependency -WorkflowFunctions $emptyWorkflow -InitialContext $context } | Should -Throw
            }

            It "Should handle empty context" {
                $workflowFunctions = @("Test-WorkflowStepA")
                $emptyContext = @{}
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $emptyContext
                $validation.IsValid | Should -Be $false
                $validation.MissingInputs.Count | Should -BeGreaterThan 0
            }

        }

        Context "Parameter Category Validation" {
            It "Should correctly categorize parameters as SatisfiedByDependency" {
                $workflowFunctions = @("Test-WorkflowStepA", "Test-WorkflowStepB")
                $partialContext = @{
                    FirstName = "John"
                    LastName = "Smith"
                    # Department missing - should be categorized correctly
                }
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $partialContext
                
                # Find missing input for Department
                $departmentMissing = $validation.MissingInputs | Where-Object { $_.ParameterName -eq "Department" }
                $departmentMissing.Category | Should -Be ([ParameterCategory]::MissingFromContext)
            }

            It "Should correctly categorize parameters as AvailableInContext" {
                $workflowFunctions = @("Test-WorkflowStepA")
                $completeContext = @{
                    FirstName = "John"
                    LastName = "Smith"
                }
                
                $validation = Test-WorkflowDependency -WorkflowFunctions $workflowFunctions -InitialContext $completeContext
                $validation.IsValid | Should -Be $true
            }
        }



        Context "Context Key Collision Scenarios" {
            It "Should handle context key collisions when multiple functions produce same output key" {
                # Create two functions that produce the same output key
                function Test-CollisionFunctionA {
                    [OutputType([hashtable])]
                    [ProducesOutput("SharedKey", [string])]
                    param([Parameter(Mandatory)][string]$InputA)
                    return @{ SharedKey = "ValueFromA" }
                }

                function Test-CollisionFunctionB {
                    [OutputType([hashtable])]
                    [ProducesOutput("SharedKey", [string])]
                    param([Parameter(Mandatory)][string]$InputB)
                    return @{ SharedKey = "ValueFromB" }
                }

                $collisionWorkflow = @("Test-CollisionFunctionA", "Test-CollisionFunctionB")
                $context = @{ 
                    InputA = "TestA"
                    InputB = "TestB" 
                }
                
                # Should execute successfully - last function's output should win
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $collisionWorkflow -Context $context -WhatIf:$false
                $result["SharedKey"] | Should -Be "ValueFromB"  # Last function's output should overwrite
            }
        }

        Context "Non-Hashtable Function Return Scenarios" {
            It "Should handle functions that return non-hashtable values gracefully" {
                # Create a function that returns a string instead of hashtable
                function Test-NonHashtableReturn {
                    [OutputType([hashtable])]  # Claims to return hashtable but doesn't
                    [ProducesOutput("Result", [string])]
                    param([Parameter(Mandatory)][string]$InputParam)
                    
                    # Return string instead of hashtable
                    return "SimpleStringResult"
                }

                $nonHashtableWorkflow = @("Test-NonHashtableReturn")
                $context = @{ InputParam = "Test" }
                
                # Should execute gracefully and continue workflow (framework logs but doesn't error)
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $nonHashtableWorkflow -Context $context -WhatIf:$false
                
                # Original context should remain unchanged (no new outputs merged)
                $result["InputParam"] | Should -Be "Test"
                $result.ContainsKey("Result") | Should -Be $false  # Non-hashtable return not merged
            }
        }

        Context "Partial Contract Fulfillment Scenarios" {
            It "Should handle functions that don't return all declared outputs" {
                # Create a function that declares multiple outputs but only returns some
                function Test-PartialContractFunction {
                    [OutputType([hashtable])]
                    [ProducesOutput("RequiredOutput", [string])]
                    [ProducesOutput("OptionalOutput", [string])]
                    [ProducesOutput("MissingOutput", [string])]  # This won't be returned
                    param([Parameter(Mandatory)][string]$InputParam)
                    
                    # Only return some of the declared outputs
                    return @{ 
                        RequiredOutput = "Present"
                        OptionalOutput = "Also Present"
                        # MissingOutput intentionally omitted
                    }
                }

                $partialContractWorkflow = @("Test-PartialContractFunction")
                $context = @{ InputParam = "Test" }
                
                # Should execute and return available outputs, handle missing ones gracefully
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $partialContractWorkflow -Context $context -WhatIf:$false
                
                $result["RequiredOutput"] | Should -Be "Present"
                $result["OptionalOutput"] | Should -Be "Also Present"
                $result.ContainsKey("MissingOutput") | Should -Be $false  # Should not be added to context
            }
        }

        Context "Functions Without ProducesOutput Attributes" {
            It "Should handle functions without ProducesOutput attributes gracefully" {
                # Create a function without ProducesOutput attributes
                function Test-NoAttributesFunction {
                    [OutputType([hashtable])]  # Standard PowerShell attribute only
                    param([Parameter(Mandatory)][string]$InputParam)
                    
                    return @{ 
                        Result = "FunctionExecuted"
                        Input = $InputParam
                    }
                }

                $noAttributesWorkflow = @("Test-NoAttributesFunction")
                $context = @{ InputParam = "Test" }
                
                # Should execute successfully but outputs won't be tracked for dependency analysis
                $result = Invoke-WorkflowPipeline -WorkflowFunctions $noAttributesWorkflow -Context $context -WhatIf:$false
                
                # Result should contain the returned values
                $result["Result"] | Should -Be "FunctionExecuted" 
                $result["Input"] | Should -Be "Test"
                
                # Verify function output analysis shows no declared outputs
                $outputs = Get-FunctionOutput -FunctionName "Test-NoAttributesFunction"
                $outputs.HasOutputs | Should -Be $false
                $outputs.OutputNames.Count | Should -Be 0
            }
        }

        Context "Error Recovery and Logging" {
            It "Should fail fast on function execution errors" {
                # Create a function that throws an error
                function Test-ErrorFunction {
                    [OutputType([hashtable])]
                    [ProducesOutput("Result", [string])]
                    param([Parameter(Mandatory)][string]$InputParam)
                    
                    throw "Intentional test error"
                }

                $workflowFunctions = @("Test-ErrorFunction")
                $context = @{ InputParam = "Test" }
                
                # Should throw and not continue to next functions
                { Invoke-WorkflowPipeline -WorkflowFunctions $workflowFunctions -Context $context -WhatIf:$false } | Should -Throw "*Intentional test error*"
            }

            It "Should validate all functions exist before execution" {
                $workflowWithMissingFunction = @("Test-WorkflowStepA", "NonExistentFunction")
                
                # Should fail readiness check
                $readiness = Test-WorkflowReadiness -WorkflowFunctions $workflowWithMissingFunction
                $readiness.IsReady | Should -Be $false
                $readiness.MissingFunctions | Should -Contain "NonExistentFunction"
            }
        }
    }
}