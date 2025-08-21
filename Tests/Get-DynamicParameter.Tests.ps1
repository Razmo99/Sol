using namespace System.Management.Automation

# Import module directly
Import-Module ./output/sol -Force

InModuleScope 'sol' {
    Describe "Get-DynamicParameter Function" {
        Context "Basic functionality" {
            It "Should return a RuntimeDefinedParameterDictionary" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem'
                $Result | Should -BeOfType [System.Management.Automation.RuntimeDefinedParameterDictionary]
            }

            It "Should generate parameters for Get-ChildItem" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem'
                $Result.Count | Should -BeGreaterThan 0
            }

            It "Should include Path parameter from Get-ChildItem" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem'
                $Result.Keys | Should -Contain 'Path'
            }

            It "Should include Filter parameter from Get-ChildItem" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem'
                $Result.Keys | Should -Contain 'Filter'
            }

            It "Should exclude common parameters by default" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem'
                $Result.Keys | Should -Not -Contain 'Verbose'
                $Result.Keys | Should -Not -Contain 'Debug'
            }

            It "Should include common parameters when requested" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem' -IncludeCommonParameters
                $Result.Keys | Should -Contain 'Verbose'
            }
        }

        Context "CommonParameters detection" {
            It "Should detect CommonParameters correctly" {
                # Test the actual CommonParameters used by the function
                $CommonParams = [string[]][Internal.CommonParameters].GetProperties().Name

                $CommonParams | Should -Not -BeNullOrEmpty
                $CommonParams | Should -Contain 'Verbose'
                $CommonParams | Should -Contain 'Debug'
                $CommonParams.Count | Should -Be 12
            }
        }

        Context "Parameter exclusion" {
            It "Should exclude specified parameters" {
                $Result = Get-DynamicParameter -CommandName 'Get-ChildItem' -ExcludeParameters @('Path', 'Filter')
                $Result.Keys | Should -Not -Contain 'Path'
                $Result.Keys | Should -Not -Contain 'Filter'
            }
        }

        Context "Error handling" {
            It "Should handle invalid command names gracefully" {
                $Result = Get-DynamicParameter -CommandName 'NonExistentCommand'
                $Result | Should -BeOfType [System.Management.Automation.RuntimeDefinedParameterDictionary]
                $Result.Count | Should -Be 0
            }
        }

        Context "Verification" {
            It "Should show correct parameter counts" {
                Write-Host "`n=== Dynamic Parameter Verification ===" -ForegroundColor Green

                # Check Get-ChildItem original parameters
                $OriginalCommand = Get-Command -Name 'Get-ChildItem'
                Write-Host "Original Get-ChildItem parameter count: $($OriginalCommand.Parameters.Count)" -ForegroundColor Cyan

                # Check our dynamic parameters
                $DynamicParams = Get-DynamicParameter -CommandName 'Get-ChildItem'
                Write-Host "Generated dynamic parameter count: $($DynamicParams.Count)" -ForegroundColor Yellow
                Write-Host "Sample dynamic parameters: $($DynamicParams.Keys | Select-Object -First 5 | Join-String -Separator ', ')" -ForegroundColor Yellow

                # Verify math: Original - Common = Dynamic
                $CommonParams = [string[]][Internal.CommonParameters].GetProperties().Name
                $ExpectedCount = $OriginalCommand.Parameters.Count - $CommonParams.Count
                Write-Host "Expected dynamic count: $ExpectedCount (Original: $($OriginalCommand.Parameters.Count) - Common: $($CommonParams.Count))" -ForegroundColor Green

                $DynamicParams.Count | Should -Be $ExpectedCount
            }
        }
    }
}