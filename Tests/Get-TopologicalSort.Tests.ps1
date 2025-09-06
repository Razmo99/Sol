using namespace System.Management.Automation
using namespace System.Collections
using namespace System.Collections.Generic

Import-Module ./output/sol -Force

InModuleScope 'sol' {
    Describe "Get-TopologicalSort" {
        Context "Real-world interactive prompt scenarios" {
            It "Should handle New-ContosoUser prompt dependencies correctly" {
                # Based on actual New-ContosoUser.ps1 example
                $edgeList = @{
                    'EmailAccess' = @()              # Independent prompt
                    'VPNAccess'   = @()              # Independent prompt
                    'AdminRights' = @('VPNAccess')   # Depends on VPNAccess
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 3
                
                # VPNAccess must come before AdminRights (AdminRights depends on VPNAccess)
                $result.IndexOf('VPNAccess') | Should -BeLessThan $result.IndexOf('AdminRights')
                
                # EmailAccess should be independent (can be anywhere)
                $result | Should -Contain 'EmailAccess'
                $result | Should -Contain 'VPNAccess' 
                $result | Should -Contain 'AdminRights'
            }

            It "Should handle simple linear dependency chain" {
                # A depends on nothing, B depends on A, C depends on B
                $edgeList = @{
                    'A' = @()     # Independent - should be first
                    'B' = @('A')  # Depends on A - should be second  
                    'C' = @('B')  # Depends on B - should be third
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 3
                $result.IndexOf('A') | Should -BeLessThan $result.IndexOf('B')
                $result.IndexOf('B') | Should -BeLessThan $result.IndexOf('C')
                # Should be exact order: A, B, C
                $result[0] | Should -Be 'A'
                $result[1] | Should -Be 'B' 
                $result[2] | Should -Be 'C'
            }

            It "Should handle parallel independent branches" {
                $edgeList = @{
                    'Root'    = @()                    # Independent
                    'Branch1' = @('Root')              # Depends on Root
                    'Branch2' = @('Root')              # Depends on Root
                    'Merge'   = @('Branch1', 'Branch2') # Depends on both branches
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 4
                
                # Root must be first
                $result[0] | Should -Be 'Root'
                
                # Both branches must come after Root but before Merge
                $result.IndexOf('Root') | Should -BeLessThan $result.IndexOf('Branch1')
                $result.IndexOf('Root') | Should -BeLessThan $result.IndexOf('Branch2')
                $result.IndexOf('Branch1') | Should -BeLessThan $result.IndexOf('Merge')
                $result.IndexOf('Branch2') | Should -BeLessThan $result.IndexOf('Merge')
                
                # Merge must be last
                $result[3] | Should -Be 'Merge'
            }

            It "Should handle complex multi-level user permissions scenario" {
                # Realistic scenario: User access levels with dependencies
                $edgeList = @{
                    'BasicAccess'    = @()                              # Entry level
                    'EmailAccess'    = @()                              # Independent  
                    'FileAccess'     = @('BasicAccess')                 # Needs basic access first
                    'VPNAccess'      = @('BasicAccess')                 # Needs basic access first
                    'DatabaseAccess' = @('FileAccess', 'VPNAccess')     # Needs both file and VPN
                    'AdminRights'    = @('DatabaseAccess', 'EmailAccess') # Needs database and email
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 6
                
                # Verify dependency chains
                $result.IndexOf('BasicAccess') | Should -BeLessThan $result.IndexOf('FileAccess')
                $result.IndexOf('BasicAccess') | Should -BeLessThan $result.IndexOf('VPNAccess')
                $result.IndexOf('FileAccess') | Should -BeLessThan $result.IndexOf('DatabaseAccess')
                $result.IndexOf('VPNAccess') | Should -BeLessThan $result.IndexOf('DatabaseAccess')
                $result.IndexOf('DatabaseAccess') | Should -BeLessThan $result.IndexOf('AdminRights')
                $result.IndexOf('EmailAccess') | Should -BeLessThan $result.IndexOf('AdminRights')
            }
        }

        Context "Edge cases and error handling" {
            It "Should handle empty edge list" {
                $edgeList = @{}
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -BeNullOrEmpty
            }

            It "Should handle single independent node" {
                $edgeList = @{
                    'OnlyNode' = @()
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 1
                $result[0] | Should -Be 'OnlyNode'
            }

            It "Should handle dependencies on nodes not in edge list" {
                # Common scenario: node depends on external prerequisite
                $edgeList = @{
                    'NodeA' = @('ExternalDep')  # Depends on node not in edgeList
                    'NodeB' = @()               # Independent
                }
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 3  # Should include the external dependency
                $result | Should -Contain 'ExternalDep'
                $result | Should -Contain 'NodeA'
                $result | Should -Contain 'NodeB'
                $result.IndexOf('ExternalDep') | Should -BeLessThan $result.IndexOf('NodeA')
            }

            It "Should detect circular dependencies and throw exception" {
                $edgeList = @{
                    'A' = @('B')  # A depends on B
                    'B' = @('C')  # B depends on C  
                    'C' = @('A')  # C depends on A - creates cycle
                }
                
                { Get-TopologicalSort -edgeList $edgeList } | Should -Throw "*cycle*"
            }

            It "Should detect self-referencing nodes and throw exception" {
                $edgeList = @{
                    'SelfRef' = @('SelfRef')  # Node depends on itself
                    'Normal'  = @()
                }
                
                { Get-TopologicalSort -edgeList $edgeList } | Should -Throw "*cycle*"
            }
        }

        Context "Data integrity and non-destructive behavior" {
            It "Should preserve original edgeList structure" {
                $originalEdgeList = @{
                    'A' = @('B')
                    'B' = @()
                }
                $originalKeys = @($originalEdgeList.Keys)
                $originalADeps = @($originalEdgeList['A'])
                $originalBDeps = @($originalEdgeList['B'])
                
                $result = Get-TopologicalSort -edgeList $originalEdgeList
                
                # Verify original structure unchanged
                $originalEdgeList.Count | Should -Be 2
                @($originalEdgeList.Keys) | Should -Be $originalKeys
                @($originalEdgeList['A']) | Should -Be $originalADeps
                @($originalEdgeList['B']) | Should -Be $originalBDeps
            }

            It "Should handle complex collection types without modification" {
                $edgeList = @{
                    'Node1' = [System.Collections.ArrayList]@('Dep1', 'Dep2')
                    'Node2' = [System.Collections.ArrayList]@()
                    'Dep1'  = [System.Collections.ArrayList]@()
                    'Dep2'  = [System.Collections.ArrayList]@()
                }
                $originalType = $edgeList['Node1'].GetType()
                $originalCount = $edgeList['Node1'].Count
                
                $result = Get-TopologicalSort -edgeList $edgeList
                
                # Verify collection types preserved
                $edgeList['Node1'].GetType() | Should -Be $originalType
                $edgeList['Node1'].Count | Should -Be $originalCount
                $edgeList['Node1'][0] | Should -Be 'Dep1'
                $edgeList['Node1'][1] | Should -Be 'Dep2'
            }
        }

        Context "Performance validation" {
            It "Should handle large dependency graphs efficiently" {
                $edgeList = @{}
                # Create linear chain: Node0 -> Node1 -> Node2 -> ... -> Node99
                for ($i = 0; $i -lt 100; $i++) {
                    if ($i -eq 0) {
                        $edgeList["Node$i"] = @()
                    } else {
                        $edgeList["Node$i"] = @("Node$($i-1)")
                    }
                }
                
                $startTime = Get-Date
                $result = Get-TopologicalSort -edgeList $edgeList
                $endTime = Get-Date
                
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 100
                ($endTime - $startTime).TotalSeconds | Should -BeLessThan 2
                
                # Verify correct ordering (Node0 first, Node99 last)
                $result[0] | Should -Be 'Node0'
                $result[99] | Should -Be 'Node99'
            }
        }
    }
}