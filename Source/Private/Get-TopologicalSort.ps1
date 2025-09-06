using namespace System.Collections
using namespace System.Collections.Generic

function Get-TopologicalSort {
    <#
    .SYNOPSIS
        Performs topological sorting on a dependency graph using non-destructive Kahn's algorithm.

    .DESCRIPTION
        Takes a hashtable representing an edge list (dependencies) and returns an array of nodes
        in topologically sorted order. Uses tracking structures to preserve original data integrity.

    .PARAMETER edgeList
        Hashtable where keys are nodes and values are arrays of their dependencies.

    .OUTPUTS
        Object[]
        Returns an array of nodes in topologically sorted order.

    .EXAMPLE
        $edges = @{ 'A' = @(); 'B' = @('A'); 'C' = @('B') }
        Get-TopologicalSort -edgeList $edges
        # Returns: A, B, C

    .NOTES
        Algorithm from http://en.wikipedia.org/wiki/Topological_sorting#Algorithms
        Non-destructive implementation preserves original edgeList data.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable]$edgeList
    )

    # Early return for empty input
    if ($edgeList.Count -eq 0) {
        return @()
    }

    # Non-destructive tracking structures - NO CLONING NEEDED
    $visited = @{}
    $inDegreeCount = @{}
    $queue = [Queue]::new()
    $result = [List[object]]::new()
    $allNodes = [HashSet[object]]::new()

    # Initialize tracking structures from original data (non-destructive)
    foreach ($node in $edgeList.Keys) {
        $inDegreeCount[$node] = 0
        [void]$allNodes.Add($node)
    }

    # Calculate in-degrees from dependencies (non-destructive read)
    # If A depends on B, then A should have higher in-degree (come later in sort)
    foreach ($node in $edgeList.Keys) {
        $dependencies = $edgeList[$node]
        if ($null -ne $dependencies) {
            foreach ($dependency in $dependencies) {
                # Add missing nodes that appear as dependencies
                if (-not $allNodes.Contains($dependency)) {
                    [void]$allNodes.Add($dependency)
                    $inDegreeCount[$dependency] = 0
                }
                # The dependent node (not the dependency) gets the in-degree count
                $inDegreeCount[$node]++
            }
        }
    }

    # Find all nodes with no incoming edges
    foreach ($node in $allNodes) {
        if ($inDegreeCount[$node] -eq 0) {
            $queue.Enqueue($node)
        }
    }

    # Process nodes using Kahn's algorithm (non-destructive)
    while ($queue.Count -gt 0) {
        $currentNode = $queue.Dequeue()
        $result.Add($currentNode)
        $visited[$currentNode] = $true

        # Find all nodes that depend on the current node and decrease their in-degree
        foreach ($nodeKey in $edgeList.Keys) {
            $nodeDependencies = $edgeList[$nodeKey]
            if ($null -ne $nodeDependencies -and $nodeDependencies -contains $currentNode) {
                # This node depends on currentNode, so decrease its in-degree
                if (-not $visited.ContainsKey($nodeKey)) {
                    $inDegreeCount[$nodeKey]--
                    
                    # If no more incoming edges, add to queue
                    if ($inDegreeCount[$nodeKey] -eq 0) {
                        $queue.Enqueue($nodeKey)
                    }
                }
            }
        }
    }

    # Check for cycles (remaining unvisited nodes indicate circular dependencies)
    $unvisitedNodes = [List[object]]::new()
    foreach ($node in $allNodes) {
        if (-not $visited.ContainsKey($node)) {
            $unvisitedNodes.Add($node)
        }
    }

    if ($unvisitedNodes.Count -gt 0) {
        $cycleNodes = $unvisitedNodes -join ', '
        throw "Graph has at least one cycle involving nodes: $cycleNodes"
    }

    # Return as array for PowerShell pipeline compatibility
    # Use comma operator to prevent PowerShell from unwrapping single-element arrays
    return ,$result.ToArray()
}