function Get-TopologicalSort {
    # Function from https://stackoverflow.com/questions/8982782/does-anyone-have-a-dependency-graph-and-topological-sorting-code-snippet-for-pow
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [hashtable] $edgeList
    )

    # Make sure we can use HashSet
    Add-Type -AssemblyName System.Core

    # Clone it so as to not alter original
    $currentEdgeList = [hashtable] (Get-ClonedObject $edgeList)

    # algorithm from http://en.wikipedia.org/wiki/Topological_sorting#Algorithms
    $topologicallySortedElements = New-Object System.Collections.ArrayList
    $setOfAllNodesWithNoIncomingEdges = New-Object System.Collections.Queue

    $fasterEdgeList = @{}

    # Keep track of all nodes in case they put it in as an edge destination but not source
    $allNodes = New-Object -TypeName System.Collections.Generic.HashSet[object] -ArgumentList (,[object[]] $currentEdgeList.Keys)
    $MissingSourceNodes=New-Object System.Collections.Queue
    # Iterate over all Keys in Edge List

    function Assert-Nodes {
        foreach($currentNode in $currentEdgeList.Keys) {
            $currentDestinationNodes = [array] $currentEdgeList[$currentNode]
            # If the current node's array is empty, meaning it has no incoming edges
            if($currentDestinationNodes.Length -eq 0) {
                $setOfAllNodesWithNoIncomingEdges.Enqueue($currentNode)
            }
            # Iterate over nodes and make sure it exists in all nodes otherwise enqueue to remove it.
            foreach($currentDestinationNode in $currentDestinationNodes) {
                if(!$allNodes.Contains($currentDestinationNode)) {
                if($currentEdgeList.ContainsKey($currentDestinationNode)){
                    [void] $allNodes.add($currentDestinationNode)
                }else{
                $MissingSourceNodes.Enqueue($currentNode)
                Write-Log -Level Verbose -Message '{0}: Criteria Not Met | Destination Node Missing for: {1}' -Arguments @($CurrentNode, $currentDestinationNode)
                }
                }
            }

            # Take this time to convert them to a HashSet for faster operation
            $currentDestinationNodes = New-Object -TypeName System.Collections.Generic.HashSet[object] -ArgumentList (,[object[]] $currentDestinationNodes )
            [void] $fasterEdgeList.Add($currentNode, $currentDestinationNodes)
        }
    }
    Assert-Nodes
    While ($MissingSourceNodes.count -gt 0){
    # This is so nasty
    $currentMissingNode = $MissingSourceNodes.Dequeue()
    $currentEdgeList.Remove($currentMissingNode)
    $allNodes.Clear()
    $setOfAllNodesWithNoIncomingEdges.Clear()
    $fasterEdgeList.Clear()
    Assert-Nodes
    }

    $currentEdgeList = $fasterEdgeList

    while($setOfAllNodesWithNoIncomingEdges.Count -gt 0) {        
        $currentNode = $setOfAllNodesWithNoIncomingEdges.Dequeue()
        [void] $currentEdgeList.Remove($currentNode)
        [void] $topologicallySortedElements.Add($currentNode)

        foreach($currentEdgeSourceNode in $currentEdgeList.Keys) {
            $currentNodeDestinations = $currentEdgeList[$currentEdgeSourceNode]
            if($currentNodeDestinations.Contains($currentNode)) {
                [void] $currentNodeDestinations.Remove($currentNode)

                if($currentNodeDestinations.Count -eq 0) {
                    [void] $setOfAllNodesWithNoIncomingEdges.Enqueue($currentEdgeSourceNode)
                }                
            }
        }
  }

  if($currentEdgeList.Count -gt 0) {
      throw "Graph has at least one cycle!"
  }

  return $topologicallySortedElements
}
