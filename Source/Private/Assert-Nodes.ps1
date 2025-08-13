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
