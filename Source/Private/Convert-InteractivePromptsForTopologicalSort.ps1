function Convert-InteractivePromptsForTopologicalSort {
    <#
    .SYNOPSIS
    Converts Prompts to a format that is accepted by the Get-TopologicalSort function
    
    .DESCRIPTION
    Transforms interactive prompts into a dependency graph format suitable for topological sorting.
    Extracts prompt requirements and creates a hashtable where each prompt name maps to its dependencies.
    
    .PARAMETER Prompts
    System.HashTable - Interactive prompts to be converted for topological sorting
    
    .OUTPUTS
    System.Collections.Hashtable - Dependency graph where keys are prompt names and values are arrays of required prompt names
    #>
    param(
        [Parameter(Mandatory = $true)][HashTable]$Prompts
    )
    [HashTable]$Results = @{}

    foreach ($InteractivePrompt in $Prompts.GetEnumerator()) {
        if ($InteractivePrompt.value.Requirements.Prompts) {
            $Results[$InteractivePrompt.Name] = $InteractivePrompt.value.Requirements.Prompts
        }
        else {
            $Results[$InteractivePrompt.Name] = @()
        }
    }
    return $Results
}
