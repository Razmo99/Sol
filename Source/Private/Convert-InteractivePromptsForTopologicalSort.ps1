function Convert-InteractivePromptsForTopologicalSort {
    <#
    .SYNOPSIS
    Converts Promtps to a format that is accepeted by the Get-TopologicalSort function
    .PARAMETER Prompts
    System.HashTable - Prompts to be converted
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
