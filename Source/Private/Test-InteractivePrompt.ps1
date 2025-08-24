function Test-InteractivePrompt {
    <#
    .SYNOPSIS
    Presents the inputted prompts to the user.

    .DESCRIPTION
    Presents Interactive prompts in a Topologically sorted order based on each prompt's unique requirements

    .PARAMETER InteractivePrompts
    System.HashTable - Contains all Interactive Prompts to present to the user for Answers

    .PARAMETER AutoMemberOf
    System.HashTable - Contains all No Prompting Groups to add the user to with conditions.

    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param(
        [parameter(Mandatory = $true)][HashTable]$InteractivePrompts,
        [Parameter(Mandatory = $false)][HashTable]$AutoMemberOf,
        [Parameter(Mandatory = $false)][boolean]$FileServerAccess = $false,
        [Parameter(Mandatory = $false)][String]$M365License = ''
    )
    # Prompts without Requirements
    [HashTable]$PWOReqs = @{}
    $InteractivePrompts.keys | ForEach-Object { if ($null -eq $InteractivePrompts.$_.Requirements) { $PWOReqs[$_] = $InteractivePrompts[$_] } }
    # Prompts with Requirements and without Requirements on other Prompts
    [HashTable]$PWReqsWOReqsOTHP = @{}
    $InteractivePrompts.keys | ForEach-Object { if (($null -ne $InteractivePrompts.$_.Requirements) -and ($null -eq $InteractivePrompts.$_.Requirements.Prompts)) { $PWReqsWOReqsOTHP[$_] = $InteractivePrompts[$_] } }
    # Prompts with Requirements and with Requirements on other Prompts
    [HashTable]$PWReqsWReqsOTHP = @{}
    $InteractivePrompts.keys | ForEach-Object { if (($null -ne $InteractivePrompts.$_.Requirements) -and ($null -ne $InteractivePrompts.$_.Requirements.Prompts)) { $PWReqsWReqsOTHP[$_] = $InteractivePrompts[$_] } }

    # RESULTS
    # Results With Requirements
    [HashTable]$ResultsWOReqs = @{}
    # Results With Requirements On Other Prompts
    [HashTable]$ResultsWReqsWReqsOTHP = @{}
    # Combination of the Above Results
    [HashTable]$CombinedResults = @{}
    # The Final Results that will be returned
    [System.Collections.ArrayList]$Results = @()

    # If Prompts without Requirements process them.
    if ($PWOReqs) {
        $Test_PWOReqs = Test-Prompt -Prompts $PWOReqs
        if ($Test_PWOReqs) {
            # Add any results to the result variables
            $Test_PWOReqs.GetEnumerator() | ForEach-Object { $ResultsWOReqs.Add($_.key, $_.Value) }
        }
    }
    # If Prompts with Requirements and without Requirements on other Prompts exist lets process them.
    if ($PWReqsWOReqsOTHP) {
        $Test_PWReqsWOReqsOTHP = Test-PromptM365AndFileServerAccess -Prompts $PWReqsWOReqsOTHP -M365License $M365License -FileServerAccess $FileServerAccess
        if ($Test_PWReqsWOReqsOTHP) {
            # Add any results to the result variables
            $Test_PWReqsWOReqsOTHP.GetEnumerator() | ForEach-Object { $ResultsWOReqs.Add($_.key, $_.Value) }
        }
    }
    # Prompts with Requirements and with Requirements on other Prompts exist lets process them.
    if ($PWReqsWReqsOTHP) {
        $Test_PWReqsWReqsOTHP = Test-PromptsWRequsOTHPrompt -prompts $PWReqsWReqsOTHP -FileServerAccess $FileServerAccess -M365License $M365License -ResultsWOReqs $ResultsWOReqs
        if ($Test_PWReqsWReqsOTHP) {
            # Convert any results for Topological sorting
            $Convert_Prompts = Convert-InteractivePromptsForTopologicalSort $Test_PWReqsWReqsOTHP
            # Topologicaly sort and resolve the prompts
            $Resolve_PWReqsWReqsOTHP = Resolve-Prompt -Prompts $Convert_Prompts -OriginalPrompts $InteractivePrompts
            if ($Resolve_PWReqsWReqsOTHP) {
                # Add any results to the result variables
                $Resolve_PWReqsWReqsOTHP.GetEnumerator() | ForEach-Object { $ResultsWReqsWReqsOTHP.Add($_.key, $_.Value) }
            }
        }
    }
    # Combine any results into one Variable
    $ResultsWOReqs.GetEnumerator() | ForEach-Object { $CombinedResults.Add($_.key, $_.Value) }
    $ResultsWReqsWReqsOTHP.GetEnumerator() | ForEach-Object { $CombinedResults.Add($_.key, $_.Value) }
    # Iterate over all results
    foreach ($CR in $CombinedResults.keys) {
        # Add each Group to the results variable, if it is not already present
        foreach ($Group in $CombinedResults.$CR.MemberOf) {
            If ($Results -notcontains $Group) {
                [void] $Results.Add($Group)
            }
        }
    }

    # If any AutoMember of provided resolve them
    if ($AutoMemberOf) {
        $Resolve_AutoMemberOf = Resolve-AutoMemberOf -InteractivePromptAnswers $CombinedResults -AutoMemberOf $AutoMemberOf -M365License $M365License -FileServerAccess:$FileServerAccess
        If ($Resolve_AutoMemberOf) {
            # Iterate over all results
            foreach ($RAMO in $Resolve_AutoMemberOf.keys) {
                # Add each Group to the results variable, if it is not already present
                foreach ($Group in $Resolve_AutoMemberOf.$RAMO.MemberOf) {
                    If ($Results -notcontains $Group) {
                        [void] $Results.Add($Group)
                    }
                }
            }
        }
    }
    return [System.Collections.ArrayList]$Results
}
