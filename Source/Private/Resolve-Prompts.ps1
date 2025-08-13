function Resolve-Prompts {
    <#
    .SYNOPSIS
    Resolves the provided prompts using Topological sorting till completion
    .DESCRIPTION
    Passes inputted prompts to the user to get answers.
    Then re calculates the topological sorting based off the answers till all prompts are exhausted
    
    .PARAMETER Prompts
    System.Hashtable - Prompts that have been converted for Topological Sorting
    
    .PARAMETER OriginalPrompts
    System.Hashtable - Unmodified Original Prompts with all metadata
    #>
    [CmdletBinding()]param(

        [parameter(Mandatory=$true)][HashTable]$Prompts,
        [parameter(Mandatory=$true)][HashTable]$OriginalPrompts
    )
    # Clone the prompts as to not modify the source
    $currentPrompts = [HashTable] (Get-ClonedObject $Prompts)
    # This is a queue so that as answers are received the currentPrompts can be updated and then reproccessed
    $PromptsQueue = New-Object System.Collections.Queue
    # Kick it all off by Enqueueing the current prompts
    $PromptsQueue.Enqueue((Get-TopologicalSort $currentPrompts))
    # This Array contains the names of prompts that returned true
    [HashTable]$PromptAnswers = @{}
    # Primary While Loop keep Iterating aslong as the queue is not empty.
    While($PromptsQueue.Count -gt 0){
        # Dequeue The current Prompts
        $PromptsDequeue = $PromptsQueue.Dequeue()
        # Iterate over the prompts to be tested
        Foreach($Key in $PromptsDequeue){
            # If the Prompt has not been answered
            if ($PromptAnswers.keys -notcontains $Key){
                # Test the User
                $TestUser = Test-UserPrompt -Message $OriginalPrompts.$Key.message -Inverse:$OriginalPrompts.$Key.inverse
                if ($TestUser){
                    # If the prompt is answered true add the prompt to Answers
                    [void ]$PromptAnswers.Add($key,$OriginalPrompts.$Key)
                }else{
                    # If the prompt is answered false remove the prompt in question from the current prompts.
                    $currentPrompts.Remove($Key)
                    # Re que the current Prompts for another round
                    $PromptsQueue.Enqueue((Get-TopologicalSort $currentPrompts))
                    # Break the loop and reset it
                    break
                }
            }
        }
    }
    return $PromptAnswers
}
