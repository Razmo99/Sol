function Test-Prompt {
    <#
    .SYNOPSIS
    Tests prompts without requirements and returns those answered positively by the user

    .DESCRIPTION
    Iterates over provided prompts that have no requirements and presents them to the user.
    Returns a hashtable containing only the prompts that the user answered "yes" to.

    .PARAMETER Prompts
    System.HashTable - Contains prompts without requirements to present to the user

    .OUTPUTS
    System.Collections.Hashtable - Contains prompts that the user answered positively
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)][HashTable]$Prompts
    )
    [HashTable]$Results = @{}
    Write-Log -Level Debug -Message 'Processing prompts without Requirements'
    # Iterate over the Prompts
    foreach ($key in $Prompts.keys) {
        $Prompt = $Prompts[$Key]
        if (Test-UserPrompt -Message $Prompt.Message -Inverse:$Prompt.Inverse) {
            # stick the groups into out results object
            [Void] $Results.Add($Key, $Prompts[$Key])
        }
    }
    return $Results
}