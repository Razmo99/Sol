function Test-Prompt {
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