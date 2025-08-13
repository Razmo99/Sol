function Test-Prompts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][HashTable]$Prompts
    )
    [HashTable]$Results=@{}
    Write-Verbose('Processing prompts without Requirements')
    # Iterate over the Prompts
    foreach ($key in $Prompts.keys) {
        $Prompt = $Prompts[$Key]
        if(Test-UserPrompt -Message $Prompt.Message -Inverse:$Prompt.Inverse){
            # stick the groups into out results object
            [Void] $Results.Add($Key,$Prompts[$Key])
        }
    }
    return $Results
}
