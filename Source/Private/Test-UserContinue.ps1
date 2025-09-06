function Test-UserContinue {
    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        [Parameter(HelpMessage = 'Just a message about what we are skipping of entering info for')][String]$Message
    )

    $splat = @{
        Prompt = "Press enter to confirm; or any other key (and then enter) to exit"
    }

    if ($Message) {
        $splat.Prompt = $Message
    }
    Wait-Logging
    $response = read-host @splat
    
    $aborted = ! [bool]$response
    if (!$aborted) {
        return $false
    }
    else {
        return $true
    }
}