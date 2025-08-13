function Test-UserContinue {
    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        [Parameter(HelpMessage = 'Just a message about what we are skipping of entering info for')][String]$Message
    )
    if ($Message) {
        $response = read-host $Message
    }
    else {
        $response = read-host "Press enter to confirm; or any other key (and then enter) to exit"
    }
    $aborted = ! [bool]$response
    if (!$aborted) {
        return $false
    }
    else {
        return $true
    }
}