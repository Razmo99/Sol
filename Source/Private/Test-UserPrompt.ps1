function Test-UserPrompt {
    param (
        [Parameter(Mandatory = $true)][String]$Message,
        [Parameter(Mandatory = $false)][boolean]$Inverse = $false
    )
    # If prompt is inverse (!)bang it
    if ($Inverse) {
        $TestUser = !(Test-UserContinue -Message $Message)
        # else normal
    }
    else {
        $TestUser = Test-UserContinue -Message $Message
    }
    return $TestUser
}
