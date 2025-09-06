function Read-UserConfirm {
    <#
    .SYNOPSIS
    Prompts user to continue
    .DESCRIPTION
    Displays a message and asks the user to:
    "Press enter to confirm; or any other key (and then enter) to exit"
    .PARAMETER Message
        system.string
        Just a message about what we are skipping of entering info for
    .INPUTS
        None.
    .OUTPUTS
        system.boolean
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $false)][String]$Message = 'Press enter to confirm; or any other key (and then enter) to exit'
    )
    Wait-Logging
    $response = read-host $Message
    
    $aborted = ! [bool]$response
    
    if (!$aborted) {
        return $false
    }
    else {
        return $true
    }
}