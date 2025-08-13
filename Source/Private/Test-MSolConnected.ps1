function Test-MSolConnected {
    <#
    .SYNOPSIS
    Checks if a connection to Msol is Present
    .DESCRIPTION
        Just runs a command if it doesnt error return true
    .OUTPUTS
        system.boolean
    .INPUTS
     None
    #>
    try {
        Get-MsolCompanyInformation -ErrorAction Stop | Out-Null
        return $true         
    }catch {
        return $false
    }
}
