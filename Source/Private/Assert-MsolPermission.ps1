function Assert-MsolPermission {
    <#
    .SYNOPSIS
    Asserts the current user has permission in Msol
    .DESCRIPTION
    Retreives the current users AzureAD Roles and matches it against the provided admin groups. Defaults to Global Administrator if no groups are provided
    returns true for a match and false for no match
    .PARAMETER MsolRoles
        Msole Role Display names to to check for
    .PARAMETER UserPrincipalName
        Userprinciple name of to check the permissions of
    .INPUTS
        System.Collections.ArrayList for Admin Groups
        system.string for UserPrincipalName
    .OUTPUTS
        system.boolean
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][System.Collections.ArrayList]$MsolRoles = @(),
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][String]$UserPrincipalName

    )
    Begin {
        if (!(Test-MSolConnected)) {
            Write-Log -Level Debug -Message 'No existing Msol session detected'
            try {
                Write-Log -Level Debug -Message 'Initiating connection to Msol'
                Connect-MsolService -ErrorAction Stop
                Write-Log -Level Debug -Message 'Connected to Msol successfully'
            }
            catch {
                return Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
        }
    }
    Process {
        #Add the company Administrator Role, presumed to have access to everything.
        if ($MsolRoles -notcontains 'Company Administrator') {
            [void] $MsolRoles.Add('Company Administrator')
        }
        #In Try catch for users who cannot call Get-MsolUserRole
        try {
            $MsolCurrentUserRoles = Get-MsolUserRole -UserPrincipalName $UserPrincipalName -ErrorAction Stop
            $result = $false
            #Iterate over all provided Msol Roles to check for
            foreach ($MsolRole in $MsolRoles) {
                #Check if Get-MsolUserRole returned anything
                if ($MsolCurrentUserRoles.Name) {
                    # Check for a match
                    if ($MsolCurrentUserRoles.Name.Contains($MsolRole)) {
                        $result = $true
                        Write-Log -Level Debug -Message '{0} has Msol role {1} assigned' -Arguments @($UserPrincipalName, $MsolRole)
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like 'Access Denied. You do not have permissions to call this cmdlet.') {
                Write-Log -Level Debug -Message '{0} does not have permissions to call "Get-MsolUserRole"' -Arguments $UserPrincipalName
            }
            else {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
        }

        if (!$result) {
            Write-Log -Level Warning -Message 'Insufficient Msol permissions'
            return $result
        }
        else {
            Write-Log -Level Debug -Message 'Sufficient Msol permissions'
            return $result
        }
    }
    End {}
}
