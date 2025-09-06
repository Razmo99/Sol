function Assert-MgPermission {
    <#
    .SYNOPSIS
    Asserts the current user has permission in Microsoft Graph
    .DESCRIPTION
    Retrieves the current users Microsoft Graph directory roles and matches it against the provided admin groups. Defaults to Global Administrator if no groups are provided
    returns true for a match and false for no match
    .PARAMETER DirectoryRoles
        Microsoft Graph Directory Role Display names to check
    .PARAMETER UserPrincipalName
        User principal name to check the permissions of
    .INPUTS
        System.Collections.ArrayList for Admin Groups
        system.string for UserPrincipalName
    .OUTPUTS
        system.boolean
    #>

    [CmdletBinding()]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][System.Collections.ArrayList]$DirectoryRoles = @(),
        [Parameter(Mandatory = $false)][String]$UserPrincipalName

    )
    Begin {

        [Hashtable]$SplatTestMgConnected = @{
            verbose      = $false
            NoPermissions = $true
        }
        if ($UserPrincipalName) {
            $SplatTestMgConnected.Add('UserPrincipalName', $UserPrincipalName)
        }
        $null = Test-MgConnected @SplatTestMgConnected
    }
    Process {
        if ($DirectoryRoles -notcontains 'Global Administrator') {
            [void] $DirectoryRoles.Add('Global Administrator')
        }
        # Get the UserPrincipalName of any active Microsoft Graph Sessions
        # Return only the first result.
        # This is just in case the user has multiple sessions open with different accounts
        if (!$UserPrincipalName) {
            try {
                $MgCurrentSessionInfo = (Get-MgContext -ErrorAction Stop).Account | Select-Object -First 1
            }
            catch {
                Write-Log -Level Error -Message 'Failed to get Microsoft Graph context: {0}' -Arguments $_.Exception.Message
                return $false
            }
        }
        else {
            $MgCurrentSessionInfo = $UserPrincipalName
        }

        try {
            # Get all Microsoft Graph Directory Roles for the user
            $memberships = Get-MgUserMemberOf -UserId $MgCurrentSessionInfo -All -ErrorAction Stop
            $directoryRoleMemberships = $memberships | Where-Object { $_.OdataType -eq '#microsoft.graph.directoryRole' }

            # Get the detailed role information
            $MgDirectoryCurrentUserRoles = @()
            foreach ($roleMembership in $directoryRoleMemberships) {
                try {
                    $roleDetail = Get-MgDirectoryRole -DirectoryRoleId $roleMembership.Id -ErrorAction Stop
                    $MgDirectoryCurrentUserRoles += $roleDetail
                }
                catch {
                    Write-Log -Level Warning -Message 'Failed to get details for role {0}: {1}' -Arguments @($roleMembership.Id, $_.Exception.Message)
                }
            }
        }
        catch {
            Write-Log -Level Error -Message 'Failed to get user directory roles for {0}: {1}' -Arguments @($MgCurrentSessionInfo, $_.Exception.Message)
            return $false
        }

        $result = $false
        #Iterate over all the Microsoft Graph Directory Roles
        foreach ($DirectoryRole in $DirectoryRoles) {
            #Check first if we got any returned roles
            if ($MgDirectoryCurrentUserRoles.DisplayName) {
                # Check for a match
                if ($MgDirectoryCurrentUserRoles.DisplayName.Contains($DirectoryRole)) {
                    $result = $true
                    Write-Log -Level Debug -Message '{0} has Microsoft Graph directory role {1} assigned' -Arguments @($MgCurrentSessionInfo, $DirectoryRole)
                }
            }
        }
        if (!$result) {
            Write-Log -Level Warning -Message 'Insufficient Microsoft Graph permissions'
            return $result
        }
        else {
            Write-Log -Level Debug -Message '{0} has sufficient Microsoft Graph permissions' -Arguments $MgCurrentSessionInfo
            return $result
        }
    }
    End {}
}