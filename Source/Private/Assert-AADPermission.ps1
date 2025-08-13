function Assert-AADPermission {
    <#
    .SYNOPSIS
    Asserts the current user has permission in Azure ActiveDirectory
    .DESCRIPTION
    Retreives the current users AzureAD Roles and matches it against the provided admin groups. Defaults to Global Administrator if no groups are provided
    returns true for a match and false for no match
    .PARAMETER AADRoles
        Azure ActiveDirectory Role Display names to to check
    .PARAMETER UserPrincipalName
        Userprinciple name of to check the permissions of
    .INPUTS
        System.Collections.ArrayList for Admin Groups
        system.string for UserPrincipalName
    .OUTPUTS
        system.boolean
    #>
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][System.Collections.ArrayList]$AADRoles=@(),
        [Parameter(Mandatory=$false)][String]$UserPrincipalName

    )
    Begin{
        
        [Hashtable]$SplatTestAADConnected=@{
            verbose = $false
            NoPermission = $true
        }
        if ($UserPrincipalName) {
            $SplatTestAADConnected.Add('UserPrincipalName',$UserPrincipalName)
        }
        $null =  Test-AADConnected @SplatTestAADConnected
    }
    Process{
        if($AADRoles -notcontains 'Global Administrator'){
            [void] $AADRoles.Add('Global Administrator')
        }
        # Get the UserPrincipalName of any active AzureAD Sessions
        # Return only the first result.
        # This is just incase the user has multiple sessions open with differenet accounts
        if(!$UserPrincipalName){
            $AADCurrentSessionInfo = (Get-AzureADCurrentSessionInfo -ErrorAction Stop).Account.id | Select-Object -First 1
        }else{
            $AADCurrentSessionInfo = $UserPrincipalName
        }
        #Get all AzureAD Roles
        $AADDirectoryCurrentUserRoles = Get-AzureADUserMembership -ObjectId $AADCurrentSessionInfo -All $true | Where-Object { $_.ObjectType -eq "Role"}
        $result=$false
        #Iterate over all the AzureAD Roles
        foreach ($AADRole in $AADRoles) {
            #Check first if we got any returned roles
            if($AADDirectoryCurrentUserRoles.DisplayName){
                # Check for a match
                if($AADDirectoryCurrentUserRoles.DisplayName.Contains($AADRole)){
                    $result=$true
                    Write-verbose('"'+$AADCurrentSessionInfo+'" has AzureAD role "'+$AADRole+'" assigned')
                }
            }
        }
        if(!$result){
            Write-Warning('Insufficient AzureAD permissions')
            return $result
        }else{
            Write-Verbose($AADCurrentSessionInfo +' has sufficient AzureAD permissions')
            return $result
        }
    }
    End{}
}
