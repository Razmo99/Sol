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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][System.Collections.ArrayList]$MsolRoles=@(),
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][String]$UserPrincipalName

    )
    Begin{
        if (!(Test-MSolConnected)) {
            Write-Verbose('No existing Msol session detected')
            try {
                Write-Verbose('Initiating connection to Msol')
                Connect-MsolService -ErrorAction Stop
                Write-Verbose('Connected to Msol successfully')
            }catch{
                return Write-Error($_.Exception.Message)
            }
        }
    }
    Process{
        #Add the company Administrator Role, presumed to have access to everything.
        if($MsolRoles -notcontains 'Company Administrator'){
            [void] $MsolRoles.Add('Company Administrator')
        }
        #In Try catch for users who cannot call Get-MsolUserRole
        try{
            $MsolCurrentUserRoles = Get-MsolUserRole -UserPrincipalName $UserPrincipalName -ErrorAction Stop
            $result=$false
            #Iterate over all provided Msol Roles to check for
            foreach ($MsolRole in $MsolRoles) {
                #Check if Get-MsolUserRole returned anything
                if($MsolCurrentUserRoles.Name){
                    # Check for a match
                    if($MsolCurrentUserRoles.Name.Contains($MsolRole)){
                        $result=$true
                        Write-verbose('"'+$UserPrincipalName+'" has Msol role "'+$MsolRole+'" assigned')
                    }
                }
            }
        }catch{
            if($_.Exception.Message -like 'Access Denied. You do not have permissions to call this cmdlet.'){
                Write-Verbose($UserPrincipalName+' does not have permissions to call "Get-MsolUserRole"')
            }else{
                Write-Error($_.Exception.Message)
            }
        }

        if(!$result){
            Write-Warning('Insufficient Msol permissions')
            return $result
        }else{
            Write-Verbose('Sufficient Msol permissions')
            return $result
        }
    }
    End{}
}
