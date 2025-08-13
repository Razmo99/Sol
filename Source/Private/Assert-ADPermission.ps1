function Assert-ADPermission {
    <#
    .SYNOPSIS
    Asserts that the current user is a part of the specified groups
    .DESCRIPTION
    Retreives the current users AD Groups and matches it against the provided admin groups for a match
    returns true for a match and false for no match
    .PARAMETER AdminGroups
        system.array ADGroup Names to match against
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .INPUTS
        system.array for Admin Groups
        system.string for server
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$Server,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][array]$AdminGroups,
        [Parameter(Mandatory=$false)][PSCredential]$Credential,
        [Parameter(Mandatory=$false)][String]$SamAccountName

    )

    $whoami = (whoami).split('\')

    [HashTable]$SplatGetADPrince =@{
        Identity = $whoami[1]
        Server = $Server
        ErrorAction = 'stop'
    }

    if($Credential){$SplatGetADPrince.Add('Credential',$Credential)}
    if($SamAccountName){$SplatGetADPrince.Identity = $SamAccountName}

    if ($PSCmdlet.ShouldProcess($SamAccountName, 'Compare-Object "'+$AdminGroups+'"')) {
        try {
            #Get the groups that the current user is a member of
            $MemberOf = Get-ADPrincipalGroupMembership @SplatGetADPrince | Select-Object SamAccountName
            #Compare the groups agains the provided admin groups
            $ComparedResults = Compare-Object -ReferenceObject $AdminGroups -DifferenceObject $MemberOf.samaccountname -IncludeEqual
            #Check each result for a match
            foreach($Result in $ComparedResults){
                # if a match is found return true and break the loop
                if ($Result.SideIndicator -eq "==") {
                    Write-Verbose('"'+$SplatGetADPrince.Identity+'" has sufficient Active Directory permissions.')
                    return $true
                    break
                }
            }
        }catch [Microsoft.ActiveDirectory.Management.ADException]{
            #Evidently the user doesnt have access to AD, as they are unable to get what groups they are a memeber of
            Write-Verbose($_.Exception.message)
            Write-Verbose('"'+$SplatGetADPrince.Identity+'" has insufficient Active Directory permissions.')
            return $false
        }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
            Write-Verbose('Failed to find "'+$SplatGetADPrince.Identity+'" on "'+$Server+'"')
            return $false
        }catch [System.Security.Authentication.AuthenticationException]{
            Write-Verbose($Server+' has rejected the client credentials.')
            return $false
        }catch{
            Write-Error($_.Exception.message)
        }
        # If the foreach loop doesnt return/break the function return false as no match was found
        Write-Verbose('"'+$SplatGetADPrince.Identity+'" has insufficient Active Directory permissions.')
        return $false
    }
}
