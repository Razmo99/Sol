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

    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$Server,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][array]$AdminGroups,
        [Parameter(Mandatory = $false)][PSCredential]$Credential,
        [Parameter(Mandatory = $false)][String]$SamAccountName

    )

    Begin {}
    Process {
        $whoami = (whoami).split('\')

        [HashTable]$SplatGetADPrince = @{
            Identity    = $whoami[1]
            Server      = $Server
            ErrorAction = 'stop'
        }

        if ($Credential) { $SplatGetADPrince.Add('Credential', $Credential) }
        if ($SamAccountName) { $SplatGetADPrince.Identity = $SamAccountName }

        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Compare-Object "' + $AdminGroups + '"')) {
            try {
                #Get the groups that the current user is a member of
                $MemberOf = Get-ADPrincipalGroupMembership @SplatGetADPrince | Select-Object SamAccountName
                #Compare the groups agains the provided admin groups
                $ComparedResults = Compare-Object -ReferenceObject $AdminGroups -DifferenceObject $MemberOf.samaccountname -IncludeEqual
                #Check each result for a match
                foreach ($Result in $ComparedResults) {
                    # if a match is found return true and break the loop
                    if ($Result.SideIndicator -eq "==") {
                        Write-Log -Level Debug -Message '{0} has sufficient Active Directory permissions.' -Arguments $SplatGetADPrince.Identity
                        return $true
                        break
                    }
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADException] {
                #Evidently the user doesnt have access to AD, as they are unable to get what groups they are a memeber of
                Write-Log -Level Debug -Message $_.Exception.message -ExceptionInfo $_
                Write-Log -Level Debug -Message '{0} has insufficient Active Directory permissions.' -Arguments $SplatGetADPrince.Identity
                return $false
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Log -Level Debug -Message 'Failed to find {0} on {1}' -Arguments @($SplatGetADPrince.Identity, $Server)
                return $false
            }
            catch [System.Security.Authentication.AuthenticationException] {
                Write-Log -Level Debug -Message '{0} has rejected the client credentials.' -Arguments $Server
                return $false
            }
            catch {
                Write-Log -Level Error -Message $_.Exception.message -ExceptionInfo $_
            }
            # If the foreach loop doesnt return/break the function return false as no match was found
            Write-Log -Level Debug -Message '{0} has insufficient Active Directory permissions.' -Arguments $SplatGetADPrince.Identity
            return $false
        }
    }
    End {}
}