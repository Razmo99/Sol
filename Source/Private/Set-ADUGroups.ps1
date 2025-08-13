function Set-ADUGroups {
    <#
    .SYNOPSIS
    Adds the user to the specific groups
    .DESCRIPTION
    Adds the specified user to multiple groups.

    .PARAMETER Identity
        system.string Attribute of the Active Directory account to match
        E.G 'firstname.lastname'
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER Groups
        System.Array All groups the user is to be added to
        Must be the sAMAccountName Attribute of the AD Groups
    .PARAMETER Credential
        pscredentials Used to authenticate to the designated Domain Controller
    .INPUTS
        system.string for Identity
        System.Array for Groups
        system.string for Server
    .OUTPUTS
        returns one or Multiple PSCustomObjects depending on input.
        Contains MemberOf & Identity Properties
        MemberOf is an array of PSCustomObjects containing the properties: SamAccountName & Result.
            SamAccountName of the groups inputed to the command
            Result of the command Boolean
        Identity the same Identity that was input to the function
    #>
    
    [cmdletbinding(SupportsShouldProcess=$true)]
    param (        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][String]$Identity,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Array]$Groups,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    Begin{}
    Process{
        #Let the console know what we are doing
        Write-Verbose($Identity+' will be added to the below groups')
        $Groups | ForEach-Object {Write-Verbose($_)}
        Write-Verbose('Trying to Set AD Groups for user; '+$Identity)
        #Splat for Get AD Users Groups
        [HashTable]$SplatGetADPrince = @{
            Server = $Server
            Identity = $Identity
            ErrorAction = 'Stop'
        }
        #Splat for Set AD User Groups
        [HashTable]$SplatSetADPrince = @{
            Server = $Server
            Identity = $Identity
            Memberof = ''
            ErrorAction = 'Stop'
        }
        if($Credential){
            Write-Verbose('Admin credentials provided.')
            $SplatSetADPrince.Add('Credential',$Credential)
            $SplatGetADPrince.Add('Credential',$Credential)
        }
        [PSCustomObject]$Results=@{
            Identity=$Identity
            MemberOf=@()
        }
        # Finally do a loop to add each group to the user writing output to the console
        foreach($Group in $Groups){
            $TimeStart = Get-Date
            $TimeEnd = $timeStart.addminutes(0.5)
            $SplatSetADPrince['Memberof']=$Group
            if ($PSCmdlet.ShouldProcess($Identity, 'Add-ADPrincipalGroupMembership -MemberOf "'+$Group)) {
                do {
                    $TimeNow = Get-Date
                    $Finished=$false
                    try {
                        if (!(Get-ADPrincipalGroupMembership @SplatGetADPrince | Select-Object SamAccountName | Where-Object -Property SamAccountName -Value $Group -EQ)) {
                            Write-Verbose('User is not a memberof "'+$Group+'" procceding to add them. ')
                            try {
                                    Add-ADPrincipalGroupMembership @SplatSetADPrince
                                    Write-Verbose('Successfully Added user; '+$Identity+' To Group; '+$Group)
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$True
                                }
                                $Finished=$true                 
                            }catch [System.Management.Automation.MethodException]{
                                Write-Error('Provided credentials have insufficient permissions to change user groups')
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$False
                                }
                                break
                            }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                                Write-Error("Cannot Find "+$Group+" Skipping")
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName=$Group
                                    Result=$False
                                }
                                $Finished=$true
                            }catch {
                                Write-Error($_.Exception.Message)
                                break
                            }
                        }else{
                            Write-Verbose('User is already a MemberOf '+$Group+' Skipping')
                            $Results.MemberOf += [PSCustomObject]@{
                                SamAccountName=$Group
                                Result=$True
                            }
                            $Finished=$true
                        }
                    }catch [Microsoft.ActiveDirectory.Management.ADException]{
                        Write-Warning('Provided credentials have insufficient permissions to change user groups')
                        break
                    }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                        $Finished=$false
                        Write-Verbose('User Not Found | Sleeping')
                        Start-Sleep 3
                    }catch{
                        write-error($_.Exception.Message)
                        break
                    }
                    if($TimeNow -ge $TimeEnd){
                        $Finished = $true
                        Write-Warning('Searched for 30 seconds Exiting.')
                    }
                } until ($Finished)
            }
        }
        if($Results.MemberOf){
            Write-Verbose('Returning Results')
            [PSCustomObject]$Results
        }
    }
    End{}
}
