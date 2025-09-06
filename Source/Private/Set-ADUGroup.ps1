function Set-ADUGroup {
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

    [cmdletbinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][String]$Identity,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Array]$Groups,
        [Parameter(Mandatory = $true)][String]$Server,
        [Parameter(Mandatory = $false)][pscredential]$Credential
    )
    Begin {}
    Process {
        #Let the console know what we are doing
        Write-Log -Level Debug -Message '{0} will be added to the below groups' -Arguments $Identity
        $Groups | ForEach-Object { Write-Log -Level Debug -Message $_ }
        Write-Log -Level Debug -Message 'Trying to Set AD Groups for user; {0}' -Arguments $Identity
        #Splat for Get AD Users Groups
        [HashTable]$SplatGetADPrince = @{
            Server      = $Server
            Identity    = $Identity
            ErrorAction = 'Stop'
        }
        #Splat for Set AD User Groups
        [HashTable]$SplatSetADPrince = @{
            Server      = $Server
            Identity    = $Identity
            Memberof    = ''
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            Write-Log -Level Debug -Message 'Admin credentials provided.'
            $SplatSetADPrince.Add('Credential', $Credential)
            $SplatGetADPrince.Add('Credential', $Credential)
        }
        [PSCustomObject]$Results = @{
            Identity = $Identity
            MemberOf = @()
        }
        # Finally do a loop to add each group to the user writing output to the console
        foreach ($Group in $Groups) {
            $TimeStart = Get-Date
            $TimeEnd = $timeStart.addminutes(0.5)
            $SplatSetADPrince['Memberof'] = $Group
            if ($PSCmdlet.ShouldProcess($Identity, 'Add-ADPrincipalGroupMembership -MemberOf "' + $Group)) {
                do {
                    $TimeNow = Get-Date
                    $Finished = $false
                    try {
                        if (!(Get-ADPrincipalGroupMembership @SplatGetADPrince | Select-Object SamAccountName | Where-Object -Property SamAccountName -Value $Group -EQ)) {
                            Write-Log -Level Debug -Message 'User is not a memberof "{0}" procceding to add them. ' -Arguments $Group
                            try {
                                Add-ADPrincipalGroupMembership @SplatSetADPrince
                                Write-Log -Level Debug -Message 'Successfully Added user; {0} To Group; {1}' -Arguments @($Identity, $Group)
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName = $Group
                                    Result         = $True
                                }
                                $Finished = $true
                            }
                            catch [System.Management.Automation.MethodException] {
                                Write-Log -Level Error -Message 'Provided credentials have insufficient permissions to change user groups'
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName = $Group
                                    Result         = $False
                                }
                                break
                            }
                            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                                Write-Log -Level Error -Message 'Cannot Find {0} Skipping' -Arguments $Group
                                $Results.MemberOf += [PSCustomObject]@{
                                    SamAccountName = $Group
                                    Result         = $False
                                }
                                $Finished = $true
                            }
                            catch {
                                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                                break
                            }
                        }
                        else {
                            Write-Log -Level Debug -Message 'User is already a MemberOf {0} Skipping' -Arguments $Group
                            $Results.MemberOf += [PSCustomObject]@{
                                SamAccountName = $Group
                                Result         = $True
                            }
                            $Finished = $true
                        }
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Log -Level Warning -Message 'Provided credentials have insufficient permissions to change user groups'
                        break
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                        $Finished = $false
                        Write-Log -Level Debug -Message 'User Not Found | Sleeping'
                        Start-Sleep 3
                    }
                    catch {
                        Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                        break
                    }
                    if ($TimeNow -ge $TimeEnd) {
                        $Finished = $true
                        Write-Log -Level Warning -Message 'Searched for 30 seconds Exiting.'
                    }
                } until ($Finished)
            }
        }
        if ($Results.MemberOf) {
            Write-Log -Level Debug -Message 'Returning Results'
            [PSCustomObject]$Results
        }
    }
    End {}
}
