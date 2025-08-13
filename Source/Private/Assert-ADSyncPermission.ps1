function Assert-ADSyncPermission {
    <#
    .SYNOPSIS
        Asserts the current user can create a PSSession to the specified server
    .DESCRIPTION
        tries to create a New-PSSession to the specified server
        returns true for a match and false for no match
    .PARAMETER Server
        system.string Exchange Management server to assert against
    .INPUTS
        system.pscredentials for Credential
        system.string for server
    .OUTPUTS
        system.boolean
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$Server,
        [parameter(Mandatory = $false)][pscredential]$Credential
    )
    Begin {}
    Process {
        # Default parameters for the sessions
        [hashtable]$SplatNewPSSession = @{
            ComputerName = $Server
            ErrorAction  = 'Stop'
        }
        #Add Credentials if presented
        if ($Credential) {
            Write-Log -Level Debug -Message 'ADSync Credentials provided'
            $SplatNewPSSession.Add('Credential', $Credential)
        }
        # boolean to return
        $Result = $true
        try {
            # open a sessions to the ADSync Server
            $Session = New-PSSession @SplatNewPSSession
            # Try to get the local ADSync Groups and see if the user is part of them
            try {
                if ($Credential.UserName.Contains('\')) {
                    $CredentialUsername = $Credential.UserName.Split('\')[1]
                }
                else {
                    $CredentialUsername = $Credential.UserName.Split('\')[0]
                }
                # Local Group
                $SyncAdmins = Invoke-Command -Session $Session -Command { Get-LocalGroupMember -Group 'ADSyncAdmins' }
                # Local Group
                $ADSyncOperators = Invoke-Command -Session $Session -Command { Get-LocalGroupMember -Group 'ADSyncOperators' }
                # boolean to determine answer
                $ADSyncPerms = $false
                # AD Groups the user is a memver of
                $CredentialGroups = (Get-ADPrincipalGroupMembership -Identity $CredentialUsername).Name
                # Merged Array of the Local Groups Above
                # Compare Merged Local Groups against the current credentials Group Membership for a match
                if ((Compare-Object -ReferenceObject $ADSyncOperators.Name.Split('\') -DifferenceObject $CredentialGroups -ExcludeDifferent -IncludeEqual) -or (Compare-Object -ReferenceObject $SyncAdmins.Name.Split('\') -DifferenceObject $CredentialGroups -ExcludeDifferent -IncludeEqual)) {
                    $ADSyncPerms = $true
                    Write-Log -Level Debug -Message '{0} is part of a group that has sufficient permissions' -Arguments $CredentialUsername
                }
                elseif (($ADSyncOperators.Name.Split('\').Contains($CredentialUsername) -or ($SyncAdmins.Name.Split('\').Contains($CredentialUsername) ))) {
                    $ADSyncPerms = $true
                    Write-Log -Level Debug -Message '{0} is has sufficient permissions' -Arguments $CredentialUsername
                }
                #Adjust result if the user does not have permissions
                if (!$ADSyncPerms) { $Result = $false }
            }
            catch {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
            # Clean up the session
            $Session | Remove-PSSession
        }
        catch [System.Management.Automation.ErrorRecord] {
            if ($_.Exception.Message.contains('Access is denied')) {
                $Result = $False
            }
            else {
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
        }
        catch {
            if ($_.Exception.Message.Contains('The user name or password is incorrect.')) {
                Write-Log -Level Debug -Message 'Incorrect Username or password.'
                $Result = $False
            }
            elseif ($_.Exception.Message.Contains('Access is denied.')) {
                Write-Log -Level Debug -Message 'ADSync: The provided credentials are insufficient.'
                $Result = $False
            }
            else {
                $Result = $False
                Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
            }
        }
        if ($Result) {
            Write-Log -Level Debug -Message 'ADSync Credentials have sufficient permissions.'
        }
        return $Result
    }
    End {}
}