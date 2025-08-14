function Test-MgConnected {
    <#
    .SYNOPSIS
    Checks if a connection to Microsoft Graph is Present
    .DESCRIPTION
    Checks if a connection to Microsoft Graph is Present. If its not initiate one.
    This is a Boolean function, and should be used as such
    .PARAMETER UserPrincipalName
    UserprincipalName to connect to Microsoft Graph With
    .PARAMETER NoRetry
    If an error occurs doesnt prompt to retry
    .OUTPUTS
    system.boolean $True for connected $False for not
    .INPUTS
    system.string UserprincipalName
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([Boolean])]
    param (
        [Parameter(Mandatory = $false)][String]$UserPrincipalName,
        [Parameter(Mandatory = $false)][switch]$NoRetry,
        [Parameter(Mandatory = $false)][switch]$NoPermissions,
        [Parameter(Mandatory = $false)][System.Collections.ArrayList]$DirectoryRoles = @()
    )
    Begin {}
    Process {
        [HashTable]$SplatTestMgConn = @{}
        if ($DirectoryRoles) {
            [void] $SplatTestMgConn.Add('DirectoryRoles', $DirectoryRoles)
        }
        [HashTable]$ConnectMgSplat = @{
            Scopes      = @('User.ReadWrite.All', 'Directory.Read.All', 'Organization.Read.All', 'RoleManagement.Read.Directory')
            ErrorAction = 'Stop'
        }
        if ($UserPrincipalName) {
            $ConnectMgSplat.Add('AccountId', $UserPrincipalName)
        }
        else {
            # Use current user context similar to original whoami /UPN fallback
            try {
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                if ($currentUser -like "*@*") {
                    $ConnectMgSplat.Add('AccountId', $currentUser)
                }
            }
            catch {
                # Fallback to interactive if current user detection fails
                Write-Log -Level Debug -Message 'Could not detect current user context, using interactive authentication'
            }
        }
        try {
            $context = Get-MgContext -ErrorAction Stop
            if ($context -and $context.Environment -eq 'Global') {
                Write-Log -Level Debug -Message 'Microsoft Graph Session open continuing'
            }
            else {
                return $false
            }
        }
        catch {
            if ($PSCmdlet.ShouldProcess("Microsoft Graph Connection", "Establish")) {
                try {
                    Write-Log -Level Debug -Message 'Connecting to Microsoft Graph.'
                    Connect-MgGraph @ConnectMgSplat | Out-Null
                }
                catch {
                    Write-Log -Level Error -Message $_.Exception.Message -ExceptionInfo $_
                    if (!$NoRetry) {
                        $response = read-host "Press enter to try again or any other key (and then enter) to abort"
                        $aborted = ! [bool]$response
                        if (!$aborted) {
                            Write-Log -Level Warning -Message 'Aborted by user.'
                            return $false
                        }
                        else {
                            Test-MgConnected @SplatTestMgConn
                        }
                    }
                }
            }
        }
    }
    End {
        if ($NoPermissions) {
            Write-Log -Level Debug -Message 'Permissions will not be checked.'
            return $true
        }
        else {
            #Check User have perms
            [HashTable]$SplatMgPerms = @{}
            if ($DirectoryRoles) {
                [void] $SplatMgPerms.Add('DirectoryRoles', $DirectoryRoles)
            }
            if (Assert-MgPermission @SplatMgPerms) {
                return $true
            }
            else {
                Disconnect-MgGraph
                Test-MgConnected @SplatTestMgConn
            }
        }
    }
}
