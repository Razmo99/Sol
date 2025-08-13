function Test-AADConnected{
    <#
    .SYNOPSIS
    Checks if a connection to AzureAD is Present
    .DESCRIPTION
    Checks if a connection to AzureAD is Present. If its not initiate one.
    This is a Boolean function, and should be used as such
    .PARAMETER UserPrincipalName
    UserprincipalName to connect to AzureAD With
    .PARAMETER CredentialPromp
    Switch to allow manual entry of Credentials
    .PARAMETER NoRetry
    If an error occurs doesnt prompt to retry
    .OUTPUTS
    system.boolean $True for connected $False for not
    .INPUTS
    system.string UserprincipalName
    #>
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false)][String]$UserPrincipalName,
        [Parameter(Mandatory=$false)][switch]$CredentialPrompt,
        [Parameter(Mandatory=$false)][switch]$NoRetry,
        [Parameter(Mandatory=$false)][switch]$NoPermissions,
        [Parameter(Mandatory=$false)][System.Collections.ArrayList]$AADRoles=@()
    )
    Begin{}
    Process{
        [HashTable]$SplatTestAADConn=@{
            CredentialPrompt = $true
        }
        if($AADRoles){
            [void] $SplatTestAADConn.Add('AADRoles',$AADRoles)
        }
        [HashTable]$ConnectAADSplat = @{}
        if ($UserPrincipalName) {
            $ConnectAADSplat = @{
                AccountId = $UserPrincipalName
                ErrorAction = 'Stop'
            }
        }elseif ($CredentialPrompt) {
            $ConnectAADSplat = @{
                ErrorAction = 'Stop'
            }
        }else{
            $ConnectAADSplat = @{
                AccountId = (whoami /UPN)
                ErrorAction = 'Stop'
            }
        }
        try{
            if((Get-AzureADCurrentSessionInfo -ErrorAction Stop).Environment.Name -eq 'AzureCloud') {
                Write-Verbose('AzureAD Session open continuing')
            }else{
                return $false
            }
        }
        catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
            try{
                Write-Verbose('Connecting to Azure AD.')
                Connect-AzureAD @ConnectAADSplat | Out-Null
            }
            catch {
                Write-Error($_.Exception.Message)
                if(!$NoRetry){
                    $response = read-host "Press enter to try again or any other key (and then enter) to abort"
                    $aborted = ! [bool]$response
                    if(!$aborted){
                        Write-Warning('Aborted by user.')
                        return $false
                    }else{
                        Test-AADConnected @SplatTestAADConn
                    }
                }
            }
        }
    }
    End{
        if($NoPermissions){
            Write-Verbose('Permissions will not be checked.')
            return $true
        }else{
            #Check User have perms
            [HashTable]$SplatADPerms=@{}
            if($AADRoles){
                [void] $SplatADPerms.Add('AADRoles',$AADRoles)
            }
            if(Assert-AADPermission @SplatADPerms){
                return $true
            }else{
                Disconnect-AzureAD
                Test-AADConnected @SplatTestAADConn
            }  
        }
    }
}
