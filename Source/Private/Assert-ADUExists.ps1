function Assert-ADUExists {
    <#
    .SYNOPSIS
    Asserts if a user exists in Active Directory
    .DESCRIPTION
    Asserts if a user exists in Active Directory, 
    returns true if they do, and false if they do not.
    .PARAMETER SamAccountName
        system.string Attribute of the Active Directory account to match
        E.G 'firstname.lastname'
    .PARAMETER Server
        system.string Domain Controller to execute the search on
    .PARAMETER Credential
        pscredentials Used to authenticate to the designated Domain Controller
    .INPUTS
        system.string for SamAccountName
        System.pscredential for Credential
        system.string for server
    .OUTPUTS
        system.boolean
        returns one or more booleans
    #>
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$SamAccountName,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    begin {}
    process {
        $SplatADGetUser =@{
            ErrorAction = 'SilentlyContinue'
            Server = $Server
            Filter = { SamAccountName -eq $SamAccountName }
        }
        #WhatIf 
        if ($PSCmdlet.ShouldProcess($Server, 'Get-ADUser Filter { SamAccountName '+$SamAccountName+' }')) {
            #if Provided add credentials to the splat
            if ($Credential) {$SplatADGetUser.Add("Credential",$Credential)}
            #Test if the provided person already exists on ActiveDirectory
            if ([bool] (Get-ADUser @SplatADGetUser)) {
                Write-Verbose ('Found '+$SamAccountName+' in AD')
                return $true
            }else {
                Write-Verbose (' could not find '+$SamAccountName+' in AD')
                return $false
            }  
        }
    }
    end {}
}
