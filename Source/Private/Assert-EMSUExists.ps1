function Assert-EMSUExists {
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
        pscredentials Used to authenticate to the designated Exchange Management Server
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
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$SamAccountName,
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][pscredential]$Credential
    )
    
    begin {
        #if Provided add credentials to the splat
        [hashtable]$SplatImportEMS =@{
            Server=$Server
        }
        if ($Credential) {$SplatImportEMS.Add("Credential",$Credential)}
        if(!$WhatIfPreference){
            if (!(Import-EMS @SplatImportEMS -whatif:$false)) {
                Write-Log -Level Error -Message 'No EMS Connection'
                return
            }
        }
    }
    process {
        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Get-RemoteMailbox')) {
        #Test if the provided person already exists on Exchange
            [bool]$GetRM = Get-RemoteMailbox $SamAccountName -ErrorAction SilentlyContinue
            if($GetRM){ Write-Log -Level Verbose -Message '{0} already has a mailbox in Exchange' -Arguments $SamAccountName
            return $true
            }else {
                Write-Log -Level Verbose -Message 'User {0} could not be found in Exchange' -Arguments $SamAccountName
                return $false
            }
        }
    }
    
    end {}
}
