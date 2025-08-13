function Set-MSolUMFA{
    <#
    .SYNOPSIS
    Sets MFA Status on a User
    .DESCRIPTION
    Checks if a connection to Msol is Present. If its not initiate one.
    Checks the UserPrincipalName Exists to Msol, if it does sets the StrongAuthenticationRequiremets
    .PARAMETER UserPrincipalName
    UserprincipalName Use to Set MFA Enforced on
    .PARAMETER StrongAuthenticationRequiremets
    StrongAuthenticationRequiremets Required level of MFA
    .OUTPUTS
    system.boolean
    .INPUTS
    system.string UserprincipalName
    system.string StrongAuthenticationRequiremets Level of MFA to set
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][string]$UserPrincipalName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][ValidateSet('Enabled','Disabled','Enforced')][String]$StrongAuthenticationRequiremets
    )
    begin{
        # Check if connected to Msol Session already
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
        if(!(Get-MsolUser -MaxResults 1 -ErrorAction Stop)){
            return Write-Error('Insufficient permissions to set MFA')
        }
    }
    Process{
        # Get the time and calc 2 min to the future
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(1)
        $Finished=$false
        #Loop to check if the user exists already
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "StrongAuthenticationRequiremets = "+$StrongAuthenticationRequiremets)) {
            do {
                $TimeNow = Get-Date
                #Primary check for success condition
                if (Get-MsolUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue) {
                    $Finished = $true
                    Write-Verbose('Found '+$UserPrincipalName+' In Msol')
                    Write-Verbose('Attempting to Set MFA Status to Enforced')
                    # Set some variables for MFA enforcement
                    $st = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
                    $st.RelyingParty = "*"
                    $st.State = $StrongAuthenticationRequiremets
                    $sta = @($st)
                    # Execute final command
                    try {
                        Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationRequirements $sta -ErrorAction Stop
                        Write-Verbose('Set MFA Command Executed')
                        return $true
                    }
                    catch {
                        Write-Error($_.Exception.Message)
                    }                
                # if 1 minutes passes we just tap out and exit the script
                }elseif($TimeNow -ge $TimeEnd){
                    $Finished = $true
                    Write-Verbose('Failed to find user in Msol')
                    Write-Warning('MFA Will not be set')
                    return $false
                }else {
                    Start-Sleep -Seconds 5
                    Write-Verbose('Sleeping 5 second')
                } 
            } until ($Finished -eq $true) 
        }      
    }
    End{}
}
