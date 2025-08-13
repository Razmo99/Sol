function Test-PromptsWRequsOTHPrompts {
    <#
    .SYNOPSIS
    Test Prompts With Requirements On Other Prompts
    
    .DESCRIPTION
    Removes prompts that require FileServerAccess or a specific M365 License
    Removes Prompts that require other prompts but the prompt does not exist
    
    .PARAMETER Prompts
    System.HashTable - Contains prompt That have requirements on other prompts
    
    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    
    .PARAMETER ResultsWOReqs
    System.HashTable - Contains prompt Results that do not have requirements
    #>
    param (
        [Parameter(Mandatory=$true)][HashTable]$Prompts,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License='',
        [Parameter(Mandatory=$true)][HashTable]$ResultsWOReqs
    )
    [HashTable]$Results=@{}
    $MissingRequirements=New-Object System.Collections.Queue
    # Iterate over all DPrompts with Dependancies
    Write-Verbose('Processing prompts with requirements on other prompts')
    foreach ($key in $Prompts.keys) {
        # Bool to tell if the Prompt should be displayed to the user
        $CriterialMet = $true
        # If the Prompt has FileServerAccess AND FileServerAccess is assigned to the user proceed
        if(!$FileServerAccess){
            # If promp FileServerAccess is False Criteria not met
            if($Prompts.$key.Requirements.FileServerAccess -eq $true){
                Write-Verbose($key+': Criterial Failed | Missing File Server Access')
                $CriterialMet = $false
            }
        # If the Prompt has M365License AND user has M365License
        }
        if($Prompts.$key.Requirements.M365License){
            # If the License is not within the M365 Array Criteria not met
            if(($Prompts.$key.Requirements.M365License -notcontains $M365License) -and !($Prompts.$key.Requirements.M365License -contains 'Any')){
                Write-Verbose($key+': Criterial Failed | Missing Microsoft 365 License '+$Prompts.$key.Requirements.M365License)
                $CriterialMet=$false
            }       
        } 
        # If the prompts has requirements
        if($Prompts.$Key.Requirements.Prompts){
            # Foreach requirements
            foreach($Req in $Prompts.$Key.Requirements.Prompts){
                if($Prompts.Keys -notcontains $Req){
                    $MissingRequirements.Enqueue($Req)
                }
            }
            While($MissingRequirements -gt 0){
                $CurrentReq = $MissingRequirements.Dequeue()
                if($ResultsWOReqs.keys -contains $CurrentReq){
                    Write-Verbose($key + ': Found Requirement "' + $CurrentReq+'"')
                    $NewReqs = New-Object System.Collections.ArrayList(,$Prompts.$Key.Requirements.Prompts)
                    $NewReqs.remove($CurrentReq)
                    $Prompts.$Key.Requirements.Prompts = $NewReqs
                }else{
                    Write-Verbose($Key+': Criterial Failed | Missing Requirement: '+$CurrentReq)
                    $CriterialMet=$false
                }
            }
        }
        if($CriterialMet){
            Write-Verbose($Key+': Criteria Met')
            [void] $Results.Add($Key,$Prompts[$Key])
        }
    }
    return $Results 
}
