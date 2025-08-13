function Test-PromptM365AndFileServerAccess {
    <#
    .SYNOPSIS
    Test Prompts for M365 and File Server Access
    
    .DESCRIPTION
    Removes prompts that require FileServerAccess or a specific M365 License
    
    .PARAMETER Prompts
    System.HashTable - Contains prompt That have requirements for M365 License or FileServerAccess
    
    .PARAMETER FileServerAccess
    System.Boolean - Has the user been assigned FileServerAccess.
    Default is False

    .PARAMETER M365License
    System.String - Type of License the user has been assigned if any.
    Default is ''
    #>    
    param (
        [Parameter(Mandatory=$true)][HashTable]$Prompts,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License=''
    )
    Write-Verbose('Processing prompts without Requirements on other prompts')
    [HashTable]$Results=@{}
    # Iterate over all DPrompts with Requirements
    foreach ($key in $Prompts.keys) {     
        # Bool to tell if the Prompt should be displayed to the user
        $CriterialMet = $true
        # If the Prompt has FileServerAccess AND FileServerAccess is assigned to the user proceed
        if(!$FileServerAccess){
            # If promp FileServerAccess is False Criteria not met
            if($Prompts.$key.Requirements.FileServerAccess -eq $true){
                Write-Verbose($key+': Criterial Failed: '+'File Server Access')
                $CriterialMet = $false
            }
        # If the Prompt has M365License AND user has M365License
        }
        if($Prompts.$key.Requirements.M365License){
            # If the License is not within the M365 Array Criteria not met
            if(($Prompts.$key.Requirements.M365License -notcontains $M365License) -and !($Prompts.$key.Requirements.M365License -contains 'Any')){
                Write-Verbose($key+': Criterial Failed: '+'Microsoft 365 License')
                $CriterialMet=$false
            }       
        } 
        if($CriterialMet){
            if(Test-UserPrompt -Message $Prompts.$Key.Message -Inverse:$Prompts.$Key.Inverse){
                # stick the groups into out results object
                [Void] $Results.Add($key,$Prompts.$Key)
            }
        }             
    }
    return $Results        
}
