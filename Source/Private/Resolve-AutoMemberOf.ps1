function Resolve-AutoMemberOf{
    <#
    .SYNOPSIS
    Resolves the requirements of non-prompting MemberOf entries
    
    .DESCRIPTION
    Iterates over the AutoMemberOf Parameter. If any requirements are present it checks them against the other inputed parameters. 
    If the AutoMemberOf Item requires another prompt a key lookup is performed on the "InteractivePromptAnswers" parameter.
    
    .EXAMPLE
    Resolve-AutoMemberOf -FileServerAccess:$False -M365License 'E1' -AutoMemberOf @{'Email'=@{MemberOf=@('Email');Requirements=@{Prompts=@('EmailAccess');FileServerAccess=$True}}} -InteractivePromptAnswers @{'EmailAccess'=@{MemberOf=@('testGroup')}}
    .PARAMETER InteractivePromptAnswer
        System.HashTable - Contains all the Answers to the Interactive Prompts preseneted to the user.
        Used to resolve requirements "AutoMemberOf" may have.
    .PARAMETER AutoMemberOf
        System.HashTable - Contains all No Prompting Groups to add the user to with conditions.
    .PARAMETER FileServerAccess
        System.Boolean - Has the user been assigned FileServerAccess.
        Default is False
    .PARAMETER M365License
        System.String - Type of License the user has been assigned if any.
        Default is ''
    .OUTPUTS
        System.HashTable - Contains Entires from AutoMemberOf that have met requirements
    #>
    [CmdletBinding()]param(
        [parameter(Mandatory=$true)][HashTable]$InteractivePromptAnswers,
        [Parameter(Mandatory=$true)][HashTable]$AutoMemberOf,
        [Parameter(Mandatory=$false)][boolean]$FileServerAccess=$false,
        [Parameter(Mandatory=$false)][String]$M365License=''
    )
    [HashTable]$Results=@{}
    Write-Verbose('Processing AutoMemberOf entries')
    # Iterate over all AutoMember Items
    foreach ($key in $AutoMemberOf.keys) {
        # If this item doesn have requirements add it to the results
        if(!$AutoMemberOf.$key.Requirements){
            Write-Verbose($key+': Criteria Met')
            [void] $Results.Add($key,$AutoMemberOf[$Key])
        }elseif($AutoMemberOf.$key.Requirements){
            $CriterialMet=$true
            if(!$FileServerAccess){
                # If item FileServerAccess is False Criteria not met
                if($AutoMemberOf.$key.Requirements.FileServerAccess -eq $true){
                    Write-Verbose($key+': Criterial Failed | File Server Access')
                    $CriterialMet = $false
                }
            # If the item has M365License AND user has M365License
            }
            if($AutoMemberOf.$key.Requirements.M365License){
                # If the License is not within the M365 Array Criteria not met
                if(($AutoMemberOf.$key.Requirements.M365License -notcontains $M365License) -and !($AutoMemberOf.$key.Requirements.M365License -contains 'Any')){
                    Write-Verbose($key+': Criterial Failed | Microsoft 365 License')
                    $CriterialMet=$false
                }       
            }
            # Does this item depend on other prompts          
            if($AutoMemberOf.$key.Requirements.prompts){
                # Iterate over each prompt it depends on
                foreach ($req in $AutoMemberOf.$key.Requirements.prompts) {
                    # If the Interactive Prompts does not contain this item Criteria not met
                    if($InteractivePromptAnswers.keys -notcontains $req){
                        Write-Verbose($key+': Criterial Failed | Missing req: '+$req)
                        $CriterialMet=$false                        
                    }
                }                    
            }
            # Add the item to the results to be returned
            if($CriterialMet){
                Write-Verbose($key+': Criteria Met')
                [void] $Results.Add($key,$AutoMemberOf[$Key])
            }
        }
    }
    return $Results 
}
