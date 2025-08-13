function Show-CompanyBranches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do{
        Write-Host('Branches')
        Write-Host('--------')
        $Branches.ChildNodes | ForEach-Object {$_.Name} | Write-Host 
        $UserBranch = Read-Host -Prompt 'Enter User Branch?'
        if ($Branches.$UserBranch.name -contains $UserBranch) {
        }else {
            Write-Warning('Could not find a match try again;')
        }  
    } until ($Branches.$UserBranch.name -contains $UserBranch)
    Write-Host('-------------- Verify Details ----------------')
    Write-Host(($Branches.$UserBranch | Format-List | Out-String).Trim())
    Write-host('-------------- Verify Details ----------------')
    #Provide oppertunity to abort the script if the details are incorrect etc
    $response = read-host "Press enter to continue or any other key (and then enter) to abort"
    $aborted = ! [bool]$response
    if(!$aborted){
        Write-Warning('Script Aborted Exiting')
        Exit
    }else{
        return $UserBranch
    }

}
