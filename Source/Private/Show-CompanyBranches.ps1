function Show-CompanyBranches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do{
        Write-Log -Level Information -Message 'Branches'
        Write-Log -Level Information -Message '--------'
        $Branches.ChildNodes | ForEach-Object {Write-Log -Level Information -Message $_.Name} 
        $UserBranch = Read-Host -Prompt 'Enter User Branch?'
        if ($Branches.$UserBranch.name -contains $UserBranch) {
        }else {
            Write-Log -Level Warning -Message 'Could not find a match try again;'
        }  
    } until ($Branches.$UserBranch.name -contains $UserBranch)
    Write-Log -Level Information -Message '-------------- Verify Details ----------------'
    Write-Log -Level Information -Message (($Branches.$UserBranch | Format-List | Out-String).Trim())
    Write-Log -Level Information -Message '-------------- Verify Details ----------------'
    #Provide oppertunity to abort the script if the details are incorrect etc
    $response = read-host "Press enter to continue or any other key (and then enter) to abort"
    $aborted = ! [bool]$response
    if(!$aborted){
        Write-Log -Level Warning -Message 'Script Aborted Exiting'
        Exit
    }else{
        return $UserBranch
    }

}
