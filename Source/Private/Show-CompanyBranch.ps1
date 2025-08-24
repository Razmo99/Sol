function Show-CompanyBranch {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do {
        Write-Log -Level Info -Message 'Branches'
        Write-Log -Level Info -Message '--------'
        $Branches.ChildNodes | ForEach-Object { Write-Log -Level Info -Message $_.Name }
        Wait-Logging
        $UserBranch = Read-Host -Prompt 'Enter User Branch?'
        if ($Branches.$UserBranch.name -contains $UserBranch) {
        }
        else {
            Write-Log -Level Warning -Message 'Could not find a match try again;'
        }
    } until ($Branches.$UserBranch.name -contains $UserBranch)
    Write-Log -Level Info -Message '-------------- Verify Details ----------------'
    Write-Log -Level Info -Message (($Branches.$UserBranch | Format-List | Out-String).Trim())
    Write-Log -Level Info -Message '-------------- Verify Details ----------------'
    #Provide oppertunity to abort the script if the details are incorrect etc
    $response = read-host "Press enter to continue or any other key (and then enter) to abort"
    $aborted = ! [bool]$response
    if (!$aborted) {
        Write-Log -Level Warning -Message 'Script Aborted Exiting'
        Exit
    }
    else {
        return $UserBranch
    }

}