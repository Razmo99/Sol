function Show-CompanyBranch {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][System.Xml.XmlLinkedNode]$Branches
    )
    Do {
        $branchList = $Branches.ChildNodes | ForEach-Object { $_.Name }
        Write-Log -Level Info -Message @"
`nBranches
--------
$($branchList -join "`n")
"@
        Wait-Logging
        $UserBranch = Read-Host -Prompt 'Enter User Branch?'
        if ($Branches.$UserBranch.name -contains $UserBranch) {
        }
        else {
            Write-Log -Level Warning -Message 'Could not find a match try again;'
        }
    } until ($Branches.$UserBranch.name -contains $UserBranch)
    Write-Log -Level Info -Message @"
`n-------------- Verify Details ----------------
$(($Branches.$UserBranch | Format-List | Out-String).Trim())
-------------- Verify Details ----------------
"@
    #Provide oppertunity to abort the script if the details are incorrect etc
    if(!(Test-UserContinue)){
        Write-Log -Level Warning -Message 'Script Aborted Exiting'
        Exit
    }
    
    return $UserBranch
}