function Get-DynamicParameterValue {
    <#
    .SYNOPSIS
        Extracts dynamic parameter values from $PSBoundParameters for a specific command
    .DESCRIPTION
        Helper function that eliminates boilerplate code when extracting dynamic parameters
        from $PSBoundParameters in wrapper functions
    .PARAMETER CommandName
        Name of the command whose parameters to extract
    .PARAMETER BoundParameters
        The $PSBoundParameters hashtable from the calling function
    .PARAMETER ExcludeParameters
        Array of parameter names to exclude from extraction
    .OUTPUTS
        System.Collections.Hashtable containing extracted parameters
    .EXAMPLE
        function Get-MyChildItem {
            [CmdletBinding()]
            param ([Switch]$LogResults)

            DynamicParam {
                return Get-DynamicParameters -CommandName 'Get-ChildItem'
            }

            Process {
                # Simple one-liner parameter extraction
                $ChildItemParams = Get-DynamicParameterValues -CommandName 'Get-ChildItem' -BoundParameters $PSBoundParameters

                $Results = Get-ChildItem @ChildItemParams
                if ($LogResults) { Write-Host "Found $($Results.Count) items" }
                return $Results
            }
        }
    #>
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [String]$CommandName,

        [Parameter(Mandatory = $true)]
        [Hashtable]$BoundParameters,

        [Parameter(Mandatory = $false)]
        [String[]]$ExcludeParameters = @()
    )

    Process {
        $ExtractedParams = @{}

        # Get dynamic parameter names for the command
        $DynamicParamNames = (Get-DynamicParameters -CommandName $CommandName -ExcludeParameters $ExcludeParameters).Keys

        # Extract matching parameters from bound parameters
        foreach ($ParamName in $DynamicParamNames) {
            if ($BoundParameters.ContainsKey($ParamName)) {
                $ExtractedParams[$ParamName] = $BoundParameters[$ParamName]
            }
        }

        return $ExtractedParams
    }
}