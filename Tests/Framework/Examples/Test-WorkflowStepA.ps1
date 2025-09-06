using namespace System.Collections

function Test-WorkflowStepA {
    <#
    .SYNOPSIS
    Example workflow function for testing framework orchestration.
    
    .DESCRIPTION
    Simple test function that demonstrates the Sol framework's ProducesOutput
    attribute and context management capabilities. Takes basic inputs and
    produces structured outputs for downstream functions.
    
    .PARAMETER FirstName
    The first name to process.
    
    .PARAMETER LastName  
    The last name to process.
    
    .INPUTS
    System.String. First and last names.
    
    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable with FullName and ProcessedBy outputs.
    
    .EXAMPLE
    Test-WorkflowStepA -FirstName "John" -LastName "Smith"
    
    Returns a hashtable with FullName and ProcessedBy values.
    
    .NOTES
    This is an example function for testing the Sol orchestration framework.
    It demonstrates proper ProducesOutput attribute usage and return structure.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    [ProducesOutput("FullName", [string])]
    [ProducesOutput("ProcessedBy", [string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FirstName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LastName
    )
    
    begin {
        Write-Log -Level INFO -Message 'Starting Test-WorkflowStepA processing'
    }
    
    process {
        if ($PSCmdlet.ShouldProcess("$FirstName $LastName", 'Process Name')) {
            
            try {
                $fullName = "$FirstName $LastName"
                $processedBy = "Test-WorkflowStepA"
                
                Write-Log -Level Debug -Message 'Processing name: {0}' -Arguments $fullName
                
                $result = @{
                    FullName = $fullName
                    ProcessedBy = $processedBy
                }
                
                Write-Log -Level INFO -Message 'Test-WorkflowStepA completed successfully for {0}' -Arguments $fullName
                return $result
            }
            catch {
                Write-Log -Level Error -Message 'Test-WorkflowStepA failed' -ExceptionInfo $_
                throw "Test-WorkflowStepA failed: $($_.Exception.Message)"
            }
        }
    }
    
    end {
        Write-Log -Level Debug -Message 'Test-WorkflowStepA processing completed'
    }
}