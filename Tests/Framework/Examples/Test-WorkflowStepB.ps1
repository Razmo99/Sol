using namespace System.Collections

function Test-WorkflowStepB {
    <#
    .SYNOPSIS
    Example workflow function that depends on Test-WorkflowStepA output.
    
    .DESCRIPTION
    Second test function that demonstrates dependency chaining in the Sol framework.
    Takes outputs from Test-WorkflowStepA and additional inputs to produce
    new structured outputs for further processing.
    
    .PARAMETER FullName
    The full name from previous workflow step.
    
    .PARAMETER ProcessedBy
    The processor name from previous workflow step.
    
    .PARAMETER Department
    The department to assign.
    
    .INPUTS
    System.String. FullName, ProcessedBy, and Department values.
    
    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable with UserProfile and ValidationStatus outputs.
    
    .EXAMPLE
    Test-WorkflowStepB -FullName "John Smith" -ProcessedBy "Test-WorkflowStepA" -Department "IT"
    
    Returns a hashtable with UserProfile and ValidationStatus values.
    
    .NOTES
    This is an example function for testing the Sol orchestration framework.
    It demonstrates dependency chaining and context consumption from previous steps.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    [ProducesOutput("UserProfile", [hashtable])]
    [ProducesOutput("ValidationStatus", [string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FullName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProcessedBy,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Department
    )
    
    begin {
        Write-Log -Level INFO -Message 'Starting Test-WorkflowStepB processing'
    }
    
    process {
        if ($PSCmdlet.ShouldProcess("$FullName in $Department", 'Create User Profile')) {
            
            try {
                Write-Log -Level Debug -Message 'Processing user profile for {0} from {1}' -Arguments @($FullName, $ProcessedBy)
                
                $userProfile = @{
                    Name = $FullName
                    Department = $Department
                    CreatedBy = $ProcessedBy
                    CreatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    Status = 'Active'
                }
                
                $validationStatus = if ($FullName -and $Department -and $ProcessedBy) {
                    'Valid'
                } else {
                    'Invalid'
                }
                
                $result = @{
                    UserProfile = $userProfile
                    ValidationStatus = $validationStatus
                }
                
                Write-Log -Level INFO -Message 'Test-WorkflowStepB completed successfully for {0} with status {1}' -Arguments @($FullName, $validationStatus)
                return $result
            }
            catch {
                Write-Log -Level Error -Message 'Test-WorkflowStepB failed' -ExceptionInfo $_
                throw "Test-WorkflowStepB failed: $($_.Exception.Message)"
            }
        }
    }
    
    end {
        Write-Log -Level Debug -Message 'Test-WorkflowStepB processing completed'
    }
}