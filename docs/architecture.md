# Sol Module Architecture Document

## 1. Existing Architecture Analysis

### 1.1. Current Architecture Summary

The existing `Sol` module is a single, monolithic PowerShell script (`Sol.psm1`). It contains one primary public function, `New-CompanyUser`, which orchestrates user creation across multiple systems (on-premise AD, on-premise Exchange, Azure AD) through a sequential, hard-coded series of steps. Configuration is passed directly via a large number of parameters.

### 1.2. Architectural Pain Points

The current monolithic design leads to several challenges that this new architecture will address:

*   **Lack of Extensibility:** Adding new functionality (like offboarding) or modifying existing steps requires significant and risky changes to the core script.
*   **Configuration Variability:** The module is difficult to adapt to different company environments without code modifications.
*   **Legacy API Dependencies:** The module relies on older `AzureAD` and `MSOnline` modules, which are being deprecated in favor of the modern MS Graph API.

## 2. Function-Based Architecture Vision

### 2.1. Architectural Goals

The new function-based architecture is designed to achieve the following primary goals:

*   **Extensibility:** The framework must be easy to extend with new features (e.g., different lifecycle events) without modifying the core code.
*   **Maintainability:** The code will be reorganized into a standard, function-based structure that leverages PowerShell's native patterns while adding workflow orchestration capabilities.
*   **Modernization:** The module will migrate from legacy APIs to the modern MS Graph API.
*   **Reusability:** The module will be generalized so it can be configured for and reused by different companies with varying infrastructure requirements.
*   **Static Validation:** The framework provides comprehensive static analysis to validate workflow dependencies before execution.

### 2.2. Core Concept

Instead of custom task classes, the architecture uses **standard PowerShell functions with native attributes** for metadata. The framework provides orchestration utilities around standard functions, maintaining PowerShell's natural patterns while adding workflow capabilities.

### 2.3. Technical Validation Summary

After comprehensive technical analysis and testing, this approach has been validated as **fully feasible** with the following key findings:

#### ✅ Validated Assumptions
- **Module Builder Pattern**: Custom attributes work perfectly when compiled into single PSM1
- **Parameter Introspection**: Rock-solid PowerShell core feature  
- **Static Validation**: Fully achievable with reflection APIs
- **Context Mutation**: Reference semantics work as designed and desired

#### ⚠️ Design Decisions Based on Findings
- **Use `[System.Collections.IDictionary]`** for context parameters (supports both hashtable and ordered)
- **Explicit WhatIf Propagation**: Manual propagation required across module boundaries
- **Count-based Emptiness Checks**: Always use `.Count` property due to hashtable boolean context

### 2.4. High-Level Strategy

To achieve these goals, we will execute a full refactor of the module. The project will first be restructured to follow the standard **`modulebuilder`** layout. Within this new structure, the monolithic script will be replaced by an extensible framework built on function-based workflow orchestration:

1.  **Standard PowerShell Functions:** Specific operations (like creating a user, disabling a user) will be implemented as standard PowerShell functions with minimal custom attributes for workflow metadata.
2.  **Workflow Orchestration:** A central orchestration engine will execute ordered sequences of functions, automatically mapping outputs to inputs and providing comprehensive static validation.
3.  **Framework Components:** Introspection engine, execution engine, and validation utilities that work with native PowerShell function patterns.

This approach leverages PowerShell's native function patterns while adding structured workflow capabilities, allowing for flexible composition of new workflows in the future. All cloud interactions will be modernized to use the `Microsoft.Graph` PowerShell module.

## 3. Detailed Design

### 3.1. Custom Attribute Definition

The framework uses a single custom attribute for workflow dependency mapping:

```powershell
# Custom attribute for workflow dependency mapping
class ProducesOutputAttribute : System.Attribute {
    [string]$OutputName
    [type]$OutputType
    
    ProducesOutputAttribute([string]$name, [type]$type) {
        $this.OutputName = $name
        $this.OutputType = $type
    }
}
```

### 3.2. Function Metadata Pattern

Standard PowerShell functions enhanced with minimal custom attributes:

```powershell
function New-CompanyADUser {
    [OutputType([hashtable])]                      # Native PowerShell - overall return type
    [ProducesOutput("SamAccountName", [string])]    # Custom - specific output for workflow mapping
    [ProducesOutput("UserPrincipalName", [string])] # Custom - specific output for workflow mapping
    param(
        [Parameter(Mandatory)]
        [string]$FirstName,           # Native - type and mandatory status
        
        [Parameter(Mandatory)]
        [string]$LastName,            # Native - type and mandatory status
        
        [Parameter(Mandatory)]
        [string]$ADDomain,            # Infrastructure input
        
        [Parameter(Mandatory)]
        [string]$PrimaryDC           # Infrastructure input
    )
    
    $samAccount = "$($FirstName.Substring(0,1))$LastName".ToLower()
    New-ADUser -Name "$FirstName $LastName" `
               -SamAccountName $samAccount `
               -Server $PrimaryDC
    
    # Return structured output matching ProducesOutput declarations
    return @{ 
        SamAccountName = $samAccount
        UserPrincipalName = "$samAccount@$ADDomain"
    }
}
```

### 3.3. Workflow Definition Pattern

Workflows are simple, ordered arrays of function names with context as structured hashtables:

```powershell
# Workflow is just an ordered list of function names
$standardUserWorkflow = @(
    'Connect-ToGraph',
    'New-CompanyADUser',
    'New-CompanyMailbox', 
    'Add-ToSecurityGroups'
)

# Context is a simple hashtable
$workflowContext = @{
    # User inputs
    FirstName = "John"
    LastName = "Smith"
    Department = "Finance"
    
    # Infrastructure inputs
    ADDomain = "company.com"
    PrimaryDC = "dc1.company.com"
    M365TenantId = "12345-67890"
    
    # Generated names (from prompt stage)
    SamAccountName = "jsmith"
    UserPrincipalName = "jsmith@company.com"
    DisplayName = "John Smith (Finance)"
}
```

### 3.4. Framework Components

The framework provides orchestration utilities around standard functions:

#### Function Introspection Engine

```powershell
function Get-FunctionRequirements {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string[]]$FunctionNames
    )
    
    $requirements = [ordered]@{}  # Use ordered for predictable iteration
    
    foreach ($functionName in $FunctionNames) {
        $cmd = Get-Command $functionName -ErrorAction SilentlyContinue
        if (!$cmd) {
            Write-Warning "Function not found: $functionName"
            continue
        }
        
        # Extract parameter metadata
        foreach ($param in $cmd.Parameters.Values) {
            # Skip common parameters (Verbose, Debug, etc.)
            if ($param.Name -in [System.Management.Automation.PSCmdlet]::CommonParameters) {
                continue
            }
            
            if (!$requirements.ContainsKey($param.Name)) {
                # Use List for internal collections per coding standards
                $requirements[$param.Name] = @{
                    Type = $param.ParameterType
                    IsRequired = ($param.Attributes | Where-Object { $_.Mandatory }).Count -gt 0
                    UsedBy = [System.Collections.Generic.List[string]]::new()
                }
                $requirements[$param.Name].UsedBy.Add($functionName)
            } else {
                $requirements[$param.Name].UsedBy.Add($functionName)
            }
        }
    }
    
    return $requirements
}
```

#### Workflow Execution Engine

```powershell
function Invoke-WorkflowPipeline {
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Functions,
        
        [Parameter(Mandatory, HelpMessage="Pass a hashtable with workflow inputs, e.g. @{FirstName='John'}")]
        [Alias('Parameters', 'Inputs')]
        [System.Collections.IDictionary]$Context,
        
        [switch]$WhatIf
    )
    
    # Use List for internal collections per coding standards
    $results = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($functionName in $Functions) {
        Write-Log -Level Info -Message "Executing function: $functionName"
        
        try {
            # Get function metadata
            $cmd = Get-Command $functionName
            $params = @{}
            
            # Map context values to function parameters
            foreach ($param in $cmd.Parameters.Values) {
                if ($Context.ContainsKey($param.Name)) {
                    $params[$param.Name] = $Context[$param.Name]
                }
            }
            
            # Explicit WhatIf propagation (required across module boundaries)
            if ($WhatIf -and $cmd.Parameters.ContainsKey('WhatIf')) {
                $params['WhatIf'] = $WhatIfPreference
            }
            
            # Execute function
            $result = & $functionName @params
            $results.Add(@{
                FunctionName = $functionName
                Success = $true
                Result = $result
                Message = "Function executed successfully"
            })
            
            # Merge function output back into context for downstream functions
            if ($result -is [hashtable]) {
                foreach ($key in $result.Keys) {
                    $Context[$key] = $result[$key]
                }
            }
            
            Write-Log -Level Info -Message "Function $functionName completed successfully"
            
        } catch {
            $errorResult = @{
                FunctionName = $functionName
                Success = $false
                Error = $_
                Message = "Function execution failed: $_"
            }
            $results.Add($errorResult)
            
            Write-Log -Level Error -Message "Function $functionName failed: $_"
            
            # Fail fast - stop workflow execution
            throw "Workflow failed at function $functionName: $_"
        }
    }
    
    # Convert to array for public API per coding standards
    return $results.ToArray()
}
```

#### Static Validation System

```powershell
function Test-WorkflowReadiness {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Functions,
        
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Context
    )
    
    $requirements = Get-FunctionRequirements -FunctionNames $Functions
    # Use Lists for internal collections per coding standards
    $missing = [System.Collections.Generic.List[hashtable]]::new()
    $available = [System.Collections.Generic.List[string]]::new()
    
    foreach ($req in $requirements.GetEnumerator()) {
        if ($req.Value.IsRequired) {
            if ($Context.ContainsKey($req.Key)) {
                $available.Add($req.Key)
            } else {
                $missing.Add(@{
                    Parameter = $req.Key
                    Type = $req.Value.Type
                    UsedBy = $req.Value.UsedBy.ToArray()  # Convert List to array for output
                })
            }
        }
    }
    
    return @{
        IsReady = ($missing.Count -eq 0)  # Use .Count for emptiness check
        MissingInputs = $missing.ToArray()  # Convert to array for public API
        AvailableInputs = $available.ToArray()  # Convert to array for public API
        TotalRequired = $requirements.Values | Where-Object { $_.IsRequired } | Measure-Object | Select-Object -ExpandProperty Count
    }
}
```

#### Context Management
- Automatically merges function outputs back into shared context
- Maintains structured output contracts via `[ProducesOutput]` declarations
- Uses reference semantics for efficient context mutation
- Supports both manual and automatic context population

### 3.5. Real-World Function Examples

#### Connection Management

```powershell
function Connect-ToGraph {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$M365TenantId,
        
        [Parameter(Mandatory)]
        [string]$M365ClientId,
        
        [Parameter(Mandatory)]
        [securestring]$M365ClientSecret,
        
        [switch]$WhatIf
    )
    
    if ($WhatIf) {
        Write-Information "Would connect to Graph with Tenant ID: $M365TenantId"
        return $true
    }
    
    Connect-MgGraph -TenantId $M365TenantId -ClientId $M365ClientId -ClientSecret $M365ClientSecret
    return $true
}
```

#### Complex Business Logic Functions

```powershell
function New-MailboxPermissionGroups {
    [OutputType([hashtable])]
    [ProducesOutput("MailboxPermissionGroupsCreated", [bool])]
    param(
        [Parameter(Mandatory)]
        [string]$SendAsGroupName,
        
        [Parameter(Mandatory)]
        [string]$SendOnBehalfGroupName,
        
        [Parameter(Mandatory)]
        [string]$FullAccessGroupName,
        
        [switch]$WhatIf
    )
    
    if ($WhatIf) {
        Write-Information "Would create mailbox permission groups:"
        Write-Information "  - $SendAsGroupName"
        Write-Information "  - $SendOnBehalfGroupName" 
        Write-Information "  - $FullAccessGroupName"
        return @{
            MailboxPermissionGroupsCreated = $true  # Matches ProducesOutput declaration
        }
    }
    
    New-ADGroup -Name $SendAsGroupName -GroupScope Global
    New-ADGroup -Name $SendOnBehalfGroupName -GroupScope Global
    New-ADGroup -Name $FullAccessGroupName -GroupScope Global
    
    return @{
        MailboxPermissionGroupsCreated = $true  # Matches ProducesOutput declaration
    }
}
```

### 3.6. Usage Patterns

#### Simple Workflow Execution

```powershell
# Define workflow
$workflow = @('Connect-ToGraph', 'New-CompanyADUser', 'New-CompanyMailbox')

# Populate context (from prompts + name generation)
$context = @{
    FirstName = "John"
    LastName = "Smith"
    ADDomain = "company.com"
    M365TenantId = "12345"
    # ... other inputs
}

# Check readiness
$readiness = Test-WorkflowReadiness -Functions $workflow -Context $context
if ($readiness.MissingInputs.Count -gt 0) {  # Use .Count for emptiness check
    Write-Warning "Missing inputs: $($readiness.MissingInputs.Parameter -join ', ')"
    return
}

# Execute workflow
$results = Invoke-WorkflowPipeline -Functions $workflow -Context $context
```

#### Interactive Mode with Input Discovery

```powershell
# Discover what inputs are needed
$requirements = Get-FunctionRequirements -FunctionNames $workflow
Write-Information "This workflow requires the following inputs:"

foreach ($req in $requirements.GetEnumerator()) {
    if ($req.Value.IsRequired) {
        # Convert List to array for display
        $usedBy = if ($req.Value.UsedBy -is [System.Collections.Generic.List[string]]) {
            $req.Value.UsedBy.ToArray()
        } else {
            $req.Value.UsedBy
        }
        Write-Information "  $($req.Key) ($($req.Value.Type.Name)) - Used by: $($usedBy -join ', ')"
    }
}

# Collect inputs interactively or from configuration files
# Apply company-specific naming logic
# Execute with full visibility
```

### 3.7. Implementation Guidelines

Based on technical validation and project coding standards, the following guidelines MUST be followed:

#### Collection Types
- **Internal/Private Functions**: Use `[System.Collections.Generic.List[T]]` for performance
- **Public API Returns**: Convert Lists to arrays using `.ToArray()` for PowerShell pipeline compatibility
- **Context Parameters**: Use `[System.Collections.IDictionary]` to support both hashtable and ordered

#### Parameter Patterns
```powershell
# Public function signature
param(
    [Parameter(Mandatory, HelpMessage="Pass a hashtable with workflow inputs")]
    [Alias('Parameters', 'Inputs')]
    [System.Collections.IDictionary]$Context
)
```

#### WhatIf Propagation
```powershell
# Explicit propagation required across module boundaries
if ($WhatIf -and $cmd.Parameters.ContainsKey('WhatIf')) {
    $params['WhatIf'] = $WhatIfPreference
}
```

#### Emptiness Checks
```powershell
# Always use .Count for hashtable/dictionary emptiness
if ($context.Count -eq 0) { 
    Write-Warning "Context is empty"
}
```

### 3.8. Target Technology Stack

*   **Languages**: PowerShell 5.1+
*   **Frameworks**: None
*   **Database**: None
*   **Infrastructure**: None
*   **External Dependencies**: The 'Logging' module, Microsoft Graph PowerShell Module, ActiveDirectory PowerShell Module

### 3.3. Code Organization and Standards

*   **File Structure Approach**: The project will strictly follow the default layout generated by `modulebuilder`. This includes a root module folder containing `Public` and `Private` subdirectories for functions, a manifest (`.psd1`), and a root script file (`.psm1`). Custom attributes and framework utilities will be organized into the `/Private` directory.
*   **Naming Conventions**: All functions will use approved PowerShell verbs (e.g., `New-`, `Set-`, `Get-`) and will follow `PascalCase` naming conventions.
*   **Coding Standards**:
    *   The code will use strong typing wherever possible, with `[System.Collections.IDictionary]` for context parameters.
    *   `using namespace` statements will be used at the top of scripts to shorten type names.
    *   All workflow functions must include both `[OutputType]` and `[ProducesOutput]` attributes to define their output contracts.
    *   For performance, `foreach` loops should be preferred over piping to `ForEach-Object`.
    *   **Collection Types**: For performance, internal functions should use generic lists (`System.Collections.Generic.List[T]`). To ensure ease of use for the end-user, public-facing functions should accept and return standard PowerShell arrays (`[Array]`).
*   **Code Smells to Avoid**:
    *   Do not use `+=` to build collections in loops.
    *   Do not use aliases in scripts; use the full cmdlet name.
    *   Do not use `Write-Host` for logging; use the dedicated logging module.
    *   Do not hardcode configuration; these should be parameters.
    *   Do not use `Invoke-Expression`.
*   **Documentation Standards**: All functions and classes will include Pester-compatible, comment-based help.

## 4. Integration and Deployment

### 4.1. API Integration

Direct API integration is not in scope for this project. All interactions with Microsoft Graph will be performed via the official `Microsoft.Graph` PowerShell module, not by making raw REST API calls.

### 4.2. Deployment Pipeline

*   **Build Process Integration**: The module will be built using a GitHub Actions workflow. The workflow will use `GitVersion` to automatically calculate the module version based on git tags and branches.
*   **Deployment Strategy**: For now, the GitHub Actions workflow will create a GitHub Release and attach the packaged module as a release asset.
*   **Configuration Management**: The module will use a dedicated configuration class (`[SolConfig]`). At runtime, a single `[SolConfig]` object will be created from a config file and/or explicit parameters. This object will then be placed into the `[TaskContext]`'s `$Configuration` property. The single, overarching `TaskContext` is then passed to every task, giving each task access to the central, session-wide configuration when needed.

## 5. Risk Analysis

### 5.1. Architectural Risks and Mitigation

*   **Technical Risks**:
    *   The migration to the MS Graph PowerShell Module is a **high-risk effort**. The new module's behavior cannot be tested against a live development tenant, so we must rely solely on Microsoft's documentation. Unexpected authentication or permission issues may only be discovered during initial production use.
    *   A large-scale refactoring of the entire module to implement new patterns could introduce subtle bugs or performance regressions.

*   **Integration Risks**:
    *   The new, extensible framework must be robust enough to handle all the variations required for different lifecycle events and company-specific configurations.

*   **Mitigation Strategies**:
    *   **(Strategic)** The project will be split into two major epics (1. Foundational Refactoring & Migration, 2. New Lifecycle Features) to mitigate the risk of a single "big bang" release.
    *   **(Technical)** The MS Graph integration will strictly follow Microsoft's official migration guides and will include extensive, detailed logging and error handling around every Graph call to ensure any real-world issues can be rapidly diagnosed.
    *   **(QA)** The Definition of Done for the core framework stories will require implementing at least two concrete workflow functions to prove the extensibility pattern works as designed.
    *   **(Testing)** The testing strategy of mocking the final cmdlets will ensure that tests are stable, repeatable, and focused on our custom logic, mitigating risks from environmental failures.

## 6. Future Considerations

### 6.1. Scalability

The new function-based, extensible architecture is designed for scalability. New features or support for new target systems (e.g., other HR or IT systems) can be added by creating new, independent functions with proper `[ProducesOutput]` attributes. These can then be composed into new or existing workflows without requiring changes to the core framework.

### 6.2. Future Work

The immediate future work following the completion of this foundational epic (Epic 1) is the implementation of **Epic 2: User Lifecycle Feature Implementation**. This will involve creating new workflow functions for features like user offboarding and modification and defining them as new, pre-packaged workflow sequences with proper orchestration.

## 7. Change Log

| Change | Date | Version | Description | Author |
| :--- | :--- | :--- | :--- | :--- |
| Created | 2025-08-12 | 1.0 | Initial architecture draft | Winston (Architect) |

## 8. Sign-off

This document represents the complete Architecture Document for the foundational refactoring of the Sol module.

**Approved by**: signed off, create the document
**Date**: 2025-08-12

---
*This document was generated by the BMad Architect agent.*
---