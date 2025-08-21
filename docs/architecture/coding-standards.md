# Function-Based Coding Standards

## File Structure and Organization

*   **ModuleBuilder Layout**: The project follows the standard `modulebuilder` layout with `Public` and `Private` subdirectories for functions, manifest (`.psd1`), and root script file (`.psm1`).
*   **Custom Attribute Classes**: The `ProducesOutputAttribute` class will be defined in the `/Private` directory and compiled into the single PSM1.
*   **Framework Components**: Introspection, execution, and validation utilities organized in `/Private` directory.

## Function Standards

### Naming Conventions
*   All functions use approved PowerShell verbs (`New-`, `Set-`, `Get-`, `Invoke-`, `Test-`)
*   Follow `PascalCase` naming conventions
*   Workflow functions should be descriptive: `New-CompanyADUser`, `Add-ToSecurityGroups`

### Function Attributes (MANDATORY)
```powershell
function New-CompanyADUser {
    [OutputType([hashtable])]                      # Native - overall return type (REQUIRED)
    [ProducesOutput("SamAccountName", [string])]    # Custom - workflow mapping (REQUIRED for workflow functions)
    [ProducesOutput("UserPrincipalName", [string])] # Custom - additional outputs (as needed)
    [CmdletBinding(SupportsShouldProcess)]          # Native - WhatIf support (RECOMMENDED)
    param(
        # Parameters with proper attributes
    )
}
```

### Parameter Standards
```powershell
# Context parameters for framework functions
param(
    [Parameter(Mandatory, HelpMessage="Pass a hashtable with workflow inputs")]
    [Alias('Parameters', 'Inputs')]
    [System.Collections.IDictionary]$Context
)

# Individual function parameters
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FirstName,
    
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]  
    [string]$LastName
)
```

## Type System Standards

### Collection Types (CRITICAL)
*   **Internal/Private Functions**: Use `[System.Collections.Generic.List[T]]` for performance
*   **Public API Returns**: Convert Lists to arrays using `.ToArray()` for PowerShell pipeline compatibility
*   **Context Parameters**: Use `[System.Collections.IDictionary]` to support both hashtable and ordered

```powershell
# CORRECT - Internal function using List for performance
$requirements = [System.Collections.Generic.List[hashtable]]::new()
$requirements.Add($item)

# CORRECT - Convert to array for public API
return $requirements.ToArray()

# CORRECT - Context parameter accepting IDictionary
[System.Collections.IDictionary]$Context
```

### Strong Typing Requirements
*   Use strong typing wherever possible with .NET interfaces
*   `using namespace` statements at top of scripts to shorten type names
*   All workflow functions MUST include both `[OutputType]` and `[ProducesOutput]` attributes

## Framework-Specific Standards

### WhatIf Propagation (MANDATORY)
```powershell
# Explicit propagation required across module boundaries
if ($WhatIf -and $cmd.Parameters.ContainsKey('WhatIf')) {
    $params['WhatIf'] = $WhatIfPreference
}

# Function-level WhatIf support
[CmdletBinding(SupportsShouldProcess)]
param(...)

if ($PSCmdlet.ShouldProcess("Target", "Operation")) {
    # Perform operation
}
```

### Context Management Patterns
```powershell
# Always use .Count for hashtable/dictionary emptiness checks
if ($context.Count -eq 0) { 
    Write-Warning "Context is empty"
}

# Proper context key checking
if ($Context.ContainsKey($param.Name)) {
    $params[$param.Name] = $Context[$param.Name]
}

# Context output merging
if ($result -is [hashtable]) {
    foreach ($key in $result.Keys) {
        $Context[$key] = $result[$key]
    }
}
```

### Error Handling Standards
```powershell
# Fail-fast approach for workflow functions
try {
    $result = & $functionName @params
    # Success handling
} catch {
    Write-Log -Level Error -Message "Function $functionName failed: $_"
    throw "Workflow failed at function $functionName: $_"  # Fail-fast
}
```

## Performance Standards

### Loop Performance
*   Prefer `foreach` loops over piping to `ForEach-Object`
*   Use generic Lists for internal collections, convert to arrays for output
*   Avoid `+=` for building collections in loops

### Memory Management  
*   Use `[ordered]@{}` for predictable hashtable iteration
*   Dispose of large objects when no longer needed
*   Convert internal Lists to arrays for public APIs

## Code Quality Standards

### Code Smells to Avoid
*   Do not use `+=` to build collections in loops
*   Do not use aliases in scripts; use full cmdlet names
*   Do not use `Write-Host` for logging; use `Write-Information`, `Write-Warning`, or dedicated logging module
*   Do not hardcode configuration; use parameters or configuration files
*   Do not use `Invoke-Expression`
*   Do not violate `[ProducesOutput]` contracts in function implementations

### Logging Standards
*   Use `Write-Information` for informational output instead of `Write-Host`
*   Use `Write-Warning` for validation issues or missing inputs
*   Use dedicated logging module for production logging with structured levels
*   Include context in error messages: function name, operation, and specific failure

## Documentation Standards

### Comment-Based Help (MANDATORY)
All functions must include Pester-compatible, comment-based help:

```powershell
<#
.SYNOPSIS
    Creates a new company Active Directory user account.

.DESCRIPTION
    Creates a new AD user with the specified details, generating SamAccountName 
    and UserPrincipalName based on naming conventions. Returns structured output
    for workflow orchestration.

.PARAMETER FirstName
    The user's first name.

.PARAMETER LastName  
    The user's last name.

.PARAMETER ADDomain
    The Active Directory domain for the user.

.PARAMETER PrimaryDC
    The primary domain controller to use for user creation.

.OUTPUTS
    hashtable
    Returns a hashtable containing SamAccountName and UserPrincipalName.

.EXAMPLE
    New-CompanyADUser -FirstName "John" -LastName "Smith" -ADDomain "company.com" -PrimaryDC "dc1.company.com"
    
.NOTES
    This function is designed for workflow orchestration and produces outputs 
    that can be consumed by downstream functions.
#>
```

## Module Structure Standards

### Module Builder Pattern
With the module builder pattern, all components compile into a single PSM1:
1. Custom attribute classes defined at the top
2. Private utility functions in the middle  
3. Public functions at the bottom
4. No issues with attribute definition/usage in same compiled module

### Dependency Management
*   External dependencies declared in module manifest
*   Required modules: `Microsoft.Graph`, `ActiveDirectory`, `Logging`
*   Version constraints specified for all dependencies

These standards ensure consistency with the project's function-based architecture while leveraging PowerShell's native capabilities for robust workflow orchestration.
