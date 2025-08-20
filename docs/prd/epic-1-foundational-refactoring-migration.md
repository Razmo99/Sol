# 5. Epic 1: Foundational Refactoring & Migration

**Epic Goal**: To refactor the existing `Sol` module into a modern, extensible, and maintainable framework using standard patterns and migrating to the MS Graph API. This epic delivers a stable technical foundation for future feature development.

**Integration Requirements**: The final product of this epic will be a fully refactored module. All existing logic from `New-CompanyUser` will be migrated into the new pattern. The module will connect to and use the MS Graph PowerShell module for all cloud operations.

## 5.1. Proposed Story Sequence (Final)

*   **Story 1: Initialize and Reorganize Module Structure.**
    *   *(Create the `modulebuilder` layout and split existing functions into the new Public/Private folder structure.)*

*   **Story 2: Integrate Centralized Logging.**
    *   *(Integrate the existing 'Logging' module and remove all instances of `Write-Host`, `Write-Verbose`, etc.)*

*   **Story 3: Implement Core Factory and Builder Classes.**
    *   *(Create the base `IBuilder` interface/class and the central `BuilderFactory` class.)*

*   **Story 4: Migrate `New-CompanyUser` to MS Graph.**
    *   **As a Developer,** I want to go through the existing `New-CompanyUser` function and replace all `AzureAD` and `MSOnline` cmdlets with their `Microsoft.Graph` equivalents, **so that** the module is fully migrated to the modern API before any structural refactoring takes place.
    *   *(This story focuses only on the API call migration within the existing function structure.)*

*   **Story 5: Refactor Migrated Function into a Builder.**
    *   **As a Developer,** I want to take the newly migrated `New-CompanyUser` function (which now uses MS Graph) and refactor its logic into a new `NewUser-Builder` class, **so that** the feature is fully integrated into the new, extensible framework.
