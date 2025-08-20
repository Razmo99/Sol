# Sol Brownfield Enhancement PRD

## 1. Intro Project Analysis and Context

### 1.1. Existing Project Overview

#### 1.1.1. Analysis Source

The analysis of the existing project is based on the output from the `document-project` task, which was completed by the Architect and saved in `service-analysis.md`.

#### 1.1.2. Current Project State

The `Sol` module is a PowerShell-based tool designed to automate the creation of new users in a hybrid Microsoft 365 environment. It orchestrates actions across on-premise Active Directory, on-premise Exchange, and cloud-based Azure AD to provision users, assign licenses, and configure settings.

### 1.2. Available Documentation Analysis

Document-project analysis is available, so we will proceed using the existing technical documentation derived from that.

#### 1.2.1. Available Documentation

*   [x] Tech Stack Documentation
*   [x] Source Tree/Architecture
*   [ ] Coding Standards
*   [x] API Documentation
*   [x] External API Documentation
*   [ ] UX/UI Guidelines
*   [ ] Technical Debt Documentation
*   [ ] Other:

### 1.3. Enhancement Scope Definition

#### 1.3.1. Enhancement Type

*   [ ] New Feature Addition
*   [x] Major Feature Modification
*   [ ] Integration with New Systems
*   [ ] Performance/Scalability Improvements
*   [x] Technology Stack Upgrade
*   [ ] Bug Fix and Stability Improvements
*   [ ] Other:

#### 1.3.2. Enhancement Description

The project will be refactored to use the 'modulebuilder' library pattern and will implement the factory pattern to make the code more generic and extensible. A new, dedicated logging module will be implemented. The module's scope will be expanded from focusing only on new user creation to managing the user lifecycle in general.

#### 1.3.3. Impact Assessment

*   [ ] Minimal Impact (isolated additions)
*   [ ] Moderate Impact (some existing code changes)
*   [ ] Significant Impact (substantial existing code changes)
*   [x] Major Impact (architectural changes required)

### 1.4. Goals and Background Context

#### 1.4.1. Goals

*   Improve code extensibility for future features.
*   Expand module capabilities to cover the entire user lifecycle.
*   Introduce a robust, centralized logging mechanism.
*   Generalize the module to be applicable to any company, enabling community use.
*   Migrate from the legacy AzureAD PowerShell module to the modern MS Graph API.

#### 1.4.2. Background Context

The current module is difficult to adapt to different company configurations. This enhancement aims to solve that by creating a solid, extensible framework. This will allow for easy adaptation and extension, such as building a new "builder" for an offboarding process to remove a user from a specific system, without requiring a rewrite of the core logic.

### 1.5. Change Log

| Change | Date | Version | Description | Author |
| :--- | :--- | :--- | :--- | :--- |
| Created | 2025-08-12 | 1.0 | Initial PRD draft | John (PM) |

## 2. Requirements

### 2.1. Functional

*   **FR1:** The module will be refactored to use the 'modulebuilder' library pattern to standardize its structure.
*   **FR2:** A factory pattern will be implemented to allow for the creation of various "builders" (e.g., for user creation, deletion, modification), making the system extensible.
*   **FR3:** The module's scope will be expanded to cover the full user lifecycle, including onboarding, offboarding, and updates, not just initial user creation.
*   **FR4:** The module will be migrated to use the existing 'Logging' module for all output and error handling.
*   **FR5:** All interactions with Azure AD will be migrated from the legacy `AzureAD` PowerShell module to the modern `MS Graph` API.
*   **FR6:** The module must be architected with generic configuration options to allow for its use by different companies with minimal code changes.

### 2.2. Non-Functional

*   **NFR1:** The framework must be highly extensible, allowing new "builders" (e.g., for specific systems) or lifecycle event hooks to be added without modifying the core module code.
*   **NFR2:** The module should be suitable for publishing to a public repository, like the PowerShell Gallery, for community consumption.
*   **NFR3:** All sensitive data, such as passwords or API keys, must be handled securely as `SecureString` objects or retrieved from a secure secret management system.
*   **NFR4:** The integration with the 'Logging' module must utilize its existing configuration options for log levels and output targets.
*   **NFR5:** The refactored code should use strong typing wherever possible, and PowerShell `using namespace` statements should be leveraged to shorten type names.
*   **NFR6:** Testing will focus on the framework's logic, the factory pattern, and ensuring that commands are constructed correctly. The successful execution of the final, platform-specific cmdlets (e.g., `New-ADUser`) is considered out of scope for this module's automated tests.

### 2.3. Compatibility Requirements

*   **CR1:** The module must retain its ability to function in a hybrid environment, interacting with both on-premise Active Directory and on-premise Exchange servers.

## 3. Technical Constraints and Integration Requirements

### 3.1. Existing Technology Stack

*   **Languages**: PowerShell 5.1+
*   **Frameworks**: None
*   **Database**: None
*   **Infrastructure**: None
*   **External Dependencies**: The 'Logging' module, Microsoft Graph, ActiveDirectory PowerShell Module

### 3.2. Integration Approach

*   **Database Integration Strategy**: N/A
*   **API Integration Strategy**: N/A (All interactions will be via PowerShell modules).
*   **Frontend Integration Strategy**: N/A
*   **Testing Integration Strategy**: Pester will be used to test the framework logic. Tests will mock the final cmdlet calls (e.g., `New-ADUser`, `Connect-MgGraph`) to verify that the factory and builders are constructing the correct commands and parameters, without executing the calls themselves.

### 3.3. Code Organization and Standards

*   **File Structure Approach**: The project will strictly follow the default layout generated by `modulebuilder`. This includes a root module folder containing `Public` and `Private` subdirectories for functions, a manifest (`.psd1`), and a root script file (`.psm1`). Any classes will be organized into a `/Classes` directory as appropriate.
*   **Naming Conventions**: All functions will use approved PowerShell verbs (e.g., `New-`, `Set-`, `Get-`) and will follow `PascalCase` naming conventions.
*   **Coding Standards**:
    *   The code will use strong typing wherever possible, being mindful of available .NET interfaces.
    *   `using namespace` statements will be used at the top of scripts to shorten type names.
    *   All functions must include the `[OutputType]` attribute to define their output object type.
    *   For performance, `foreach` loops should be preferred over piping to `ForEach-Object`.
    *   **Collection Types**: For performance, internal functions should use generic lists (`System.Collections.Generic.List[T]`). To ensure ease of use for the end-user, public-facing functions should accept and return standard PowerShell arrays (`[Array]`).
*   **Code Smells to Avoid**:
    *   Do not use `+=` to build collections in loops.
    *   Do not use aliases in scripts (e.g., `gci`, `?`, `%`); use the full cmdlet name.
    *   Do not use `Write-Host` for logging or success messages; use the dedicated logging module.
    *   Do not hardcode configuration; these should be parameters.
    *   Do not use `Invoke-Expression`.
*   **Documentation Standards**: All functions and classes will include Pester-compatible, comment-based help.

### 3.4. Deployment and Operations

*   **Build Process Integration**: The module will be built using a GitHub Actions workflow. The workflow will use `GitVersion` to automatically calculate the module version based on git tags and branches.
*   **Deployment Strategy**: For now, the GitHub Actions workflow will create a GitHub Release and attach the packaged module as a release asset. Future work could publish it to the PowerShell Gallery.
*   **Monitoring and Logging**: The module will not integrate with a specific, external monitoring system. Instead, it will provide a default initialization function for the 'Logging' module that is easy for end-users to configure. This function will set up colored logging to the console and a rotating file handler by default.
*   **Configuration Management (Recommended Approach)**:
    *   **Strategy**: We will use a dedicated configuration object (e.g., a PowerShell Class `[SolConfig]`) to manage all settings.
    *   **Process**:
        1.  The main function will accept parameters for key settings (e.g., `-ConfigFilePath`, `-ServerName`, `-TenantId`).
        2.  At runtime, a single `[SolConfig]` object will be created and populated from a configuration file (if provided) and then overridden by any explicit parameters.
        3.  This single, unified configuration object will be passed to the "Director" class that manages the builders. Each builder will then pull the specific settings it needs (e.g., the `New-User-Builder` would pull AD domain info) from that shared configuration object.
    *   **Benefits**: This approach decouples the builders from the configuration source. It makes testing easier (we can pass a mock config object) and provides a flexible and centralized way to manage settings for different environments.

### 3.5. Risk Assessment and Mitigation

*   **Technical Risks**:
    *   The migration to the MS Graph PowerShell Module is a **high-risk effort**. The new module's behavior cannot be tested against a live development tenant, so we must rely solely on Microsoft's documentation. Unexpected authentication or permission issues may only be discovered during initial production use.
    *   A large-scale refactoring of the entire module to implement new patterns (Builder, Factory) could introduce subtle bugs or performance regressions.

*   **Integration Risks**:
    *   The new, extensible framework must be robust enough to handle all the variations required for different lifecycle events and company-specific configurations.
    *   Ensuring continued, reliable interaction with multiple on-premise Active Directory and Exchange environments after the refactor.

*   **Deployment Risks**:
    *   The new build and release pipeline using GitHub Actions and GitVersion will need to be carefully configured and tested to ensure it produces reliable, versioned artifacts.

*   **Mitigation Strategies**:
    *   **(Strategic)** As we agreed, the project will be split into at least two major epics (1. Foundational Refactoring & Migration, 2. New Lifecycle Features). This mitigates the risk of a single "big bang" release.
    *   **(Technical)** The initial MS Graph integration will be developed in a dedicated story. The implementation will strictly follow Microsoft's official migration guides. **Crucially, this code must include extensive and detailed logging and error handling around every Graph call** to ensure any real-world issues can be rapidly diagnosed.
    *   **(QA)** The Definition of Done for the core framework stories will require implementing at least two concrete "builders" to prove the extensibility pattern works as designed.
    *   **(Testing)** Our agreed-upon testing strategy of mocking the final cmdlets will ensure that our tests are stable, repeatable, and focused on our custom logic, mitigating risks from environmental failures.

## 4. Epic and Story Structure

### 4.1. Epic Approach

**Epic Structure Decision**: This project will be broken into two sequential epics.

*   **Epic 1: Foundational Refactoring & Migration.** This epic will focus entirely on the core technical uplift. This includes **restructuring the entire module to use the `modulebuilder` layout**, refactoring the code to use the new design patterns (Builder, Factory), integrating the 'Logging' module, and completing the critical migration to the MS Graph PowerShell Module. No new end-user features will be added in this epic. The goal is to create a stable, modernized foundation.
*   **Epic 2: User Lifecycle Feature Implementation.** Once the foundation is stable, this epic will deliver the new, user-facing lifecycle features (e.g., offboarding, user modifications) by adding new "builders" to the extensible framework created in Epic 1.

This two-epic approach allows us to tackle the high-risk technical work first and ensure the foundation is solid before building new functionality on top of it. It provides an incremental path to value and makes the project easier to manage.

## 5. Epic 1: Foundational Refactoring & Migration

**Epic Goal**: To refactor the existing `Sol` module into a modern, extensible, and maintainable framework using standard patterns and migrating to the MS Graph API. This epic delivers a stable technical foundation for future feature development.

**Integration Requirements**: The final product of this epic will be a fully refactored module. All existing logic from `New-CompanyUser` will be migrated into the new pattern. The module will connect to and use the MS Graph PowerShell module for all cloud operations.

### 5.1. Proposed Story Sequence (Final)

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

## 6. Out of Scope

The following items are explicitly out of scope for the work covered by this PRD (specifically Epic 1):

*   The implementation of any new user lifecycle features beyond the refactored `New-CompanyUser`.
*   Publishing the module to the public PowerShell Gallery.
*   Creating tests that validate the successful execution of the underlying `Microsoft.Graph` or `ActiveDirectory` cmdlets themselves.

## 7. Open Questions and Assumptions

*   What are the specific user lifecycle events (e.g., Disable, Department Change, etc.) that will be the highest priority for implementation in Epic 2?
*   What are the exact permissions that will be required for the MS Graph application registration to support the features planned for Epic 2 and beyond?

## 8. Sign-off

This document represents the complete Product Requirements Document for the foundational refactoring of the Sol module.

**Approved by**: signed off
**Date**: 2025-08-12

---
*This document was generated by the BMad Product Manager agent.*
---