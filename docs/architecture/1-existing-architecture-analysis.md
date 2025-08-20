# 1. Existing Architecture Analysis

## 1.1. Current Architecture Summary

The existing `Sol` module is a single, monolithic PowerShell script (`Sol.psm1`). It contains one primary public function, `New-CompanyUser`, which orchestrates user creation across multiple systems (on-premise AD, on-premise Exchange, Azure AD) through a sequential, hard-coded series of steps. Configuration is passed directly via a large number of parameters.

## 1.2. Architectural Pain Points

The current monolithic design leads to several challenges that this new architecture will address:

*   **Lack of Extensibility:** Adding new functionality (like offboarding) or modifying existing steps requires significant and risky changes to the core script.
*   **Configuration Variability:** The module is difficult to adapt to different company environments without code modifications.
*   **Legacy API Dependencies:** The module relies on older `AzureAD` and `MSOnline` modules, which are being deprecated in favor of the modern MS Graph API.
