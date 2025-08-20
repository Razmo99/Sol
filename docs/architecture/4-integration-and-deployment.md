# 4. Integration and Deployment

## 4.1. API Integration

Direct API integration is not in scope for this project. All interactions with Microsoft Graph will be performed via the official `Microsoft.Graph` PowerShell module, not by making raw REST API calls.

## 4.2. Deployment Pipeline

*   **Build Process Integration**: The module will be built using a GitHub Actions workflow. The workflow will use `GitVersion` to automatically calculate the module version based on git tags and branches.
*   **Deployment Strategy**: For now, the GitHub Actions workflow will create a GitHub Release and attach the packaged module as a release asset.
*   **Configuration Management**: The module will use a dedicated configuration class (`[SolConfig]`). At runtime, a single `[SolConfig]` object will be created from a config file and/or explicit parameters. This object will then be placed into the `[TaskContext]`'s `$Configuration` property. The single, overarching `TaskContext` is then passed to every task, giving each task access to the central, session-wide configuration when needed.
