# Source Tree

The module will follow the standard `modulebuilder` layout to ensure consistency and best practices.

/Sol/
|
|-- /Classes/
|   |-- /Tasks/
|   |   |-- TaskBase.ps1
|   |   |-- NewADUserTask.ps1
|   |   |-- EnableExchangeMailboxTask.ps1
|   |   `-- ... (other granular task classes)
|   |
|   |-- /Core/
|   |   |-- SolUser.ps1
|   |   |-- SolConfig.ps1
|   |   |-- TaskContext.ps1
|   |   |-- TaskResult.ps1
|   |   |-- INamingConvention.ps1
|   |   `-- WorkflowDirector.ps1
|   |
|   `-- /Factories/
|       `-- WorkflowFactory.ps1
|
|-- /Private/
|   `-- ... (internal helper functions, each in its own .ps1 file)
|
|-- /Public/
|   `-- ... (public functions, e.g., Invoke-SolWorkflow, each in its own .ps1 file)
|
|-- /en-US/
|   `-- about_Sol.help.txt
|
|-- Sol.psd1         # The module manifest
`-- Sol.psm1         # The root script module, responsible for loading classes and functions
