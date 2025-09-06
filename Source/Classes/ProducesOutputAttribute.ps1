using namespace System

class ProducesOutputAttribute : Attribute {
    [string]$OutputName
    [type]$OutputType

    ProducesOutputAttribute([string]$OutputName, [type]$OutputType) {
        if ([string]::IsNullOrWhiteSpace($OutputName)) {
            throw [ArgumentException]::new("OutputName cannot be null or empty", "OutputName")
        }
        if ($null -eq $OutputType) {
            throw [ArgumentNullException]::new("OutputType", "OutputType cannot be null")
        }

        $this.OutputName = $OutputName
        $this.OutputType = $OutputType
    }
}