# Tests/New-CompanyUser.Tests.ps1
BeforeAll {
    # Mock the AzureAD module
    Import-Module ./output/sol
}

Describe 'New-CompanyUser' {
    # This is a dummy test
    It 'Should be available after importing the module' {
        Get-Command New-CompanyUser | Should -Not -BeNull
    }
}
