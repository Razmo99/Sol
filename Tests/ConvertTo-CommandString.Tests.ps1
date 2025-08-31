Describe "ConvertTo-CommandString" {
    BeforeAll {
        # Import the function
        . "$PSScriptRoot/../Source/Private/ConvertTo-CommandString.ps1"
    }

    Context "Basic Parameter Types" {
        It "Should convert string parameters correctly" {
            $params = [ordered]@{
                Name = "TestUser"
                Path = "C:\Users\Test"
            }
            $result = ConvertTo-CommandString -CommandName "New-ADUser" -Parameters $params
            $result | Should -Be 'New-ADUser -Name "TestUser" -Path "C:\Users\Test"'
        }

        It "Should convert boolean parameters correctly" {
            $params = [ordered]@{
                Enabled = $true
                Archive = $false
                Force = $true
            }
            $result = ConvertTo-CommandString -CommandName "Set-User" -Parameters $params
            $result | Should -Be "Set-User -Enabled -Force"
        }

        It "Should convert integer parameters correctly" {
            $params = [ordered]@{
                Count = 5
                Timeout = 120
            }
            $result = ConvertTo-CommandString -CommandName "Get-Items" -Parameters $params
            $result | Should -Be "Get-Items -Count 5 -Timeout 120"
        }

        It "Should handle SecureString parameters" {
            $secureString = ConvertTo-SecureString "password" -AsPlainText -Force
            $params = [ordered]@{
                Name = "TestUser"
                Password = $secureString
            }
            $result = ConvertTo-CommandString -CommandName "New-User" -Parameters $params
            $result | Should -Be 'New-User -Name "TestUser" -Password $SecurePassword'
        }
    }

    Context "Special Cases" {
        It "Should skip null or empty string values" {
            $params = [ordered]@{
                Name = "TestUser"
                EmptyString = ""
                NullValue = $null
                WhitespaceOnly = "   "
            }
            $result = ConvertTo-CommandString -CommandName "New-User" -Parameters $params
            $result | Should -Be 'New-User -Name "TestUser"'
        }

        It "Should skip WhatIf by default" {
            $params = [ordered]@{
                Name = "TestUser"
                Whatif = $true
            }
            $result = ConvertTo-CommandString -CommandName "New-User" -Parameters $params
            $result | Should -Be 'New-User -Name "TestUser"'
        }

        It "Should include WhatIf when IncludeWhatIf switch is used" {
            $params = [ordered]@{
                Name = "TestUser"
                Whatif = $true
            }
            $result = ConvertTo-CommandString -CommandName "New-User" -Parameters $params -IncludeWhatIf
            $result | Should -Be 'New-User -Name "TestUser" -Whatif'
        }
    }

    Context "Parameter Ordering" {
        It "Should preserve order with ordered hashtables" {
            $params = [ordered]@{
                Identity = "john.doe"
                Server = "dc1.contoso.com"
                Properties = "Name,Department"
            }
            $result = ConvertTo-CommandString -CommandName "Get-ADUser" -Parameters $params
            $result | Should -Be 'Get-ADUser -Identity "john.doe" -Server "dc1.contoso.com" -Properties "Name,Department"'
        }

        It "Should handle regular hashtables with exact format validation" {
            $params = [ordered]@{
                Name = "TestUser"
                Enabled = $true
            }
            $result = ConvertTo-CommandString -CommandName "New-ADUser" -Parameters $params
            $result | Should -Be 'New-ADUser -Name "TestUser" -Enabled'
        }
    }

    Context "Complex Data Types" {
        It "Should handle hashtables by converting to string representation" {
            $params = [ordered]@{
                Name = "TestUser"
                Properties = @{ Department = "IT"; Location = "Sydney" }
            }
            $result = ConvertTo-CommandString -CommandName "New-User" -Parameters $params
            $result | Should -Be 'New-User -Name "TestUser" -Properties @{Department=''IT''; Location=''Sydney''}'
        }

        It "Should handle arrays by converting to string representation" {
            $params = [ordered]@{
                Groups = @("Admins", "Users", "IT-Staff")
                Name = "TestUser"
            }
            $result = ConvertTo-CommandString -CommandName "Add-UserToGroups" -Parameters $params
            $result | Should -Be 'Add-UserToGroups -Groups @(''Admins'', ''Users'', ''IT-Staff'') -Name "TestUser"'
        }
    }

    Context "Real-world Scenarios" {
        It "Should handle typical AD user creation splat" {
            $params = [ordered]@{
                Name = "John Doe"
                SamAccountName = "john.doe"
                UserPrincipalName = "john.doe@contoso.com"
                Path = "OU=Users,DC=contoso,DC=com"
                Enabled = $true
                ChangePasswordAtLogon = $false
                Department = "IT"
                Office = "Sydney"
            }
            $result = ConvertTo-CommandString -CommandName "New-ADUser" -Parameters $params
            $result | Should -Be 'New-ADUser -Name "John Doe" -SamAccountName "john.doe" -UserPrincipalName "john.doe@contoso.com" -Path "OU=Users,DC=contoso,DC=com" -Enabled -Department "IT" -Office "Sydney"'
        }

        It "Should handle Exchange mailbox creation splat" {
            $securePassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
            $params = [ordered]@{
                Name = "Test User"
                Password = $securePassword
                UserPrincipalName = "test.user@contoso.com"
                Alias = "testuser"
                Archive = $true
                DomainController = "dc1.contoso.com"
                OnPremisesOrganizationalUnit = "contoso.com/Users"
            }
            $result = ConvertTo-CommandString -CommandName "New-RemoteMailbox" -Parameters $params
            $result | Should -Be 'New-RemoteMailbox -Name "Test User" -Password $SecurePassword -UserPrincipalName "test.user@contoso.com" -Alias "testuser" -Archive -DomainController "dc1.contoso.com" -OnPremisesOrganizationalUnit "contoso.com/Users"'
        }
    }

    Context "Parameter Validation" {
        It "Should require CommandName parameter" {
            { ConvertTo-CommandString -Parameters @{} } | Should -Throw
        }

        It "Should require Parameters parameter" {
            { ConvertTo-CommandString -CommandName "Test-Command" } | Should -Throw
        }

        It "Should handle empty parameters hashtable" {
            $result = ConvertTo-CommandString -CommandName "Test-Command" -Parameters @{}
            $result | Should -Be "Test-Command"
        }
    }

    Context "Output Format Validation" {
        It "Should produce executable PowerShell command format" {
            $params = [ordered]@{
                Name = "Test User"
                Enabled = $true
                Count = 5
            }
            $result = ConvertTo-CommandString -CommandName "New-TestUser" -Parameters $params
            $result | Should -Be 'New-TestUser -Name "Test User" -Enabled -Count 5'
        }
    }
}