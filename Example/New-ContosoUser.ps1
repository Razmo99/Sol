#Requires -Module Sol

# Note this requires atleast a real AD environment

$InteractivePrompts = @{
    'EmailAccess' = @{
        Message  = 'Does this user need access to shared mailboxes?'
        Inverse  = $false
        MemberOf = @('SharedMailboxUsers')
    }
    'VPNAccess'   = @{
        Message      = 'Does this user need VPN access?'
        Inverse      = $false  
        MemberOf     = @('VPN-Users')
        Requirements = @{
            FileServerAccess = $true
            M365License      = @('E3', 'E5')
        }
    }
    'AdminRights' = @{
        Message      = 'Does this user need administrative rights?'
        Inverse      = $false
        MemberOf     = @('Local-Admins')
        Requirements = @{
            Prompts = @('VPNAccess')
        }
    }
}

$SplatContosoCompanyUser = @{
    EMSServer          = 'exchange.contoso.local'
    ADSyncServer       = 'adsync.contoso.local'
    EmailDomain        = '@contoso.local'
    Domain             = 'contoso.local'
    Company            = 'contoso'
    FallbackUserOU     = 'contoso.local/Users'
    AdminGroups        = ('Domain Admins', 'ContosoHelpdesk')
    InteractivePrompts = $InteractivePrompts
    WhatIf             = $true
}

New-CompanyUser @SplatContosoCompanyUser -Firstname John -Lastname Deer