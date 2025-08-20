# Sol - A PowerShell Module

Sol is a PowerShell module that automates the creation of new company users in hybrid Microsoft 365 environments. It streamlines the process of creating users across on-premises Active Directory, Exchange Server, and Microsoft 365 systems.

**Key Features:**
- Automated user creation with AD and Microsoft Graph synchronization
- Branch-specific configuration support via BRANCHES.XML
- Interactive and non-interactive modes with pipeline support
- Conditional prompting system with topological sorting
- Microsoft 365 license assignment (E1, E2, E3)
- Comprehensive parameter validation and credential fallback
- Detailed logging and error handling

Currently configured for Hybrid 365 systems with on-premises Exchange Server and Microsoft Graph integration.

# How It Works

## Username Format

Usernames are automatically generated using the format: `firstname.lastname`

## Interactive Mode (Default)

When running the configuration script without parameters, Sol operates in interactive mode and follows this workflow:

1. **Permission Validation** - Validates AD, EMS, and ADSync permissions with credential fallback
2. **Branch Configuration** - Loads BRANCHES.XML and displays available branches for selection
    - _Skipped if BRANCHES.XML cannot be found_
3. **User Information Setup** - Generates SamAccountName, UserPrincipalName, and DisplayName
4. **Duplicate User Check** - Verifies user doesn't exist in AD, Microsoft Graph, or EMS
5. **Active Directory User Creation** - Creates new AD user with all provided attributes
6. **AD Synchronization Wait** - Waits for AD user sync confirmation (60 second timeout)
7. **Directory Sync Trigger** - Initiates EntraID sync via ADSync server
8. **Microsoft Graph Sync Wait** - Waits for Microsoft Graph user sync (120 second timeout)
9. **M365 License Assignment** - Interactive prompt for license selection (E1/E2/E3/None)
10. **Group Membership Processing** - Processes InteractivePrompts and AutoMemberOf configurations
11. **Group Assignment** - Applies group memberships based on license and access requirements 

## Non-Interactive Mode

Non-interactive mode follows the same workflow as interactive mode but skips user prompts for confirmation and input. All required parameters must be provided via the function parameters or pipeline input.

**Note:** Credentials will still be prompted if they are invalid or if MFA is enabled on the M365 account.

# Installation

## Option 1: Standard Module Installation
Follow the [official PowerShell module installation guide](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7.1#where-to-install-modules) to install Sol in your PowerShell modules directory.

## Option 2: Local Installation
Alternatively, place the Sol module in the same folder as your execution script and import it directly:

~~~powershell
Import-Module .\Sol
~~~

## Requirements
~~~powershell
# Add your specific module requirements here
~~~

# Usage

Once the module is installed, you can use any of its functions. The primary function is `New-CompanyUser`.

## Creating a Company-Specific Script

For convenient usage, create a PowerShell script named `Create-{YourCompanyName}User.ps1` and add the following configuration code:
### Option A: Local Module Import
Use this approach if the Sol module is in the same directory as your script:

~~~powershell
$CurrentPath = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
# Import the Sol Module
try {
    Import-Module ($CurrentPath + '\Sol')    
} catch {
    Write-Error($_.Exception.Message)
    exit
}
~~~

### Option B: System Module
Use this approach if Sol is installed as a system module:

~~~powershell
#Requires -Module Sol
~~~

## Company Configuration

Next, create a company-specific configuration hashtable (splat):

~~~powershell
$SplatContosoCompanyUser = @{
    EMSServer = 'exchange.contoso.local'
    ADSyncServer = 'adsync.contoso.local'
    EmailDomain = '@contoso.local'
    Domain = 'contoso'
    Company = 'contoso'
    FallbackUserOU = 'contoso.local/Users'
    AdminGroups = ('Domain Admins','ContosoHelpdesk')
}
~~~

## Running the Function

Execute the `New-CompanyUser` function with your configuration:

~~~powershell
# Test run (recommended for first use)
New-CompanyUser @SplatContosoCompanyUser -WhatIf

# Production run
New-CompanyUser @SplatContosoCompanyUser
~~~

**Tip:** Use `-WhatIf` parameter for the first run to verify the configuration is correct before making actual changes.

# Configuration Parameters

The Sol module uses two categories of parameters: company-specific settings that remain constant across all user creations, and user-specific parameters that vary for each individual user.

## Company-Specific Parameters

- **EMSServer** -- `{string}` ***(Required)***
    - DNS name of the on-premises Exchange server
    - A PowerShell session will be established to this address
    
- **ADSyncServer** -- `{string}` ***(Required)***
    - DNS name of the server hosting the Azure AD Connector
    
- **EmailDomain** -- `{string}` ***(Required)***
    - Email domain for the company (e.g., `@contoso.local`)
    
- **Domain** -- `{string}` ***(Required)***
    - Full domain name of the company
    - Used to discover Domain Controller for AD commands
    
- **Company** -- `{string}` ***(Required)***
    - Company name used in Active Directory attributes
    - Used alongside [Branch Information](#branchdepartment-information)
    
- **FallbackUserOU** -- `{string}`
    - Default OU to place new users when branch information is unavailable
    
- **AdminGroups** -- `{ArrayList}`
    - Groups used to verify current user has sufficient permissions
    - Accepts: distinguished name, objectGUID, objectSid, sAMAccountName
    
- **InteractivePrompts** -- `{HashTable}`
    - Configuration for conditional user prompting
    - See [Interactive Prompts](#interactive-prompts) section
    
- **AutoMemberOf** -- `{HashTable}`
    - Non-prompting group assignments with conditions
    
- **ADAdminCreds** -- `{PSCredential}`
    - Alternative credentials for Active Directory operations
    
- **EMSAdminCreds** -- `{PSCredential}`
    - Alternative credentials for Exchange server connection
    
- **ADSyncAdminCreds** -- `{PSCredential}`
    - Alternative credentials for AD Sync server connection

## User-Specific Parameters

### Mandatory User Information
- **Firstname** -- `{string}` ***(Required)***
    - First name of the user (1-20 characters)
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Lastname** -- `{string}` ***(Required)***
    - Last name of the user (can be empty string)
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Password** -- `{SecureString}` ***(Required)***
    - User's initial password
    - Supports pipeline input via ValueFromPipelineByPropertyName

### Contact Information
- **OfficePhone** -- `{string}`
    - Office phone number (must be exactly 4 digits or empty)
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **MobilePhone** -- `{string}`
    - Mobile phone number (must be exactly 10 digits or empty)
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Title** -- `{string}`
    - Job title/position
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Description** -- `{string}`
    - User description/notes
    - Supports pipeline input via ValueFromPipelineByPropertyName

### Address Information
- **StreetAddress** -- `{string}`
    - Street address
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **State** -- `{string}`
    - State/province
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **City** -- `{string}`
    - City
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **PostalCode** -- `{string}`
    - Postal/ZIP code
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Country** -- `{string}`
    - Country
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Department** -- `{string}`
    - Department
    - Supports pipeline input via ValueFromPipelineByPropertyName

### Active Directory Profile Settings
- **LogonScript** -- `{string}`
    - Logon script path
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **ProfilePath** -- `{string}`
    - User profile path
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **HomeDirectory** -- `{string}`
    - Home directory path
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **HomeDrive** -- `{string}`
    - Home drive letter
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **Manager** -- `{string}`
    - Manager's sAMAccountName
    - Accepts: distinguished name, objectGUID, objectSid, sAMAccountName
    - Supports pipeline input via ValueFromPipelineByPropertyName
    
- **UserOU** -- `{string}`
    - Organizational Unit for the user
    - Supports pipeline input via ValueFromPipelineByPropertyName

### Microsoft 365 License Assignment
M365 licenses are assigned interactively during user creation with the prompt: "Assign M365 License? [E1,E2,E3,N]"

**Supported License Types:**
- **E1** → Microsoft 365 Business Basic (STANDARDPACK)
- **E2** → Exchange Enterprise (EXCHANGEENTERPRISE)  
- **E3** → Microsoft 365 Business Premium (ENTERPRISEPACK)
- **N** → No license assigned

# Branch/Department Information

Sol supports branch-specific user configuration through an optional XML file named `BRANCHES.XML`. This file should be placed in the same directory as your configuration script and contains company branch-specific information such as department, address, logon script, and organizational unit details.

**Note:** If this file is missing or cannot be found, `New-CompanyUser` will use the fallback settings and skip branch-specific configuration.

## Branch XML Structure

The BRANCHES.XML file follows this hierarchical structure:

```
CompanyName
  └── BranchName
      ├── name              # Display name (shown in interactive mode)
      ├── street            # Maps to AD 'StreetAddress'
      ├── po_box            # Maps to AD 'POBox'
      ├── state             # Maps to AD 'State'
      ├── city              # Maps to AD 'City'
      ├── office            # Maps to AD 'Office'
      ├── country           # Maps to AD 'Country'
      ├── department        # Maps to AD 'Department'
      ├── company           # Maps to AD 'Company'
      ├── post_code         # Maps to AD 'PostalCode'
      ├── manager           # Maps to AD 'sAMAccountName'
      ├── logonscript       # Maps to AD 'ScriptPath'
      ├── ou                # Maps to Exchange 'OnPremisesOrganizationalUnit'
      ├── drive_group       # File server security group for branch
      └── distro            # Email distribution group for branch
```

### Field Details

- **manager**: Accepts distinguished name, objectGUID, objectSid, or sAMAccountName
- **ou**: Accepts Name, Canonical name, Distinguished name (DN), or GUID
- **drive_group**: File server security group for users with file access
- **distro**: Email distribution group (user added unless specified otherwise)
- Both **drive_group** and **distro** accept: distinguished name, objectGUID, objectSid, sAMAccountName

## BRANCHES.XML Example

~~~xml
<?xml version="1.0" encoding="utf-8"?>
<contoso>
    <HeadOffice-9999> 
        <name>Head Office - Sydney</name> 
        <street>99 Contoso Place</street>
        <po_box>P.O Box 9999</po_box>
        <state>NSW</state>
        <city>Sydney</city>
        <office>Head Office</office>
        <country>AU</country> 
        <department>HO</department>
        <company>Contoso Ltd</company> 
        <post_code>2000</post_code>
        <manager>contoso.manager</manager> 
        <logonscript>HO.bat</logonscript>
        <ou>contoso.local/HeadOffice-9999</ou>
        <drive_group>HO-FileAccess</drive_group>
        <distro>HO-Staff</distro>
    </HeadOffice-9999>
    
    <OutBack-9998>
        <name>Outback Branch - Perth</name>
        <street>123 Mining Road</street>
        <po_box>P.O Box 9998</po_box>
        <state>WA</state>
        <city>Perth</city>
        <office>Outback Office</office>
        <country>AU</country>
        <department>OB</department>
        <company>Contoso Ltd</company>
        <post_code>6000</post_code>
        <manager>outback.manager</manager>
        <logonscript>OB.bat</logonscript>
        <ou>contoso.local/OutBack-9998</ou>
        <drive_group>OB-FileAccess</drive_group>
        <distro>OB-Staff</distro>
    </OutBack-9998>
</contoso>
~~~
## Interactive Prompts

The module supports advanced conditional prompting through an `InteractivePrompts` configuration. This allows you to present context-specific questions to users based on their assigned licenses, file server access, and dependencies between prompts.

### Setting up Interactive Prompts

Interactive prompts are configured as a HashTable and passed to `New-CompanyUser`. Each prompt can have requirements that determine when it should be displayed to the user.

#### Basic Interactive Prompt Structure
~~~powershell
$InteractivePrompts = @{
    'EmailAccess' = @{
        Message = 'Does this user need access to shared mailboxes?'
        Inverse = $false
        MemberOf = @('SharedMailboxUsers')
    }
    'VPNAccess' = @{
        Message = 'Does this user need VPN access?'
        Inverse = $false  
        MemberOf = @('VPN-Users')
        Requirements = @{
            FileServerAccess = $true
            M365License = @('E3', 'E5')
        }
    }
    'AdminRights' = @{
        Message = 'Does this user need administrative rights?'
        Inverse = $false
        MemberOf = @('Local-Admins')
        Requirements = @{
            Prompts = @('VPNAccess')
        }
    }
}
~~~

#### Adding to Company Configuration
~~~powershell
$SplatContosoCompanyUser = @{
    EMSServer = 'exchange.contoso.local'
    ADSyncServer = 'adsync.contoso.local'
    EmailDomain = '@contoso.local'
    Domain = 'contoso'
    Company = 'contoso'
    FallbackUserOU = 'contoso.local/Users'
    AdminGroups = ('Domain Admins','ContosoHelpdesk')
    InteractivePrompts = $InteractivePrompts
}
~~~

### Prompt Requirements

Prompts support three types of requirements:

- **FileServerAccess** -- `{bool}`
    - Prompt only displays if the user has been assigned file server access
- **M365License** -- `{ArrayList}`
    - Prompt only displays if user has one of the specified licenses ('E1','E2','E3' or 'Any')
- **Prompts** -- `{ArrayList}`
    - Prompt only displays if the user answered "yes" to the specified dependent prompts

The system automatically handles prompt ordering using topological sorting to ensure dependencies are resolved in the correct sequence.

## Logging

Sol automatically creates detailed logs to track user creation activities. Logs are stored in a `logs` folder created in the same directory as your [configuration script](#usage).

### Log File Naming Convention

- **Single User Creation**: `{DisplayName}_{Date}.log`
- **Pipeline/Batch Creation**: `{Domain}_{Date}.log`

### Log Location

```
YourScript.ps1
logs/
├── John.Smith_2023-12-15.log
├── Jane.Doe_2023-12-15.log
└── contoso_2023-12-15.log
```

Logs contain detailed information about each step of the user creation process, including any errors encountered and credential prompts.
