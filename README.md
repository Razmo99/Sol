# Sol; A Powershell Module
Contains functions to create New Company Users

Currently its configured for a Hybrid 365 System with a on premise exchange server.

# How it works

## Formatting

Usernames are currently configured for firstname.lastname

## Interactive Mode True
Assuming the configuration script it run without and input.

1. FirstName, LastName & Password are prompted for.
2. List of Branches are displayed; Prompts to select one.
    1. _Skipped if BRANCHES.XML cannot be found_
3. Display branch information and confirmation is requested
4. Other user information is collected; Title, Manager, M365 License etc
5. All User information is display and confirmation is requested
6. A connection to the on premise exchange server is made
    1. _Prompts for credentials if the current users are insufficient_
7. If the user doesn't exist, the user is then created.
8. Waits till the user appears in AD, then Sets the users attributes.
9. Sets the users groups.
10. Starts a "Delta sync" on the Azure AD Connect server
11. Waits till the user can be found in M365
    1. Tries to sign in using the UserPrincipleName of the current user, MFA will need to be entered if enabled
    2. If auth fails it will ask again for other credentials
12. Sets M365 License if specified.
13. Authenticates to Msol and Sets StrongAuthenticationRequirements for the user 

## Interactive Mode False

Same as "Interactive Mode True" except it doesn't prompt the user for confirmation or input.

Credentials will be prompted for if found to be invalid, or if MFA is enabled on the M365 account.

# Installation
[Install the module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7.1#where-to-install-modules)\
Alternatively just place the module in the same folder as the execution script and use `Import-Module`
## Requirements
~~~powershell
#Requires  -module ActiveDirectory
#Requires  -module AzureAD
#Requires  -module MSOnline
~~~

# Usage

After getting the module installed you can call any function in the module which is useful. Currently the main function is `New-CompanyUser`\
To use this function conveniently, make another powershell file called "Create-{InsertCompanyName}User.ps1" 

_Add the following code to it filling in company specific info_
~~~powershell
$CurrentPath = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
#Get the Sol Module which contains most of the functions needed
try{
    Import-Module ($CurrentPath+'\Sol')    
}
catch{
    #Without the Sol module exit
    Write-Error($_.Exception.Message)
    exit
}
~~~
_The above code would be relevant if you had the sol module in the same directory as the "Create-{InsertCompanyName}User.ps1". Otherwise the below should suffice_
~~~powershell
#Requires Sol
~~~
Next A Company Specific "Splat" needs to be made

~~~powershell
$SplatContosoCompanyUser = @{
    EMSServer = 'exchange.contoso.local',
    ADSyncServer = 'adsync.contoso.local',
    EmailDomain = '@contoso.local',
    Domain = 'contso',
    Company = 'contoso',
    Verbose = $true,
    FallbackUserOU = 'contoso.local/Users',
    AdminGroups = ('Domain Admins','ContosoHelpdesk'),
    StrongAuthenticationRequirements = 'Enforced',
}
~~~
Then just run the New-CompanyUser function
~~~powershell
New-CompanyUser @SplatContosoCompanyUser -whatif
~~~
_I would add whatif for the first time, to check everything is correct._

# Variable Explanation
Some variables are specific to a company others are specific to the user being created

## Company Specific Variables
- EMSServer -- {string} ***Required**
    - DNS Name of an on premise exchange server
    - A `New-PSSessions` will be initiated to this address
- EMSCredentials -- {PSCredential}
    - Used if the current users credentials are insufficient to start a `New-PSSessions` on the EMSServer.
    - This will auto prompt.
- ADSyncServer -- {string} ***Required**
    - DNS Name of the server hosting the Azure AD Connector
- ADSyncCredentials -- {PSCredential}
    - Used if the current users credentials are insufficient to start a `New-PSSessions` on the ADSyncServer.
    - This will auto prompt.
- EmailDomain -- {string} ***Required**
    - Domain of the company the user is being made for
    - i.e @contoso.local
- ADCredentials -- {PSCredential}
    - Used if the current users credentials are insufficient to run certain commands on Active Directory.
    - This will auto prompt.
- Domain -- {string} ***Required**
    - Full domain name of the company
    - Used to Discover a Domain Controller to execute AD commands on.
    - Used to Name log files when accepting pipline input
    - Used to prefix ADCredentials sign in
- Company -- {string}
    - Specifies the `CompanyName` to use
    - _Used alongside the [Branch Information](#Branch/Department-Information)_
- Verbose -- {bool}
- whatif -- {bool}
- FallbackUserOU -- {string} ***Required**
    - Default OU to place new user into
    - _Only used if the [Branch Information](#Branch/Department-Information) is missing_
- AdminGroups -- {ArrayList}
    - This is part of the check to assert if the current user has sufficient perms to make new users
    - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_
- Interactive -- {bool}
    - True by default
    - Will prompt in the console for missing fields like manager, Branch, title etc
    - _False if accepting pipeline input_

## User Specific Variables
- Firstname -- {string} ***Required**
- Lastname -- {string} ***Required**
    - Allowed to be an empty string
- Password -- {SecureString} ***Required**
    - In interactive mode a input will come up
- OfficePhone -- {string}
- MobilePhone -- {string}
- Title -- {string}
- Manager -- {string}
    - AD Attribute 'sAMAccountName'
    - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_
- Branch -- {string}
    - Selected from what available in the `BRANCHES.XML`
- M365License -- {string}
    - _Supports: E1,E2,E3 currently_
- FileServerAccess -- {bool}
- DistributionList -- {bool}
- MemberOf -- {ArrayList}
    - Groups the user is a MemberOf
    - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_
- StrongAuthenticationRequirements -- {ArrayList} ***Required**
    - _Supports: Enforced,Disabled,Enabled_

# Branch/Department Information
An optional XML Document named `BRANCHES.XML` can be placed in the same directory as the configuration ps1.\
It contains company branch specific information such as Department, Address, Logon script etc.

If this file is missing or cannot be found the New-CompanyUser will just be unable to set this information for the new user

## Branch Breakdown
- CompanyName
    - BranchName
        - name
            - This will be displayed in interactive mode. Generally the same as `BranchName`
        - street
            - AD Attribute 'StreetAddress'
        - po_box
            - AD Attribute 'POBox'
        - state
            - AD Attribute 'State'
        - city
            - AD Attribute 'City'
        - office
            - AD Attribute 'Office'
        - country
            - AD Attribute 'Country'
        - department
            - AD Attribute 'Department'
        - company
            - AD Attribute 'Company'
        - post_code
            - AD Attribute 'PostalCode'
        - manager
            - AD Attribute 'sAMAccountName'
            - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_
        - logonscript
            - AD Attribute 'ScriptPath'
        - ou
            - EMS Attribute 'OnPremisesOrganizationalUnit'
            - _Accepts: Name,Canonical name,Distinguished name (DN),GUID_
        - drive_group
            - A File server security group for this branch to add the new user to; if File Access is specified.
            - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_
        - distro
            - A email distribution group for this branch that the user will be added, unless specified otherwise
            - _Accepts: distinguished name,objectGUID,objectSid,sAMAccountName_

## Branch Example
~~~xml
<?xml version="1.0" encoding="utf-8"?>
<contoso>
    <HeadOffice-9999> 
        <name>HeadOffice-9999</name> 
        <street>99 contoso place</street>
        <po_box>P.O Box 9999</po_box>
        <state>NSW</state>
        <city>Contoso</city>
        <office>Head Office</office>
        <country>AU</country> 
        <department>HO</department>
        <company>Contoso</company> 
        <post_code>9999</post_code>
        <manager>contoso.manager</manager> 
        <logonscript>HO.bat</logonscript>
        <ou>contoso.local/HeadOffice-9999</ou>
        <drive_group>HO</drive_group>
        <distro>FS-Access</distro>
    </HeadOffice-9999>
    <OutBack-9998>
        <name>OutBack-9998</name>
        <!-- and so on filling out all the fields -->
    <OutBack-9998>
</contoso>
~~~
## Logging
Logs will be placed in a folder called logs in the same directory as the [configuration .ps1](#Usage)

Single user creations will be named {DisplayName}_{Date}.log
Pipeline user creation will be name {Domain}_{Date}.log
