using SharpADWS.ADWS;
using System;
using System.Net;
using System.Collections.Generic;
using SharpADWS.ADWS.Enumeration;

namespace SharpADWS.Methods.ACL
{
    internal class Computer
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public Computer(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void Run(string Trustees, string Rights, int Rid, string OutputFormat)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(objectClass=computer)", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "nTSecurityDescriptor" });

            Console.WriteLine();

            foreach (ADObject userObject in userObjects)
            {
                if (userObject.Class == "computer")
                {
                    ACLParser aclParser = new ACLParser(userObject.NTSecurityDescriptor, userObject, Trustees, Rights, null, Rid, OutputFormat);
                    aclParser.Parse();
                }
            }
            List<ADObject> ComputerObjects = enumerateRequest.Enumerate("(&(operatingSystem=*)(sAMAccountName=*))", this.DefaultNamingContext, "subtree", new string[] { "name", "dNSHostName" });

            Console.WriteLine("Domain Computer IP:");
            foreach (ADObject adObject in ComputerObjects)
            {
                string Domian = adObject.DNSHostName;
                try
                {
                    IPAddress[] addresses = Dns.GetHostAddresses(Domian);
                    Console.Write($"{Domian}: ");
                    int len = addresses.Length;
                    foreach (IPAddress address in addresses)
                    {
                        Console.Write(address);
                        if (len > 1)
                        {
                            Console.Write(",");
                            len--;
                        }
                        else
                        {
                            Console.WriteLine();
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine($"{Domian} Down");
                }
            }
        }
    }
}
