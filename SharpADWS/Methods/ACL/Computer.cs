using SharpADWS.ADWS;
using System;
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
        }
    }
}
