using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;

namespace SharpADWS.Methods.ACL
{
    internal class Domain
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public Domain(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void Run(string Trustees, string Rights, int Rid, string OutputFormat)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(objectClass=domain)", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "nTSecurityDescriptor" });

            Console.WriteLine();

            foreach (ADObject userObject in userObjects)
            {
                if (userObject.Class == "domaindns")
                {
                    ACLParser aclParser = new ACLParser(userObject.NTSecurityDescriptor, userObject, Trustees, Rights, null, Rid, OutputFormat);
                    aclParser.Parse();
                }
            }
        }
    }
}
