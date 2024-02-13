using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;

namespace SharpADWS.Methods.ACL
{
    internal class DomainController
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public DomainController(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void Run(string Trustees, string Rights, int Rid, string OutputFormat)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(primaryGroupID=516)", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "nTSecurityDescriptor" });

            Console.WriteLine();

            foreach (ADObject userObject in userObjects)
            {
                ACLParser aclParser = new ACLParser(userObject.NTSecurityDescriptor, userObject, Trustees, Rights, null, Rid, OutputFormat);
                aclParser.Parse();
            }
        }
    }
}
