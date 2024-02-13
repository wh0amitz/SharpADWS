using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS.Methods.ACL
{
    internal class ACLSearch
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public ACLSearch(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void Run(string distinguishedName, string searchScope, string Trustees, string Rights, int Rid, string OutputFormat)
        {
            if(String.IsNullOrEmpty(distinguishedName))
            {
                distinguishedName = this.DefaultNamingContext;
            }

            if(String.IsNullOrEmpty(searchScope))
            {
                searchScope = "base";
            }

            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> userObjects = enumerateRequest.Enumerate("(objectClass=*)", distinguishedName, searchScope, new string[] { "distinguishedName", "nTSecurityDescriptor" });

            Console.WriteLine();

            foreach (ADObject userObject in userObjects)
            {
                ACLParser aclParser = new ACLParser(userObject.NTSecurityDescriptor, userObject, Trustees, Rights, null, Rid, OutputFormat);
                aclParser.Parse();
            }
        }
    }
}
