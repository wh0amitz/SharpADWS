using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpADWS.ADWS.Transfer;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.ServiceModel.Channels;

namespace SharpADWS.Methods
{
    internal class AddComputer
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;
        public AddComputer(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void Add(string ComputerName, string ComputerPass)
        {
            string sAMAccountName = "";

            if (ComputerName.EndsWith("$"))
            {
                sAMAccountName = ComputerName;
                ComputerName = ComputerName.Substring(0, ComputerName.Length - 1);
            }
            else
            {
                sAMAccountName = ComputerName + "$";
            }

            List<string> spnList = new List<string>
            {
                $"HOST/{ComputerName}",
                $"HOST/{ComputerName}.{adwsConnection.DomainName}",
                $"RestrictedKrbHost/{ComputerName}",
                $"RestrictedKrbHost/{ComputerName}.{adwsConnection.DomainName}",
            };

            string dNSHostName = $"{ComputerName}.{adwsConnection.DomainName}";
            string userAccountControl = "4096";
            string servicePrincipalName = $"HOST/{ComputerName}";
            
            byte[] unicodePwd = Encoding.Unicode.GetBytes("\"" + ComputerPass + "\"");

            DirectoryAttribute[] directoryAttribute = new DirectoryAttribute[6];
            directoryAttribute[0] = new DirectoryAttribute();
            directoryAttribute[0].Name = "objectClass";
            directoryAttribute[0].Add("computer");
            
            directoryAttribute[1] = new DirectoryAttribute();
            directoryAttribute[1].Name = "dNSHostName";
            directoryAttribute[1].Add(dNSHostName);
            
            directoryAttribute[2] = new DirectoryAttribute();
            directoryAttribute[2].Name = "userAccountControl";
            directoryAttribute[2].Add(userAccountControl);
            
            directoryAttribute[3] = new DirectoryAttribute();
            directoryAttribute[3].Name = "servicePrincipalName";
            directoryAttribute[3].Add(servicePrincipalName);
            
            directoryAttribute[4] = new DirectoryAttribute();
            directoryAttribute[4].Name = "sAMAccountName";
            directoryAttribute[4].Add(sAMAccountName);
            
            directoryAttribute[5] = new DirectoryAttribute();
            directoryAttribute[5].Name = "unicodePwd";
            directoryAttribute[5].Add(unicodePwd);
            
            CreateRequest createRequest = new CreateRequest(adwsConnection);
            Message addResponse = createRequest.AddRequest("CN=Computers," + this.DefaultNamingContext, "CN=" + ComputerName, directoryAttribute);

            Console.WriteLine();

            if(!addResponse.IsFault)
            {
                Console.WriteLine($"[*] Successfully added machine account {ComputerName}$ with password {ComputerPass}.");
            }
            else
            {
                Console.WriteLine($"[-] Add machine account {ComputerName}$ failed.");
            }
        }
    }
}
