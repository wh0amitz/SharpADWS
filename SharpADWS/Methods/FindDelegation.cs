using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SharpADWS.Methods
{
    internal class FindDelegation
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public FindDelegation(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void FindAllDelegation()
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate("(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(UserAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", this.DefaultNamingContext, "subtree", new string[] { "sAMAccountName", "userAccountControl", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo" });
            List<List<string>> results = new List<List<string>>();

            Console.WriteLine();

            foreach (ADObject adObject in adObjects)
            {
                string sAMAccountName = "";
                string objectType = "";
                string delegation = "";
                List<string> rightsTo = new List<string> { };

                sAMAccountName = adObject.SAMAccountName;
                if((adObject.UserAccountControl & 0x00080000) == 0x00080000)
                {
                    delegation = "Unconstrained";
                    rightsTo.Add("N/A");
                }

                if ((adObject.UserAccountControl & 0x01000000) == 0x01000000) 
                {
                    delegation = "Constrained w/ Protocol Transition";
                }
                else if(adObject.MsDSAllowedToDelegateTo != null)
                {
                    delegation = "Constrained";
                }

                objectType = FirstCharToUpper(adObject.Class);

                if(adObject.MsDSAllowedToDelegateTo != null)
                {
                    foreach(string delegRights in adObject.MsDSAllowedToDelegateTo)
                    {
                        rightsTo.Add(delegRights);
                    }
                }

                foreach (string rights in rightsTo)
                {
                    results.Add(new List<string> { sAMAccountName, objectType, delegation, rights});
                }

                if(adObject.MsDSAllowedToActOnBehalfOfOtherIdentity != null)
                {
                    string searchFilter = "(&(|";
                    foreach (ActiveDirectoryAccessRule ADRule in adObject.MsDSAllowedToActOnBehalfOfOtherIdentity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        if (ADRule.ActiveDirectoryRights == ActiveDirectoryRights.GenericAll ||
                          ADRule.AccessControlType == AccessControlType.Allow)
                        {
                            string objectSid = ADRule.IdentityReference.ToString();
                            searchFilter += $"(objectSid={objectSid})";
                        }
                    }
                    searchFilter += ")(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

                    List<ADObject> identityObjects = enumerateRequest.Enumerate(searchFilter, this.DefaultNamingContext, "subtree", new string[] { "sAMAccountName" });
                    foreach (ADObject iObject in identityObjects)
                    {
                        results.Add(new List<string> { iObject.SAMAccountName, FirstCharToUpper(iObject.Class), "Resource-Based Constrained", sAMAccountName });
                    }
                }
            }

            if(results.Count != 0)
            {
                List<string> headers = new List<string> { "AccountName", "AccountType", "DelegationType", "DelegationRightsTo" };
                PrintTable(results, headers);
            }
        }

        private string FirstCharToUpper(string input)
        {
            if (String.IsNullOrEmpty(input))
                throw new ArgumentException("Fxxk!");
            return input.First().ToString().ToUpper() + input.Substring(1);
        }

        static void PrintTable(List<List<string>> items, List<string> header)
        {
            List<int> colLen = new List<int>();

            for (int i = 0; i < header.Count; i++)
            {
                int rowMaxLen = items.Select(row => row[i].Length).Max();
                colLen.Add(Math.Max(rowMaxLen, header[i].Length));
            }

            PrintRow(header, colLen);

            PrintSeparator(colLen);

            foreach (var row in items)
            {
                PrintRow(row, colLen);
            }
        }

        static void PrintRow(List<string> row, List<int> colLen)
        {
            for (int i = 0; i < row.Count; i++)
            {
                Console.Write(row[i].PadRight(colLen[i]));
                if (i < row.Count - 1)
                {
                    Console.Write("  "); 
                }
            }
            Console.WriteLine();
        }

        static void PrintSeparator(List<int> colLen)
        {
            for (int i = 0; i < colLen.Count; i++)
            {
                Console.Write(new string('-', colLen[i]));
                if (i < colLen.Count - 1)
                {
                    Console.Write("  ");
                }
            }
            Console.WriteLine();
        }
    }
}
