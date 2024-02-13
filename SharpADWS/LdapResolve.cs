/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Resolve GUIDs to display name, such as SchemaObjectGUID, ExtendedRight, etc
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.AccessControl;
using System.Data;
using static System.Net.Mime.MediaTypeNames;

namespace SharpADWS
{
    internal class LdapResolve
    {
        private ADObjectCache objectCache = null;
        public LdapResolve()
        {
            try
            {
                FileStream fileStream = new FileStream("object.cache", FileMode.Open);
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                objectCache = (ADObjectCache)binaryFormatter.Deserialize(fileStream);
                fileStream.Close();
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("[-] Cache file not found, please run SharpADWS.exe Cache first to generate");
                Environment.Exit(0);
            }
        }

        public string ResolveSIDToName(string Sid)
        {
            Dictionary<string, string> UniversalWellKnownSIDs = new Dictionary<string, string>
            {
                {"S-1-0", "Null Authority"},
                {"S-1-0-0", "Nobody"},
                {"S-1-1", "World Authority"},
                {"S-1-1-0", "Everyone"},
                {"S-1-2", "Local Authority"},
                {"S-1-2-0", "Local"},
                {"S-1-2-1", "Console Logon "},
                {"S-1-3", "Creator Authority"},
                {"S-1-3-0", "Creator Owner"},
                {"S-1-3-1", "Creator Group"},
                {"S-1-3-2", "Creator Owner Server"},
                {"S-1-3-3", "Creator Group Server"},
                {"S-1-3-4", "Owner Rights"},
                {"S-1-4", "Non-unique Authority"},
                {"S-1-5", "NT Authority"},
                {"S-1-5-1", "Dialup"},
                {"S-1-5-2", "Network"},
                {"S-1-5-3", "Batch"},
                {"S-1-5-4", "Interactive"},
                {"S-1-5-6", "Service"},
                {"S-1-5-7", "Anonymous"},
                {"S-1-5-8", "Proxy"},
                {"S-1-5-9", "Enterprise Domain Controllers"},
                {"S-1-5-10", "Principal Self"},
                {"S-1-5-11", "Authenticated Users"},
                {"S-1-5-12", "Restricted Code"},
                {"S-1-5-13", "Terminal Server Users"},
                {"S-1-5-14", "Remote Interactive Logon"},
                {"S-1-5-15", "This Organization"},
                {"S-1-5-17", "IUSR"},
                {"S-1-5-18", "Local System"},
                {"S-1-5-19", "NT Authority"},
                {"S-1-5-20", "NT Authority"},
                {"S-1-5-22", "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS BETA"},
                {"S-1-5-32-544", "Administrators"},
                {"S-1-5-32-545", "Users"},
                {"S-1-5-32-546", "Guests"},
                {"S-1-5-32-547", "Power Users"},
                {"S-1-5-32-548", "BUILTIN\\Account Operators"},
                {"S-1-5-32-549", "Server Operators"},
                {"S-1-5-32-550", "Print Operators"},
                {"S-1-5-32-551", "Backup Operators"},
                {"S-1-5-32-552", "Replicator"},
                {"S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access"},
                {"S-1-5-32-555", "BUILTIN\\Remote Desktop Users"},
                {"S-1-5-32-556", "BUILTIN\\Network Configuration Operators"},
                {"S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders"},
                {"S-1-5-32-558", "BUILTIN\\Performance Monitor Users"},
                {"S-1-5-32-559", "BUILTIN\\Performance Log Users"},
                {"S-1-5-32-560", "BUILTIN\\Windows Authorization Access Group"},
                {"S-1-5-32-561", "BUILTIN\\Terminal Server License Servers"},
                {"S-1-5-32-562", "BUILTIN\\Distributed COM Users"},
                {"S-1-5-32-568", "BUILTIN\\IIS_IUSRS"},
                {"S-1-5-32-569", "BUILTIN\\Cryptographic Operators"},
                {"S-1-5-32-573", "BUILTIN\\Event Log Readers "},
                {"S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access"},
                {"S-1-5-32-575", "BUILTIN\\RDS Remote Access Servers"},
                {"S-1-5-32-576", "BUILTIN\\RDS Endpoint Servers"},
                {"S-1-5-32-577", "BUILTIN\\RDS Management Servers"},
                {"S-1-5-32-578", "BUILTIN\\Hyper-V Administrators"},
                {"S-1-5-32-579", "BUILTIN\\Access Control Assistance Operators"},
                {"S-1-5-32-580", "BUILTIN\\Remote Management Users"},
                {"S-1-5-33", "Write Restricted Code"},
                {"S-1-5-64-10", "NTLM Authentication"},
                {"S-1-5-64-14", "SChannel Authentication"},
                {"S-1-5-64-21", "Digest Authentication"},
                {"S-1-5-65-1", "This Organization Certificate"},
                {"S-1-5-80", "NT Service"},
                {"S-1-5-84-0-0-0-0-0", "User Mode Drivers"},
                {"S-1-5-113", "Local Account"},
                {"S-1-5-114", "Local Account And Member Of Administrators Group"},
                {"S-1-5-1000", "Other Organization"},
                {"S-1-15-2-1", "All App Packages"},
                {"S-1-16-0", "Untrusted Mandatory Level"},
                {"S-1-16-4096", "Low Mandatory Level"},
                {"S-1-16-8192", "Medium Mandatory Level"},
                {"S-1-16-8448", "Medium Plus Mandatory Level"},
                {"S-1-16-12288", "High Mandatory Level"},
                {"S-1-16-16384", "System Mandatory Level"},
                {"S-1-16-20480", "Protected Process Mandatory Level"},
                {"S-1-16-28672", "Secure Process Mandatory Level"},
                {"S-1-18-1", "Authentication Authority Asserted Identityl"},
                {"S-1-18-2", "Service Asserted Identity"}
            };

            if (UniversalWellKnownSIDs.ContainsKey(Sid))
            {
                return UniversalWellKnownSIDs[Sid];
            }
            else
            {
                if (objectCache.ObjectSidToNameCache.ContainsKey(Sid))
                {
                    return objectCache.ObjectSidToNameCache[Sid];
                }
                return Sid;
            }
        }

        public bool isStandardPrincipal(string Sid)
        {
            Dictionary<string, string> InterestingSIDs = new Dictionary<string, string>
            {
                {"S-1-1-0", "Everyone"},
                {"S-1-3-0", "Creator Owner"},
                {"S-1-3-1", "Creator Group"},
                {"S-1-5-4", "Interactive"},
                {"S-1-5-7", "Anonymous"},
                {"S-1-5-11", "Authenticated Users"},
                {"S-1-5-32-545", "Users"},
                {"S-1-5-32-546", "Guests"},
            };

            int rid = int.Parse(Sid.Substring(Sid.LastIndexOf('-') + 1));

            if(rid > 1000 || InterestingSIDs.ContainsKey(Sid))
            {
                return true;
            }
            return false;
        }
    }
}
