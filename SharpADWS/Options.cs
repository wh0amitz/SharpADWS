using SharpADWS.Methods.ADCS;
using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS
{
    internal class Options
    {
        public string Method { get; set; }
        public string DomainName { get; set; }
        public string DomainController { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string DistinguishedName { get; set; }
        public string Scope { get; set; }
        public string Trustee { get; set; }
        public string Right { get; set; }
        public int Rid { get; set; }
        public string Target { get; set; }
        public string Action { get; set; }
        public string ComputerName { get; set; }
        public string ComputerPass { get; set; }
        public string DelegateTo { get; set; }
        public string DelegateFrom { get; set; }
        public string CertPassword { get; set; }
        public string Filename { get; set; }
        public string DeviceID { get; set; }
        public string OutputFormat { get; set; }
        public string Template { get; set; }

        public bool DisplayHelp { get; set; }

        public bool isUser = false;
        public bool isComputer = false;
        public bool isGroup = false;
        public bool isDomain = false;
        public bool isDomainController = false;
        public bool isGpo = false;

        public bool Vulnerable = false;
        public bool EnrolleeSuppliesSubject = false;
        public bool ClientAuth = false;

        public bool noWrap = false;

        public Options(string[] args)
        {
            Method = args[0].ToLower();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-h":
                        DisplayHelp = true;
                        break;
                    case "-d":
                        DomainName = args[i + 1];
                        break;
                    case "-dc":
                        DomainController = args[i + 1];
                        break;
                    case "-u":
                        Username = args[i + 1];
                        break;
                    case "-p":
                        Password = args[i + 1];
                        break;
                    case "-target":
                        Target = args[i + 1];
                        break;
                    case "-dn":
                        DistinguishedName = args[i + 1];
                        break;
                    case "-scope":
                        Scope = args[i + 1];
                        break;
                    case "-trustee":
                        Trustee = args[i + 1];
                        break;
                    case "-right":
                        Right = args[i + 1];
                        break;
                    case "-rid":
                        Rid = Convert.ToInt32(args[i + 1]);
                        break;
                    case "-user":
                        isUser = true;
                        break;
                    case "-computer":
                        isComputer = true;
                        break;
                    case "-group":
                        isGroup = true;
                        break;
                    case "-domain":
                        isDomain = true;
                        break;
                    case "-domaincontroller":
                        isDomainController = true;
                        break;
                    case "-gpo":
                        isGpo = true;
                        break;
                    case "-action":
                        Action = args[i + 1].ToLower();
                        break;
                    case "-computer-name":
                        ComputerName = args[i + 1];
                        break;
                    case "-computer-pass":
                        ComputerPass = args[i + 1];
                        break;
                    case "-delegate-to":
                        DelegateTo = args[i + 1];
                        break;
                    case "-delegate-from":
                        DelegateFrom = args[i + 1];
                        break;
                    case "-f":
                        Filename = args[i + 1];
                        break;
                    case "-cert-pass":
                        CertPassword = args[i + 1];
                        break;
                    case "-nowrap":
                        noWrap = true;
                        break;
                    case "-device-id":
                        DeviceID = args[i + 1];
                        break;
                    case "-vulnerable":
                        Vulnerable = true;
                        break;
                    case "-enrolleeSuppliesSubject":
                        EnrolleeSuppliesSubject = true;
                        break;
                    case "-clientAuth":
                        ClientAuth = true;
                        break;
                    case "-template":
                        Template = args[i + 1];
                        break;
                }
            }
        }
    }
}
