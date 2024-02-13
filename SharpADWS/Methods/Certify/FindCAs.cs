using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS;
using SharpADWS.Methods.ACL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections;

namespace SharpADWS.Methods.ADCS
{
    internal class FindCAs
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public FindCAs(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        private static Dictionary<string, List<string>> CARights = new Dictionary<string, List<string>>();

        public void Run(bool vulnerable, bool enrolleeSuppliesSubject, bool clientAuth)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> pkiObjects = enumerateRequest.Enumerate("(ObjectClass=pKIEnrollmentService)", "CN=Configuration," + this.DefaultNamingContext, "subtree", new string[] { "name", "certificateTemplates" });
            
            foreach (ADObject pkiObject in pkiObjects)
            {
                if (pkiObject.Class == "pkienrollmentservice")
                {
                    
                    if (pkiObject.CertificateTemplates != null)
                    {
                        string caname = pkiObject.Name.ToUpper();
                        foreach (string template in pkiObject.CertificateTemplates)
                        {
                            PKITemplateCache.AddTemplateCA(template, caname);
                        }
                    }
                }
            }

            enumerateRequest = new EnumerateRequest(this.adwsConnection);
            pkiObjects = enumerateRequest.Enumerate("(ObjectClass=*)", "CN=Configuration," + this.DefaultNamingContext, "subtree", new string[] { "name", "displayName", "nTSecurityDescriptor", "objectGUID", "dNSHostName", "nTSecurityDescriptor", "certificateTemplates", "cACertificate", "msPKI-Minimal-Key-Size", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag", "pKIExtendedKeyUsage", "pKIOverlapPeriod", "pKIExpirationPeriod" });

            Console.WriteLine();

            CAParser caParser = new CAParser();

            Console.WriteLine("[*] Find CA and certificate templates");
            Console.WriteLine($"[*] Using the search base 'CN=Configuration,{this.DefaultNamingContext}'");
            
            foreach (ADObject pkiObject in pkiObjects)
            {
                if (pkiObject.Class == "pkienrollmentservice")
                {
                    CA ca = caParser.ParseCA(pkiObject, adwsConnection.DomainName);

                    IEnumerator aces = ca.Aces.GetEnumerator();
                    while (aces.MoveNext())
                    {
                        if (((Ace)aces.Current).RightName == "Certificate-Enrollment" || ((Ace)aces.Current).RightName == "Certificate-AutoEnrollment")
                        {
                            AddCARights("Enroll", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "ManageCA")
                        {
                            AddCARights("ManageCA", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "ManageCertificates")
                        {
                            AddCARights("ManageCertificates", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteDacl")
                        {
                            AddCARights("WriteDacl", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteOwner")
                        {
                            AddCARights("WriteOwner", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteProperty")
                        {
                            AddCARights("WriteProperty", ((Ace)aces.Current).Principal);
                        }
                    }

                    Console.WriteLine($"[*] Listing info about the Enterprise CA '{ca.Properties.caname}'\n");

                    Console.WriteLine("    Enterprise CA Name              : " + ca.Properties.caname);
                    Console.WriteLine("    DNS Name                        : " + ca.Properties.dnsname);
                    Console.WriteLine("    FullName                        : " + ca.Properties.dnsname + "\\" + ca.Properties.caname);
                    Console.WriteLine("    Certificate Subject             : " + ca.Properties.certificatesubject);
                    Console.WriteLine("    Certificate Serial Number       : " + ca.Properties.certificateserialnumber);
                    Console.WriteLine("    Certificate Validity Start      : " + ca.Properties.certificatevaliditystart);
                    Console.WriteLine("    Certificate Validity End        : " + ca.Properties.certificatevalidityend);
                    Console.WriteLine("    CA Permissions                  : ");
                    Console.WriteLine("         Enrollment Rights          : ");

                    foreach(string principal in GetCARights("Enroll"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("         Object Control Permissions : ");

                    Console.WriteLine("             ManageCA               : ");

                    foreach (string principal in GetCARights("ManageCA"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             ManageCertificates     : ");

                    foreach (string principal in GetCARights("ManageCertificates"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             WriteDacl              : ");

                    foreach (string principal in GetCARights("WriteDacl"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             WriteOwner             : ");

                    foreach (string principal in GetCARights("WriteOwner"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             WriteProperty          : ");

                    foreach (string principal in GetCARights("WriteProperty"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine();
                }
            }

            Console.WriteLine($"[*] Available Certificates Templates\n");

            foreach (ADObject pkiObject in pkiObjects)
            {
                if (pkiObject.Class == "pkicertificatetemplate")
                {
                    CARights.Clear();

                    CATemplate caTemplate = caParser.ParseCATemplate(pkiObject, adwsConnection.DomainName);

                    if(vulnerable)
                    {
                        if (!caTemplate.Properties.enrolleesuppliessubject && !caTemplate.Properties.clientauthentication)
                        {
                            continue;
                        }
                    }

                    if(enrolleeSuppliesSubject)
                    {
                        if (!caTemplate.Properties.enrolleesuppliessubject)
                        {
                            continue;
                        }
                    }

                    if (clientAuth)
                    {
                        if (!caTemplate.Properties.clientauthentication)
                        {
                            continue;
                        }
                    }

                    IEnumerator aces = caTemplate.Aces.GetEnumerator();
                    while (aces.MoveNext())
                    {
                        if (((Ace)aces.Current).RightName == "Certificate-Enrollment" || ((Ace)aces.Current).RightName == "Certificate-AutoEnrollment")
                        {
                            AddCARights("Enroll", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteDacl")
                        {
                            AddCARights("WriteDacl", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteOwner")
                        {
                            AddCARights("WriteOwner", ((Ace)aces.Current).Principal);
                        }

                        if (((Ace)aces.Current).RightName == "WriteProperty")
                        {
                            AddCARights("WriteProperty", ((Ace)aces.Current).Principal);
                        }
                    }

                    Console.Write("    CA Name                         : ");
                    foreach (string ca in caTemplate.Properties.certificateauthorities)
                    {
                        Console.Write(ca + "  ");
                    }
                    Console.WriteLine();
                    Console.WriteLine("    Template Name                   : " + caTemplate.Properties.templatename);
                    Console.WriteLine("    Enabled                         : " + caTemplate.Properties.Enabled);
                    Console.WriteLine("    Client Authentication           : " + caTemplate.Properties.clientauthentication);
                    Console.WriteLine("    Enrollment Agent                : " + caTemplate.Properties.enrollmentagent);
                    Console.WriteLine("    Any Purpose                     : " + caTemplate.Properties.anypurpose);
                    Console.WriteLine("    Enrollee Supplies Subject       : " + caTemplate.Properties.enrolleesuppliessubject);
                    Console.Write("    pKIExtendedKeyUsage             : ");
                    foreach (var flag in caTemplate.Properties.extendedkeyusage)
                    {
                        Console.Write(flag.ToString() + "  ");
                    }
                    Console.WriteLine();
                    Console.Write("    msPKI-Certificate-Name-Flag     : ");
                    foreach (var flag in caTemplate.Properties.certificatenameflag)
                    {
                        Console.Write(flag.ToString() + "  ");
                    }
                    Console.WriteLine();
                    Console.Write("    msPkI-Enrollment-Flag           : ");
                    foreach (var flag in caTemplate.Properties.enrollmentflag)
                    {
                        Console.Write(flag.ToString() + "  ");
                    }
                    Console.WriteLine();
                    Console.Write("    msPKI-Private-Key-Flag          : ");
                    foreach (var flag in caTemplate.Properties.privatekeyflag)
                    {
                        Console.Write(flag.ToString() + "  ");
                    }
                    Console.WriteLine();
                    Console.WriteLine("    CA Permissions                  : ");
                    Console.WriteLine("         Enrollment Rights          : ");

                    foreach (string principal in GetCARights("Enroll"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("         Object Control Permissions : ");
                    Console.WriteLine("             WriteDacl              : ");

                    foreach (string principal in GetCARights("WriteDacl"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             WriteOwner             : ");

                    foreach (string principal in GetCARights("WriteOwner"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine("             WriteProperty          : ");

                    foreach (string principal in GetCARights("WriteProperty"))
                    {
                        Console.WriteLine("                                    : " + principal);
                    }

                    Console.WriteLine();
                }
            }
        }

        internal static void AddCARights(string right, string principal)
        {
            if (!CARights.ContainsKey(right))
                CARights.Add(right, new List<string>());
            CARights[right].Add(principal);

        }

        internal static List<string> GetCARights(string right)
        {
            if (CARights.ContainsKey(right))
                return CARights[right].Distinct().ToList();
            else
                return new List<string>();
        }

        public void ResultOutput(object parseResult)
        {

        }
    }
}
