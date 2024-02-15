using SharpADWS.ADWS;
using SharpADWS.Methods.ADCS;
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace SharpADWS.Methods.ACL
{
    internal class ACLParser
    {
        private string ObjectType = null;
        private string ObjectTypeGuid = null;
        LdapResolve ldapResolve = new LdapResolve();

        private ActiveDirectorySecurity NTSecurityDescriptor = null;
        private ADObject adObject = null;
        private string Trustees = null;
        private string Rights = null;
        private int Rid = 0;
        private string OutputFormat = null;

        public ACLParser(ActiveDirectorySecurity NTSecurityDescriptor, ADObject adObject, string Trustees, string Rights, string ObjectTypeGuid, int Rid, string OutputFormat)
        {
            this.NTSecurityDescriptor = NTSecurityDescriptor;
            this.adObject = adObject;
            this.Trustees = Trustees;
            this.Rights = Rights;
            this.ObjectTypeGuid = ObjectTypeGuid;
            this.Rid = Rid;
            this.OutputFormat = OutputFormat;
        }

        public ACLParser(ActiveDirectorySecurity NTSecurityDescriptor, ADObject adObject)
        {
            this.NTSecurityDescriptor = NTSecurityDescriptor;
            this.adObject = adObject;
        }

        public void Parse()
        {
            ArrayList ADRulesList = new ArrayList();

            foreach (ActiveDirectoryAccessRule ADRule in this.NTSecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (this.Rid > 0)
                {
                    int rid = int.Parse(ADRule.IdentityReference.ToString().Substring(ADRule.IdentityReference.ToString().LastIndexOf('-') + 1));

                    if (rid < this.Rid)
                    {
                        continue;
                    }
                }

                int SeverityLevel = GetRightsSeverity(ADRule.ActiveDirectoryRights.ToString(), ADRule.AccessControlType.ToString(), ADRule.ObjectType.ToString(), ADRule.IdentityReference.ToString());
                if (SeverityLevel >= 0)
                {
                    if (!this.ldapResolve.isStandardPrincipal(ADRule.IdentityReference.ToString()))
                    {
                        SeverityLevel = 0;
                    }

                    string ObjectDN = adObject.DistinguishedName;
                    string AccessControlType = ADRule.AccessControlType.ToString();
                    string ActiveDirectoryRights = ADRule.ActiveDirectoryRights.ToString();
                    string IdentityReference = this.ldapResolve.ResolveSIDToName(ADRule.IdentityReference.ToString());
                    string IsInherited = ADRule.IsInherited.ToString();

                    // Launch filter Trustees
                    if (!String.IsNullOrEmpty(this.Trustees))
                    {
                        if (!Regex.IsMatch(IdentityReference, this.Trustees, RegexOptions.IgnoreCase))
                            continue;
                    }

                    // Launch filter Rights
                    if (!String.IsNullOrEmpty(this.Rights))
                    {
                        if (!Regex.IsMatch(ActiveDirectoryRights, this.Rights, RegexOptions.IgnoreCase))
                            continue;
                    }

                    // Launch filter Rights
                    if (!String.IsNullOrEmpty(this.ObjectTypeGuid))
                    {
                        if (!Regex.IsMatch(ADRule.ObjectType.ToString(), this.ObjectTypeGuid, RegexOptions.IgnoreCase))
                            continue;
                    }

                    Dictionary<string, string> ADRulePropertiesDict = new Dictionary<string, string>();
                    ADRulePropertiesDict.Add("ObjectDN", ObjectDN);
                    ADRulePropertiesDict.Add("AccessControlType", AccessControlType);
                    ADRulePropertiesDict.Add("ActiveDirectoryRights", ActiveDirectoryRights);
                    ADRulePropertiesDict.Add("ObjectType", this.ObjectType);
                    ADRulePropertiesDict.Add("IdentityReference", IdentityReference);
                    ADRulePropertiesDict.Add("IsInherited", IsInherited);
                    ADRulePropertiesDict.Add("SeverityLevel", SeverityLevel.ToString());

                    ADRulesList.Add(ADRulePropertiesDict);
                }
            }

            OutputUtils.FormatOutput(ADRulesList, OutputFormat);
        }


        public IEnumerable<Ace> ParsePKIAcl()
        {
            ArrayList ADRulesList = new ArrayList();

            foreach (ActiveDirectoryAccessRule ADRule in this.NTSecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                string rightName = null;

                string IdentityReference = this.ldapResolve.ResolveSIDToName(ADRule.IdentityReference.ToString());

                var certificationAuthorityRights = (CertificationAuthorityRights)ADRule.ActiveDirectoryRights;
                if (((certificationAuthorityRights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                {
                    yield return new Ace
                    {
                        RightName = "ManageCA",
                        Principal = IdentityReference,
                    };
                }

                if (((certificationAuthorityRights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                {
                    yield return new Ace
                    {
                        RightName = "ManageCertificates",
                        Principal = IdentityReference,
                    };
                }
                if (((certificationAuthorityRights & CertificationAuthorityRights.Auditor) == CertificationAuthorityRights.Auditor))
                {
                    yield return new Ace
                    {
                        RightName = "Auditor",
                        Principal = IdentityReference,
                    };
                }
                if (((certificationAuthorityRights & CertificationAuthorityRights.Operator) == CertificationAuthorityRights.Operator))
                {
                    yield return new Ace
                    {
                        RightName = "Operator",
                        Principal = IdentityReference,
                    };
                }

                if (ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    switch (ADRule.ObjectType.ToString())
                    {
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                            rightName = "Certificate-Enrollment";
                            break;
                        case "a05b8cc2-17bc-4802-a710-e7c15ab866a2":
                            rightName = "Certificate-AutoEnrollment";
                            break;
                    }

                    yield return new Ace
                    {
                        RightName = rightName,
                        Principal = IdentityReference,
                    };
                }

                //GenericAll applies to every object
                if (ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    yield return new Ace
                    {
                        RightName = "GenericAll",
                        Principal = IdentityReference,
                    };
                }
                //WriteDACL and WriteOwner are always useful no matter what the object type is as well because they enable all other attacks
                if (ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    yield return new Ace
                    {
                        RightName = "WriteDacl",
                        Principal = IdentityReference,
                    };
                }

                if (ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    yield return new Ace
                    {
                        RightName = "WriteOwner",
                        Principal = IdentityReference,
                    };
                }

                if (ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericWrite) || ADRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if(ADRule.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000")
                    {
                        yield return new Ace
                        {
                            RightName = "WriteProperty",
                            Principal = IdentityReference,
                        };
                    }
                }
            }
        }

        private int GetRightsSeverity(string ActiveDirectoryRights, string AccessControlType, string ObjectTypeGuid, string IdentityReference)
        {
            int SeverityLevel = -1;

            if (Regex.IsMatch(ActiveDirectoryRights, @"(GenericExecute)"))
            {
                if (AccessControlType == "Allow")
                {
                    switch (ObjectTypeGuid.ToLower())
                    {
                        // ms-Mcs-AdmPwd
                        case "2537b2be-3ce2-459e-a86a-b7949c1d361c":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        default:
                            break;
                    }
                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(CreateChild)"))
            {
                if (AccessControlType == "Allow")
                {
                    this.ObjectType = "All";
                    SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                }
                    
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(GenericAll)|(GenericWrite)|(WriteDacl)|(WriteOwner)"))
            {
                if (AccessControlType == "Allow")
                {
                    this.ObjectType = "All";
                    SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(WriteProperty)"))
            {
                if (AccessControlType == "Allow")
                {
                    if (adObject.Class == "user" || adObject.Class == "computer")
                    {
                        switch (ObjectTypeGuid)
                        {
                            case "00000000-0000-0000-0000-000000000000":
                                this.ObjectType = "All";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // ms-DS-Supported-Encryption-Types
                            case "20119867-1d04-4ab7-9371-cfc3d5df0afd":
                                this.ObjectType = "msDS-SupportedEncryptionTypes";
                                SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                                break;
                            // User-Account-Control
                            case "bf967a68-0de6-11d0-a285-00aa003049e2":
                                this.ObjectType = "userAccountControls";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // Service-Principal-Name
                            case "f3a64788-5306-11d1-a9c5-0000f80367c1":
                                this.ObjectType = "servicePrincipalName";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            //  Is-Member-Of-DL
                            case "bf967991-0de6-11d0-a285-00aa003049e2":
                                this.ObjectType = "memberOf";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // Primary-Group-ID
                            case "bf967a00-0de6-11d0-a285-00aa003049e2":
                                this.ObjectType = "primaryGroupID";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // SID-History
                            case "17eb4278-d167-11d0-b002-0000f80367c1":
                                this.ObjectType = "sIDHistory";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
                            case "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79":
                                this.ObjectType = "msDS-AllowedToActOnBehalfOfOtherIdentity";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // ms-DS-Key-Credential-Link
                            case "5b47d60f-6090-40b2-9f37-2a4de88f3063":
                                this.ObjectType = "msDS-KeyCredentialLink";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // PKI-Extended-Key-Usage
                            case "18976af6-3b9e-11d2-90cc-00c04fd91ab1":
                                this.ObjectType = "pKIExtendedKeyUsage";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // ms-PKI-Enrollment-Flag
                            case "d15ef7d8-f226-46db-ae79-b34e560bd12c":
                                this.ObjectType = "msPKI-Enrollment-Flag";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // ms-PKI-Certificate-Name-Flag
                            case "ea1dddc4-60ff-416e-8cc0-17cee534bce7":
                                this.ObjectType = "msPKI-Certificate-Name-Flag";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // DNS-Host-Name
                            case "72e39547-7b18-11d1-adef-00c04fd8d5cd":
                                this.ObjectType = "dNSHostName";
                                SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                                break;
                            default:
                                break;
                        }
                    }
                    else if (adObject.Class == "domaindns")
                    {
                        switch (ObjectTypeGuid)
                        {
                            case "00000000-0000-0000-0000-000000000000":
                                this.ObjectType = "All";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // MS-DS-Machine-Account-Quota
                            case "d064fb68-1480-11d3-91c1-0000f87a57d4":
                                this.ObjectType = "ms-DS-MachineAccountQuota";
                                SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                                break;
                            default:
                                break;
                        }
                    }
                    else if (adObject.Class == "group")
                    {
                        switch (ObjectTypeGuid)
                        {
                            case "00000000-0000-0000-0000-000000000000":
                                this.ObjectType = "All";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // member
                            case "bf9679c0-0de6-11d0-a285-00aa003049e2":
                                this.ObjectType = "member";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            default:
                                break; 
                        }
                    }
                    else if (adObject.Class == "grouppolicycontainer")
                    {
                        switch (ObjectTypeGuid)
                        {
                            case "00000000-0000-0000-0000-000000000000":
                                this.ObjectType = "All";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            // GPC-File-Sys-path
                            case "f30e3bc1-9ff0-11d1-b603-0000f80367c1":
                                this.ObjectType = "gPCFileSysPath";
                                SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                                break;
                            default:
                                break;
                        }
                    }

                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(ExtendedRight)"))
            {
                if (AccessControlType == "Allow")
                {
                    switch (ObjectTypeGuid)
                    {
                        case "00000000-0000-0000-0000-000000000000":
                            this.ObjectType = "All";
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        case "ab721a52-1e2f-11d0-9819-00aa0040529b":
                            this.ObjectType = "Domain-Administer-Server";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "00299570-246d-11d0-a768-00aa006e0529":
                            this.ObjectType = "User-Force-Change-Password";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "4c164200-20c0-11d0-a768-00aa006e0529":
                            this.ObjectType = "User-Account-Restrictions";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "bc0ac240-79a9-11d0-9020-00c04fc2d4cf":
                            this.ObjectType = "Membership";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                            this.ObjectType = "DS-Replication-Get-Changes";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2":
                            this.ObjectType = "DS-Replication-Synchronize";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2":
                            this.ObjectType = "DS-Replication-Manage-Topology";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "014bf69c-7b3b-11d1-85f6-08002be74fab":
                            this.ObjectType = "Change-Domain-Master";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "9923a32a-3607-11d2-b9be-0000f87a36b2":
                            this.ObjectType = "DS-Install-Replica";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                            this.ObjectType = "Certificate-Enrollment";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "bf9679c0-0de6-11d0-a285-00aa003049e2":
                            this.ObjectType = "Self-Membership";
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        case "72e39547-7b18-11d1-adef-00c04fd8d5cd":
                            this.ObjectType = "Validated-DNS-Host-Name";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "f3a64788-5306-11d1-a9c5-0000f80367c1":
                            this.ObjectType = "Validated-SPN";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "91d67418-0135-4acc-8d79-c08e857cfbec":
                            this.ObjectType = "SAM-Enumerate-Entire-Domain";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                            this.ObjectType = "DS-Replication-Get-Changes-All";
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        case "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2":
                            this.ObjectType = "Read-Only-Replication-Secret-Synchronization";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "89e95b76-444d-4c62-991a-0facbeda640c":
                            this.ObjectType = "DS-Replication-Get-Changes-In-Filtered-Set";
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        case "80863791-dbe9-4eb8-837e-7f0ab55d9ac7":
                            this.ObjectType = "Validated-MS-DS-Additional-DNS-Host-Name";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "a05b8cc2-17bc-4802-a710-e7c15ab866a2":
                            this.ObjectType = "Certificate-AutoEnrollment";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        case "4125c71f-7fac-4ff0-bcb7-f09a41325286":
                            this.ObjectType = "DS-Set-Owner";
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        default:
                            break;
                    }
                }
            }

            return SeverityLevel;
        }
    }
}
