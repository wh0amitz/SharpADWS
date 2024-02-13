using SharpADWS.ADWS;
using SharpADWS.Methods.ACL;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS.Methods.ADCS
{
    internal class CAParser
    {
        public CAParser()
        {

        }
        public CA ParseCA(ADObject adObject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
            ACLParser aclParser = new ACLParser(adObject.NTSecurityDescriptor, adObject);

            CA canode = new CA()
            {

                ObjectIdentifier = adObject.ObjectGUID.ToString(),
                Properties = new CAProperties()
                {
                    name = adObject.Name.ToUpper() + "@" + domainName.ToUpper(),
                    domain = domainName.ToUpper(),
                    highvalue = false,
                    caname = adObject.Name,
                    dnsname = adObject.DNSHostName,
                    certificateserialnumber = adObject.CACertificate[0].SerialNumber,
                    certificatesubject = adObject.CACertificate[0].Subject,
                    certificatevaliditystart = adObject.CACertificate[0].NotBefore,
                    certificatevalidityend = adObject.CACertificate[0].NotAfter,
                    type = "Enrollment Service"
                },
                Aces = aclParser.ParsePKIAcl(),
            };
            return canode;
        }

        public CATemplate ParseCATemplate(ADObject adObject, string domainName)
        {
            DateTime EpochDiff = new DateTime(1970, 1, 1);
            OidConverter _oid = new OidConverter();
            ACLParser aclParser = new ACLParser(adObject.NTSecurityDescriptor, adObject);

            CATemplate catemplate = new CATemplate()
            {

                ObjectIdentifier = adObject.ObjectGUID.ToString(),
                Properties = new CATemplateProperties()
                {
                    name = adObject.Name.ToUpper() + "@" + domainName.ToUpper(),
                    templatename = adObject.Name,
                    displayname = adObject.DisplayName,
                    certificateauthorities = PKITemplateCache.GetTemplateCA(adObject.Name),
                    Enabled = (PKITemplateCache.GetTemplateCA(adObject.Name).Count > 0),
                    certificatenameflag = ParseIntToEnum<msPKICertificateNameFlag>(adObject.MsPKICertificateNameFlag.ToString()).ToString().Split(',').Select(x => (msPKICertificateNameFlag)Enum.Parse(typeof(msPKICertificateNameFlag), x.Trim())).ToList(),
                    enrollmentflag = ParseIntToEnum<msPKIEnrollmentFlag>(adObject.MsPKIEnrollmentFlag.ToString()).ToString().Split(',').Select(x => (msPKIEnrollmentFlag)Enum.Parse(typeof(msPKIEnrollmentFlag), x.Trim())).ToList(),
                    privatekeyflag = ParseIntToEnum<msPKIPrivateKeyFlag>((adObject.MsPKIPrivateKeyFlag & 0x00FFFFFF).ToString()).ToString().Split(',').Select(x => (msPKIPrivateKeyFlag)Enum.Parse(typeof(msPKIPrivateKeyFlag), x.Trim())).ToList(),
                    extendedkeyusage = _oid.LookupOid(adObject.PKIExtendedKeyUsage),
                    validityperiod = ConvertPKIPeriod(adObject.PKIExpirationPeriod),
                    renewalperiod = ConvertPKIPeriod(adObject.PKIOverlapPeriod),
                    minimumrsakeylength = adObject.MsPKIMinimalKeySize,
                    domain = domainName.ToUpper(),
                    type = "Certificate Template"
                },
                Aces = aclParser.ParsePKIAcl(),

            };
            catemplate.Properties.clientauthentication = new[] { "Any Purpose", "Client Authentication", "Smart Card Logon", "PKINIT Client Authentication" }.Any(c => catemplate.Properties.extendedkeyusage.Contains(c));
            catemplate.Properties.anypurpose = catemplate.Properties.extendedkeyusage.Any("Any Purpose".Contains);
            catemplate.Properties.enrollmentagent = new[] { "Any Purpose", "Certificate Request Agent" }.Any(c => catemplate.Properties.extendedkeyusage.Contains(c));
            catemplate.Properties.enrolleesuppliessubject = catemplate.Properties.certificatenameflag.Contains(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
            catemplate.Properties.requiresmanagerapproval = catemplate.Properties.enrollmentflag.Contains(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
            catemplate.Properties.requireskeyarchival = catemplate.Properties.privatekeyflag.Contains(msPKIPrivateKeyFlag.REQUIRE_PRIVATE_KEY_ARCHIVAL);
            catemplate.Properties.highvalue = catemplate.Properties.Enabled && ((catemplate.Properties.enrolleesuppliessubject && !catemplate.Properties.requiresmanagerapproval && catemplate.Properties.clientauthentication) || (catemplate.Properties.enrollmentagent && !catemplate.Properties.requiresmanagerapproval));
            return catemplate;
        }


        public T ParseIntToEnum<T>(string value)
        {
            var intVal = Convert.ToInt32(value);
            var uintVal = unchecked((uint)intVal);

            return (T)Enum.Parse(typeof(T), uintVal.ToString());
        }

        private string ConvertPKIPeriod(byte[] bytes)
        {
            // ref: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if ((value % 31536000 == 0) && (value / 31536000) >= 1)
                {
                    if ((value / 31536000) == 1)
                    {
                        return "1 year";
                    }

                    return $"{value / 31536000} years";
                }
                else if ((value % 2592000 == 0) && (value / 2592000) >= 1)
                {
                    if ((value / 2592000) == 1)
                    {
                        return "1 month";
                    }
                    else
                    {
                        return $"{value / 2592000} months";
                    }
                }
                else if ((value % 604800 == 0) && (value / 604800) >= 1)
                {
                    if ((value / 604800) == 1)
                    {
                        return "1 week";
                    }
                    else
                    {
                        return $"{value / 604800} weeks";
                    }
                }
                else if ((value % 86400 == 0) && (value / 86400) >= 1)
                {
                    if ((value / 86400) == 1)
                    {
                        return "1 day";
                    }
                    else
                    {
                        return $"{value / 86400} days";
                    }
                }
                else if ((value % 3600 == 0) && (value / 3600) >= 1)
                {
                    if ((value / 3600) == 1)
                    {
                        return "1 hour";
                    }
                    else
                    {
                        return $"{value / 3600} hours";
                    }
                }
                else
                {
                    return "";
                }
            }
            catch (Exception)
            {
                return "ERROR";
            }
        }
    }
}
