/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Utils used by the project, including result output, threat rating, etc
*/
using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SharpADWS
{
    internal class OutputUtils
    {
        static bool Verbose;
        static string ObjectDN;
        static string AccessControlType;
        static string ActiveDirectoryRights;
        static string ObjectType;
        static string IdentityReference;
        static string IsInherited;

        static int SeverityLevel;
        static string SeverityLevelString;

        static ArrayList ADRulesList;
        public static void FormatOutput(ArrayList rulesList, string outputFormat)
        {
            ADRulesList = rulesList;

            switch (outputFormat)
            {
                /*
                case "CSV":
                    CsvOutput();
                    break;
                case "HTML":
                    HtmlOutput();
                    break;
                */
                default:
                    DefaultOutput();
                    break;
            }

        }

        private static void RightsSeverityFree()
        {
            SeverityLevel = 0;
        }

        private static void SelectOutputColor(int severityLevel)
        {
            switch (severityLevel)
            {
                case 0:
					SeverityLevelString = "Info";
                    Console.ForegroundColor = ConsoleColor.White;
                    break;
                case 1:
                    SeverityLevelString = "Warning";
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                case 2:
                    SeverityLevelString = "High";
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case 3:
                    SeverityLevelString = "Critical";
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                default:
                    SeverityLevelString = "Info";
                    Console.ForegroundColor = ConsoleColor.White;
                    break;
            }
        }


        private static void DefaultOutput()
        {
            if (Verbose) Console.WriteLine($"[*] Generate a raw report of the results.\n");

            foreach (Dictionary<string, string> ADRulePropertiesDict in ADRulesList)
            {
                
                ObjectDN = ADRulePropertiesDict["ObjectDN"];
                AccessControlType = ADRulePropertiesDict["AccessControlType"];
                ActiveDirectoryRights = ADRulePropertiesDict["ActiveDirectoryRights"];
                ObjectType = ADRulePropertiesDict["ObjectType"];
                IdentityReference = ADRulePropertiesDict["IdentityReference"];
                IsInherited = ADRulePropertiesDict["IsInherited"];
				SeverityLevel = Convert.ToInt32(ADRulePropertiesDict["SeverityLevel"]);
				
                SelectOutputColor(SeverityLevel);

                Console.WriteLine(" Severity ".PadRight(23, ' ') + ": " + SeverityLevelString);
                Console.WriteLine(" ObjectDN ".PadRight(23, ' ') + ": " + ObjectDN);
                Console.WriteLine(" AccessControlType ".PadRight(23, ' ') + ": " + AccessControlType);
                Console.WriteLine(" ActiveDirectoryRights ".PadRight(23, ' ') + ": " + ActiveDirectoryRights);
				Console.WriteLine(" ObjectType ".PadRight(23, ' ') + ": " + ObjectType);
                Console.WriteLine(" Trustee ".PadRight(23, ' ') + ": " + IdentityReference);
                Console.WriteLine(" IsInherited ".PadRight(23, ' ') + ": " + IsInherited);

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine();

                RightsSeverityFree();
            }
        }
    }
}
