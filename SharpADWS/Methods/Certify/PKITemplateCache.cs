using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpADWS.Methods.ADCS
{
    public static class PKITemplateCache
    {
        private static Dictionary<string, List<string>> TemplateToCACache { get; set; }
        static PKITemplateCache()
        {
            TemplateToCACache = new Dictionary<string, List<string>>();
        }


        internal static void AddTemplateCA(string template, string CA)
        {
            if (!TemplateToCACache.ContainsKey(template))
                TemplateToCACache.Add(template, new List<string>());
            TemplateToCACache[template].Add(CA);

        }

        internal static List<string> GetTemplateCA(string template)
        {
            if (TemplateToCACache.ContainsKey(template))
                return TemplateToCACache[template];
            else
                return new List<string>();
        }
    }
}
