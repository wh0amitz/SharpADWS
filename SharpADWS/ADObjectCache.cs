using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SharpADWS
{
    [Serializable]
    internal class ADObjectCache
    {
        public Dictionary<string, string> ObjectSidToNameCache = new Dictionary<string, string>();

        public ADObjectCache() { }

        public void AddCacheValue(SecurityIdentifier objectSid, string name) 
        {
            if (!this.ObjectSidToNameCache.ContainsKey(objectSid.ToString()))
            {
                this.ObjectSidToNameCache.Add(objectSid.ToString(), name);
            }
        }
    }
}
