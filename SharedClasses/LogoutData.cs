using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedClasses
{
    [Serializable]
    public class LogoutData
    {
        public string cookie;
        public byte[] serializedRoot;

        public string message;

        public LogoutData(string message) { this.message = message; }
        public LogoutData(string cookie, byte[] serializedRoot) { this.cookie = cookie;this.serializedRoot = serializedRoot; }
    }
}
