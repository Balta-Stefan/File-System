using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomFS
{
    public class LoginInfo
    {
        public readonly File root;
        public readonly string cookie;
        public LoginInfo(File root, string cookie) { this.root = root;this.cookie = cookie; }
    }
}
