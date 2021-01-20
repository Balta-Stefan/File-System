using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DokanNet;

namespace CustomFS
{
    class Program
    {
        static void Main(string[] args)
        {
            new CustomFileSystem().Mount(@"Y:\", DokanOptions.DebugMode | DokanOptions.StderrOutput);
        }
    }
}
