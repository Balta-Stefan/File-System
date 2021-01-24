using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using DokanNet;

namespace CustomFS
{
    class Program
    {
        static void Main(string[] args)
        {
            Stream stream = null;
            try
            {
                IFormatter formatter = new BinaryFormatter();
                stream = new FileStream("Filesystem tree.bin", System.IO.FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
                File obj = (File)formatter.Deserialize(stream);
                stream.Close();
                new CustomFileSystem("Y:", obj).Mount(@"Y:\", DokanOptions.DebugMode | DokanOptions.StderrOutput);

            }
            catch (System.IO.FileNotFoundException exception)
            {
                if(stream != null)
                    stream.Close();
                new CustomFileSystem("Y:").Mount(@"Y:\", DokanOptions.DebugMode | DokanOptions.StderrOutput);
            }
        }
    }
}
