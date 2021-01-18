using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomFS
{
    public class File
    {
		public string name { get; }
		public bool isDir { get; }
		public File parentDir;
		public DateTime dateCreated;
		//public BTree directoryContents { get; } //used only for directories
		public byte[] data; //null if isDir == true
							//Permissions perms;

		private static readonly int minimumDegree = 256;
		public File(string name, File parentDir, bool isDir)
        {
			this.name = name;
			this.isDir = isDir;
			this.parentDir = parentDir;

			//if (isDir == true)
				//directoryContents = new BTree();
        }

		public int CompareTo(object val)
        {
			//directories should be "greater" than files
			File file = (File)val;
			bool bothDirectories = (isDir == true) && (file.isDir == true);
			if (bothDirectories)
				return name.CompareTo(file.name);
			else if ((isDir == true) && (file.isDir == false))
				return 1;
			else if ((isDir == false) && (file.isDir == true))
				return -1;
			return name.CompareTo(file.name);
        }

        public override string ToString()
        {
			return name;
        }
    }
}
