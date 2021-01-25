using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomFS
{
	[Serializable]
    public class File
    {
		public string name { get; private set; }
		public bool isDir { get; }
		public File parentDir;
		public string absoluteParentPath;
		public DateTime dateCreated;
		public BTree directoryContents { get; } //used only for directories
		public byte[] data; //null if isDir == true
							//Permissions perms;
		public long endOfFile;
		public bool alreadyWritten = false;

		public File(string name, File parentDir, bool isDir)
        {
			this.name = name;
			this.isDir = isDir;
			this.parentDir = parentDir;

			if (isDir == true)
				directoryContents = new BTree();
			else
				data = new byte[0];
        }
		public bool changeName(string newName)
        {
			name = newName;
			return true;
        }
		public int CompareTo(object val)
        {
			//directories should be "greater" than files
			File file = (File)val;
			/*bool bothDirectories = (isDir == true) && (file.isDir == true);
			if (bothDirectories)
				return name.CompareTo(file.name);
			else if ((isDir == true) && (file.isDir == false))
				return 1;
			else if ((isDir == false) && (file.isDir == true))
				return -1;*/

			//both are files
			return name.CompareTo(file.name);
        }

        public override string ToString()
        {
			return name;
        }
    }
}
