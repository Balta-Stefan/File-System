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
		[Serializable]
		public class FileMetadata
        {
			public string name { get; private set; }
			public bool isDir { get; }
			public string absoluteParentPath;
			public DateTime dateCreated { get; private set; }
			[NonSerialized] public byte[] data; //null if isDir == true
			public long endOfFile;
			public bool alreadyWritten = false;

			public FileMetadata(string name, bool isDir, DateTime creationTime)
            {
				this.name = name;
				this.isDir = isDir;
				dateCreated = creationTime;
            }

			public void changeName(string newName)
            {
				name = newName;
            }
		}
		[NonSerialized] public FileMetadata metadata; // { get; private set;  }

		//public string name { get; private set; }
		//public bool isDir { get; }
		public File parentDir;
		//public string absoluteParentPath;
		//public DateTime dateCreated;
		public BTree directoryContents { get; } //used only for directories
		//public byte[] data; //null if isDir == true
						
		//public long endOfFile;
		//public bool alreadyWritten = false;

		// cryptography related
		public byte[] IV;
		public byte[] encryptedData;
		public byte[] signedChecksum;

		// files: serialize metadata, convert it into byte array and encrypt it.The same byte array will also be hashed and signed with the RSA key.

		// folders: Nothing will be encrypted.Only integrity has to be taken care of.
		// call the traverse method of the BTree with a List passed as argument.This list will contain all the files and folders contained in that BTree.
		// then, make hash of all the metaData references WITHOUT THE DATA BYTE ARRAY inside the File references in that list.
		// finally, sign that hash.

		// when the file system is unmounted, all decrypted data has to be encrypted and all checksums have to be recalculated and signed.

		// when files are modified (not counting the data byte array), checksum of the parent folder must be recalculated.
		// when a folder is opened, its integrity must be verified.It wouldn't make sense to decrypt all the files and folders.Some metadata has to be moved out of the FileMetadata into the File.
		// that metadata is the filename and isDir flag.

		public File(string name, File parentDir, bool isDir, DateTime creationTime)
        {
			metadata = new FileMetadata(name, isDir, creationTime);

			//this.name = name;
			//this.isDir = isDir;
			this.parentDir = parentDir;

			if (isDir == true)
				directoryContents = new BTree();
			else
				metadata.data = new byte[0];
        }
		public bool changeName(string newName)
        {
			metadata.changeName(newName);
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
			return metadata.name.CompareTo(file.metadata.name);
        }

        public override string ToString()
        {
			return metadata.name;
        }
    }
}
