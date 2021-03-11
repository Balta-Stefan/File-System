using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace CustomFS
{
	public class InvalidSignature : Exception
    {
		public InvalidSignature() : base("Invalid signature!") { }
    }

	[Serializable]
	public class File
	{
		[Serializable]
		public class FileMetadata
		{
			// the problem here is that parentDir and directoryContents aren't included in the integrity check.Fix this in the future.

			public string name;
			public bool isDir;
			public string absoluteParentPath;
			public DateTime dateCreated { get; private set; }
			public byte[] data; //null if isDir == true
			public long endOfFile;
			public bool alreadyWritten = false;

			public FileMetadata(string name, bool isDir, DateTime creationTime)
			{
				this.name = name;
				this.isDir = isDir;
				dateCreated = creationTime;
			}


		}
		public void changeName(string newName)
		{
			name = newName;
			metadata.name = newName;
		}


		[NonSerialized] public FileMetadata metadata; // { get; private set;  }

		public string name { get; private set; }
		public bool isDir { get; }

		public File parentDir;
		public BTree directoryContents { get; } //used only for directories

		// cryptography related
		public byte[] IV;
		public byte[] encryptedData;
		public byte[] signedChecksum; // encryptedData is hashed and then signed

		// files: serialize metadata, convert it into byte array and encrypt it.The same byte array will also be signed with the RSA key.

		// folders: Nothing will be encrypted.Only integrity has to be taken care of.
		// call the traverse method of the BTree with a List passed as argument.This list will contain all the files and folders contained in that BTree.
		// then, make hash of all the metaData references WITHOUT THE DATA BYTE ARRAY inside the File references in that list.
		// finally, sign that hash.

		// when the file system is unmounted, all decrypted data has to be encrypted and all checksums have to be recalculated and signed.

		// when files are modified (not counting the data byte array), checksum of the parent folder must be recalculated.
		// when a folder is opened, its integrity must be verified.It wouldn't make sense to decrypt all the files and folders.Some metadata has to be moved out of the FileMetadata into the File.
		// that metadata is the filename and isDir flag.

		/// <summary>
		/// Encrypt the file or folder.
		/// </summary>
		/// <param name="encryptionKey">Key used for symmetric encryption.</param>
		/// <param name="IVlength">Length of IV in bytes.</param>
		/// <param name="keyPair">Keypair used for signing.</param>
		public void encrypt(byte[] encryptionKey, int IVlength, AsymmetricCipherKeyPair keyPair, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
        {
			byte[] dataToSign = null;

			if(isDir == false)
            {
				// convert metadata into a byte array
				byte[] metadataBytes = null;
				using (var memoryStream = new MemoryStream())
				{
					// Serialize to memory instead of to file
					var formatter = new BinaryFormatter();
					formatter.Serialize(memoryStream, metadata);

					// This resets the memory stream position for the following read operation
					memoryStream.Seek(0, SeekOrigin.Begin);

					// Get the bytes
					metadataBytes = new byte[memoryStream.Length];
					memoryStream.Read(metadataBytes, 0, (int)memoryStream.Length);
				}

				encryptedData = CryptoUtilities.encryptor(encryptionAlgorithm, metadataBytes, encryptionKey, ref IV, true);
				dataToSign = encryptedData;
			}
			else
				dataToSign = hashFolderContents(directoryContents, hashingAlgorithm);
			

			CryptoUtilities.signVerify(ref signedChecksum, true, dataToSign, keyPair.Private, hashingAlgorithm);
        }

		public void decrypt(byte[] symmetricKey, AsymmetricCipherKeyPair keyPair, byte[] symmetricEncryptionKey, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
        {
			if(isDir == false) // only files are encrypted
            {
				if (CryptoUtilities.signVerify(ref signedChecksum, false, encryptedData, keyPair.Public, hashingAlgorithm) == false)
					throw new InvalidSignature();
				
				signedChecksum = null;

				byte[] metadataBytes = CryptoUtilities.encryptor(encryptionAlgorithm, encryptedData, symmetricKey, ref IV, false);

				BinaryFormatter bf = new BinaryFormatter();
				using (MemoryStream ms = new MemoryStream(metadataBytes))
				{
					metadata = (FileMetadata)bf.Deserialize(ms);
				}
				IV = null;
				encryptedData = null;

				if(metadata.name != name || metadata.isDir != isDir)
					throw new Exception("Data corrupted.");
			}
			else // for folders, only check their integrity.
            {
				byte[] folderContentsHash = hashFolderContents(directoryContents, hashingAlgorithm);
				if (CryptoUtilities.signVerify(ref signedChecksum, false, folderContentsHash, keyPair.Public, hashingAlgorithm) == false)
					throw new InvalidSignature();
            }
		}

		/// <summary>
		/// Hashes pairs File.name and File.isDir.
		/// </summary>
		/// <param name="folder">Starting folder.</param>
		/// <returns>Hash of all name and isDir pairs</returns>
		private byte[] hashFolderContents(BTree folder, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm)
        {
			List<File> dirContents = new List<File>();
			folder.traverse(out dirContents);

			// hash name-isDir pairs of each found File reference
			byte[] isDirFlag = new byte[1];
			byte[] dataToSign = null;
			foreach (File f in dirContents)
			{
				dataToSign = CryptoUtilities.hash(hashingAlgorithm, Encoding.UTF8.GetBytes(f.name));
				if (f.isDir == true)
					isDirFlag[0] = 1;
				else
					isDirFlag[0] = 0;

				dataToSign = CryptoUtilities.hash(hashingAlgorithm, dataToSign);
			}
			return dataToSign;
		}

		public File(string name, File parentDir, bool isDir, DateTime creationTime)
        {
			metadata = new FileMetadata(name, isDir, creationTime);
			this.name = name;
			this.isDir = isDir;

			//this.name = name;
			//this.isDir = isDir;
			this.parentDir = parentDir;

			if (isDir == true)
				directoryContents = new BTree();
			else
				metadata.data = new byte[0];
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
