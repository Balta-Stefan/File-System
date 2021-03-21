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
	/// <summary>
	/// Thrown when trying to work with a file that is encrypted.
	/// </summary>
	public class FileEncrypted : Exception
    {
		public FileEncrypted() : base("The file is encrypted.Decrypt it before performing operations on it.") { }
    }
	public class InvalidSignature : Exception
    {
		public InvalidSignature(string fileName) : base("Invalid signature: " + fileName) { }
    }
	public class DataCorruption : Exception
    {
		public DataCorruption(string fileName) : base("Data corrupted: " + fileName) { }
    }

	[Serializable]
	public class File
	{
		[Serializable]
		public class FileMetadata
		{
			// the problem here is that parentDir and directoryContents aren't included in the integrity check.Fix this in the future.

			public string name;
			public readonly bool isDir;
			public string absolutePath;
			public DateTime dateCreated { get; private set; }
			public byte[] data; //null if isDir == true
			public string parentAbsolutePath;

			//public bool alreadyWritten = false;

			/// <summary>
			/// parentDir must be decrypted!.
			/// </summary>
			public FileMetadata(string name, bool isDir, DateTime creationTime, File parentDir)
			{
				this.name = name;
				this.isDir = isDir;
				dateCreated = creationTime;
				if(parentDir != null)
                {
					parentAbsolutePath = parentDir.metadata.absolutePath;
					if (parentAbsolutePath.Equals(Path.DirectorySeparatorChar.ToString()) == false)
						absolutePath = parentDir.metadata.absolutePath + Path.DirectorySeparatorChar + name;
					else
						absolutePath = Path.DirectorySeparatorChar + name; // parent is the root
				}
				else
                {
					// for root folder
					absolutePath = name;// Path.DirectorySeparatorChar.ToString();
					parentAbsolutePath = "";
                }
			}
		}

		[Serializable]
		public class SharedFileMetadata
        {
			// IV, encrypted data and signed checksum will be in the outer class (File)
			public readonly CryptoUtilities.encryptionAlgorithms encryptionAlgorithm;
			public readonly CryptoUtilities.integrityHashAlgorithm hashingAlgorithm;
			public readonly byte[] encryptedSymmetricKey; // encrypted with the receiver's public key

			public SharedFileMetadata(CryptoUtilities.encryptionAlgorithms encryptionAlgorithm, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, byte[] encryptedSymmetricKey)
            {
				this.encryptionAlgorithm = encryptionAlgorithm;
				this.encryptedSymmetricKey = encryptedSymmetricKey;
				this.hashingAlgorithm = hashingAlgorithm;
			}
		}

		[NonSerialized] private FileMetadata metadata = null; // { get; private set;  }
		public SharedFileMetadata sharedMetadata = null;

		//[NonSerialized] public bool modified = false; // there's no need to encrypt and sign a file that hasn't been modified.If true, encrypt and sign the file.
		public string name { get; private set; }
		public bool isDir { get; }

		public File parentDir;
		private BTree directoryContents { get; } //used only for directories

		// cryptography related
		public byte[] IV;
		public byte[] encryptedData;
		public byte[] signedChecksum; // encryptedData is hashed and then signed
		public byte[] folderContentsSignature; // used to verify the integrity of a folder

		[NonSerialized] public bool requiresEncryption = true;

		// files: serialize metadata, convert it into byte array and encrypt it.The same byte array will also be signed with the RSA key.

		// folders: Nothing will be encrypted.Only integrity has to be taken care of.
		// call the traverse method of the BTree with a List passed as argument.This list will contain all the files and folders contained in that BTree.
		// then, make hash of all the metaData references WITHOUT THE DATA BYTE ARRAY inside the File references in that list.
		// finally, sign that hash.

		// when the file system is unmounted, all decrypted data has to be encrypted and all checksums have to be recalculated and signed.

		// when files are modified (not counting the data byte array), checksum of the parent folder must be recalculated.
		// when a folder is opened, its integrity must be verified.It wouldn't make sense to decrypt all the files and folders.Some metadata has to be moved out of the FileMetadata into the File.
		// that metadata is the filename and isDir flag.


		public void shareTheFile(AsymmetricKeyParameter publicKey, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm)
        {
			// generate an IV
			int IVlength = CryptoUtilities.getIVlength(encryptionAlgorithm);

			// generate a symmetric encryption key
			byte[] key = new byte[CryptoUtilities.defaultSymmetricKeySize];
			CryptoUtilities.getRandomData(key);
			byte[] encryptedKey = CryptoUtilities.RSAOAEP(true, publicKey, key);

			sharedMetadata = new SharedFileMetadata(encryptionAlgorithm, hashingAlgorithm, encryptedKey);

			requiresEncryption = true;
			encrypt(key, IVlength, publicKey, hashingAlgorithm, encryptionAlgorithm);
        }

		/// <summary>
		/// Only for directories.Used to insert new file to this directory.
		/// </summary>
		/// <param name="file"></param>
		public void insertNewFile(File file)
        {
			directoryContents.insert(file);
			requiresEncryption = true;
        }

		public File searchDirectory(string file)
        {
			return directoryContents.search(file);
        }

		public void deleteFile(File file)
        {
			directoryContents.remove(file);
			requiresEncryption = true;
        }

		public void traverseDirectory(out List<File> list)
        {
			directoryContents.traverse(out list);
        }

		/// <summary>
		/// Get data of this file.
		/// </summary>
		/// <remarks>Check whether the file is decrypted before calling this method.</remarks>
		/// <returns></returns>
		public byte[] getData()
        {
			if (metadata == null)
				throw new FileEncrypted();
			return (byte[])metadata.data.Clone();
        }

		/// <remarks>Check whether the file is decrypted before calling this method.</remarks>
		/// <param name="newData"></param>
		public void setData(byte[] newData)
        {
			if (metadata == null)
				throw new FileEncrypted();
			metadata.data = newData;
        }
		public string getAbsolutePath()
        {
			if (metadata == null)
				throw new FileEncrypted();
			return metadata.absolutePath;
        }
		public void changeParentDir(File newParent)
		{
			if (metadata == null)
				throw new FileEncrypted();
			parentDir = newParent;
			metadata.parentAbsolutePath = parentDir.metadata.absolutePath;
			metadata.absolutePath = parentDir.metadata.absolutePath + Path.DirectorySeparatorChar + name;

			requiresEncryption = true;
		}
		/*public void changeName(string newName)
		{
			name = newName;
			metadata.name = newName;
		}*/

		/// <summary>
		/// Encrypt the file or folder.
		/// </summary>
		/// <param name="encryptionKey">Key used for symmetric encryption.</param>
		/// <param name="IVlength">Length of IV in bytes.</param>
		/// <param name="key">Key used for signing.</param>
		public void encrypt(byte[] encryptionKey, int IVlength, AsymmetricKeyParameter key, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
        {
			if (requiresEncryption == false)
				return;
			requiresEncryption = false;
			// convert metadata into a byte array
			byte[] metadataBytes = null;
			serializeMetadata(ref metadataBytes);
			encryptedData = CryptoUtilities.encryptor(encryptionAlgorithm, metadataBytes, encryptionKey, ref IV, true);

			if (isDir == true)
            {
				byte[] folderContentsHash = hashFolderContents(directoryContents, hashingAlgorithm);
				CryptoUtilities.signVerify(ref folderContentsSignature, true, folderContentsHash, key, hashingAlgorithm);
			}

			CryptoUtilities.signVerify(ref signedChecksum, true, encryptedData, key, hashingAlgorithm);
        }


		public void decrypt(byte[] symmetricKey, AsymmetricCipherKeyPair keyPair, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
        {
			if (metadata != null)
				return; // already decrypted

			BinaryFormatter bf;
			if (sharedMetadata != null)
            {
				// this is a shared file.Check if it can be decrypted (if it is for this user).

				try
                {
					// the signature should be compared with the encrypted contents, but Bouncy castle throws an exception if incorrect parameters are used so signature checking seems to be redundant.

					byte[] sharedSymmetricKey = CryptoUtilities.RSAOAEP(false, keyPair.Private, sharedMetadata.encryptedSymmetricKey); // decrypt the symmetric key
					byte[] decryptedData = CryptoUtilities.encryptor(sharedMetadata.encryptionAlgorithm, encryptedData, sharedSymmetricKey, ref IV, false); // decrypt the data using the key above

					// convert the decrypted data to metadata
					bf = new BinaryFormatter();
					using (MemoryStream ms = new MemoryStream(decryptedData))
					{
						metadata = (FileMetadata)bf.Deserialize(ms);
					}
				}
				catch(Exception)
                {
					throw new Exception("This shared file is for another user.");
                }

				// does the file need to be encrypted, that is, does the signature have to be regenerated with own key?
				encrypt(symmetricKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair.Private, hashingAlgorithm, encryptionAlgorithm);

				return;
            }

			if (CryptoUtilities.signVerify(ref signedChecksum, false, encryptedData, keyPair.Public, hashingAlgorithm) == false)
				throw new InvalidSignature(name);

			
			//signedChecksum = null;

			byte[] metadataBytes = CryptoUtilities.encryptor(encryptionAlgorithm, encryptedData, symmetricKey, ref IV, false);

			bf = new BinaryFormatter();
			using (MemoryStream ms = new MemoryStream(metadataBytes))
			{
				metadata = (FileMetadata)bf.Deserialize(ms);
			}
			//IV = null;
			//encryptedData = null;
			
			if(isDir == true)
            {
				// check the integrity of folder contents
				byte[] folderContentsHash = hashFolderContents(directoryContents, hashingAlgorithm);
				if (CryptoUtilities.signVerify(ref folderContentsSignature, false, folderContentsHash, keyPair.Public, hashingAlgorithm) == false)
					throw new InvalidSignature(name);
				//folderContentsSignature = null;
            }
			if (metadata.name != name || metadata.isDir != isDir)
				throw new DataCorruption(name);
			if(parentDir != null && (metadata.parentAbsolutePath != parentDir.metadata.absolutePath))
				throw new DataCorruption(name);

		}
		/// <summary>
		/// Hashes folder metadata and File.name - File.isDir pairs.
		/// </summary>
		/// <param name="folder">Starting folder.</param>
		/// <returns>Hash of all name and isDir pairs</returns>
		private byte[] hashFolderContents(BTree folder, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm)
		{
			List<File> dirContents;
			folder.traverse(out dirContents);

			// hash name-isDir pairs of each found File reference
			byte[] isDirFlag = new byte[1];
			byte[] dataToSign = new byte[0];


			foreach (File f in dirContents)
			{
				byte[] temp = CryptoUtilities.hash(hashingAlgorithm, Encoding.UTF8.GetBytes(f.name));

				if (f.isDir == true)
					isDirFlag[0] = 1;
				else
					isDirFlag[0] = 0;

				// merge old dataToSign, temp and isDirFlag.This might not be working properly.Test it!
				byte[] temp2 = new byte[dataToSign.Length + temp.Length + isDirFlag.Length];
				Array.Copy(dataToSign, temp2, dataToSign.Length);
				Array.Copy(temp, 0, temp2, dataToSign.Length, temp.Length);
				temp2[temp2.Length - 1] = isDirFlag[0];

				dataToSign = CryptoUtilities.hash(hashingAlgorithm, temp2);
			}
			return dataToSign;
		}


		private void serializeMetadata(ref byte[] metadataBytes)
		{
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
		}

		/// <summary>
		/// parentDir must be decrypted!.
		/// </summary>
		/// <param name="parentDir">Must be decrypted before calling this method.</param>
		public File(string name, File parentDir, bool isDir, DateTime creationTime)
        {
			metadata = new FileMetadata(name, isDir, creationTime, parentDir);
			this.name = name;
			this.isDir = isDir;
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
			return name.CompareTo(file.name);
        }

        /*public override bool Equals(object obj)
        {
			if (obj is File == false)
				return false;
			File tempFile = (File)obj;
			if (parentDir != tempFile.parentDir)
				return false;
			if (name.Equals(tempFile.name) == false)
				return false;
			if (isDir != tempFile.isDir)
				return false;
			return true;
        }*/
        public override bool Equals(object obj)
        {
			if (obj is File == false)
				return false;

			File tempFile = (File)obj;
			return tempFile.metadata.absolutePath.Equals(metadata.absolutePath);
		}
        public override int GetHashCode()
        {
			return metadata.absolutePath.GetHashCode();
        }
        public override string ToString()
        {
			char fileType = (isDir == true) ? 'd' : 'f';
			return "(" + fileType + ") " + name;
		}

		/*public FileMetadata getMetadata(byte[] symmetricKey, AsymmetricCipherKeyPair keyPair, CryptoUtilities.integrityHashAlgorithm hashingAlgorithm, CryptoUtilities.encryptionAlgorithms encryptionAlgorithm)
        {
			if (decrypted == true)
				return metadata;

			decrypt(symmetricKey, keyPair, hashingAlgorithm, encryptionAlgorithm);

			return metadata;
        }*/
	}
}
