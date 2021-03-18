using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CustomFS.CryptoUtilities;

namespace CustomFS
{
    [Serializable]
    class Filesystem
    {
        // potrebno je implementirati i dijeljenje fajlova sa drugim korisnicima tako da samo taj korisnik moze procitati taj fajl.
        // potrebno je da korisnik moze izmijeniti sadrzaj txt fajla
        // potrebno je da korisnik moze stvoriti novi txt fajl i staviti pocetni sadrzaj u njega

        // The user will have to manually move the file from the virtual upload folder to whenever he wants (inside virtual file system).


        private readonly File root;
        private readonly File uploadFolder;
        [NonSerialized] private File currentFolder;
        public static readonly string uploadFolderName = "upload";
        public static readonly string downloadFolderName = "download";


        [NonSerialized] private byte[] encryptionKey;
        [NonSerialized] private readonly integrityHashAlgorithm hashingAlgorithm;
        [NonSerialized] private readonly encryptionAlgorithms encryptionAlgorithm;
        [NonSerialized] private readonly AsymmetricCipherKeyPair keyPair;
        [NonSerialized] private readonly Queue<string> messageQueue = new Queue<string>();

        private readonly List<File> requiresEncryption = new List<File>();
        public Filesystem(byte[] encryptionKey, integrityHashAlgorithm hashingAlgorithm, encryptionAlgorithms encryptionAlgorithm, AsymmetricCipherKeyPair keyPair, Filesystem oldFS = null)
        {
            this.encryptionKey = encryptionKey;
            this.hashingAlgorithm = hashingAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.keyPair = keyPair;

            if (Directory.Exists(uploadFolderName) == false)
                Directory.CreateDirectory(uploadFolderName);
            if (Directory.Exists(downloadFolderName) == false)
                Directory.CreateDirectory(downloadFolderName);

            if (oldFS == null)
            {
                currentFolder = root = new File(Path.DirectorySeparatorChar.ToString(), null, true, DateTime.Now);
                uploadFolder = new File(uploadFolderName, root, true, DateTime.Now);
                root.directoryContents.insert(uploadFolder);

                uploadFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
                root.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            }
            else
                currentFolder = root = oldFS.root;
        }

        public Queue<string> getMessages()
        {
            Queue<string> temp = new Queue<string>(messageQueue);
            messageQueue.Clear();
            return temp;
        }

        /// <summary>
        /// Creates the wanted file in temp folder.
        /// </summary>
        /// <param name="parentDir">Parent folder.</param>
        /// <param name="name">Name of the wanted file.</param>
        /// <returns>The wanted file.</returns>
        public File downloadFile(string fileName, File wantedFile = null)
        {
            //File wantedFile = findFile(fileName);
            if (wantedFile == null)
                wantedFile = findFile(fileName);

            if (wantedFile == null)
                throw new Exception("Wanted file doesn't exist.");

            // first decrypt the file
            wantedFile.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);

            if (wantedFile == null || wantedFile.isDir == true)
                return null;

            if (Directory.Exists(downloadFolderName) == false)
                Directory.CreateDirectory(downloadFolderName);

            // create the file
            using (MemoryStream stream = new MemoryStream(wantedFile.metadata.data))
            {
                using (FileStream file = new FileStream(downloadFolderName + Path.DirectorySeparatorChar + wantedFile.name, FileMode.Create, System.IO.FileAccess.Write))
                    stream.CopyTo(file);
            }

            return wantedFile;
        }
        /// <summary>
        /// Upload the file specified by the given file name.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <returns>False if specified file doesn't exist or if it specifies a folder.True if file upload is successful.</returns>
        public void uploadFile(string fileName)
        {
            if (System.IO.File.Exists(uploadFolderName + Path.DirectorySeparatorChar + fileName) == false)
                throw new Exception("Specified file doesn't exist.");
            if (Directory.Exists(uploadFolderName + Path.DirectorySeparatorChar + fileName) == true)
                throw new Exception("Specified file name is a directory.");


            if (Directory.Exists(uploadFolderName) == false)
                Directory.CreateDirectory(uploadFolderName);
            // serialize the file
            using (MemoryStream fileStream = loadFile(uploadFolderName + Path.DirectorySeparatorChar + fileName))
            {
                // Encrypt and sign the file.
                File newFile = new File(fileName, uploadFolder, false, DateTime.Now);
                newFile.metadata.data = fileStream.ToArray();

                newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);

                uploadFolder.directoryContents.insert(newFile);
                uploadFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            }
        }

        private MemoryStream loadFile(string path)
        {
            MemoryStream inMemoryCopy = new MemoryStream();
            using (FileStream fs = System.IO.File.OpenRead(path))
            {
                fs.CopyTo(inMemoryCopy);
            }
            inMemoryCopy.Position = 0;

            return inMemoryCopy;
        }

        /*
        /// <summary>
        /// Creates a new file.
        /// </summary>
        /// <returns>False if the file already exists.True if file creation is successful.</returns>
        public bool addFile(string name, File parentDir, bool isDir)
        {
            //File newFile = new File(path, parentDir, isDir, DateTime.Now);
            // check if the file exists
            if(parentDir.directoryContents.search(name) != null)
                return false;

            File newFile = new File(name, parentDir, isDir, DateTime.Now);
            parentDir.directoryContents.insert(newFile);

            requiresEncryption.Add(newFile);
            requiresEncryption.Add(parentDir);

            return true;
        }*/

        public bool shareWith(string userName, File file)
        {
            // to do

            return true;
        }

        public File findFile(string path)
        {
            // parse the paths
            string[] source = path.Split(Path.DirectorySeparatorChar);

            // if a path begins with a slash, treat it as absolute path
            // else, treat it as relative path such that the first element is the name of a file or folder in the current folder.
            File wantedFile = null;
            File currentPath;

            if (source[0] == " ")
                currentPath = root;// absolute path
            else
                currentPath = currentFolder; // relative path


            int i = 0;
            for (; i < source.Length - 1; i++)
            {
                try
                {
                    currentPath.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
                }
                catch(Exception e)
                {
                    messageQueue.Enqueue(e.Message);
                }
                currentPath = currentPath.directoryContents.search(source[i]);
                if (currentPath == null || currentPath.isDir == false)
                    return null;
            }
            if (i < source.Length)
            {
                try
                {
                    currentPath.decrypt(encryptionKey, keyPair, hashingAlgorithm, encryptionAlgorithm);
                }
                catch (Exception e)
                {
                    messageQueue.Enqueue(e.Message);
                }
                wantedFile = currentPath.directoryContents.search(source[i]); // this is either a directory or a file, everything before this was a directory.
            }

            return wantedFile;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourcePath"></param>
        /// <param name="destinationPath"></param>
        /// <exception cref="Exception">If moving isn't successful.</exception>
        /// <returns></returns>
        public bool move(string sourcePath, string destinationPath)
        {
            File sourceFile = findFile(sourcePath);
            if (sourceFile == null)
                throw new Exception("Source file doesn't exist");

            File destinationFile = findFile(destinationPath);
            if (destinationFile == null)
                throw new Exception("Destination file doesn't exist");

            // check if such file already exists at the destination
            string fileName = Path.GetFileName(sourcePath);
            if (destinationFile.isDir == false)
                throw new Exception("Destination isn't a folder!");

            if (destinationFile.directoryContents.search(fileName) != null)
                throw new Exception("File already exists!");

            sourceFile.parentDir.directoryContents.remove(sourceFile); // remove the file from the old location
            sourceFile.changeParentDir(destinationFile);
            //sourceFile.parentDir = destinationFile;
            destinationFile.directoryContents.insert(sourceFile);

            sourceFile.parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            sourceFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            destinationFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);

            return true;
        }

        /// <summary>
        /// Changed current (working) directory.
        /// </summary>
        /// <param name="dirName">Path to the new directory.</param>
        /// <returns>True if the operation is successful, false otherwise.</returns>
        public bool changeDirectory(string dirName)
        {
            if(dirName.Equals(".."))
            {
                if(currentFolder.parentDir != null)
                    currentFolder = currentFolder.parentDir;
                return true;
            }
            File newDir = findFile(dirName);

            if (newDir == null)
                return false;
            if (newDir.isDir == false)
                return false;

            currentFolder = newDir;
            return true;
        }
   
        public bool removeFile(string path)
        {
            File toRemove = findFile(path);

            if (toRemove == null)
                return false;

            toRemove.parentDir.directoryContents.remove(toRemove);
            toRemove.parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            requiresEncryption.Add(toRemove.parentDir);

            return true;
        }
    
        private File findParent(string path)
        {
            string dirName = Path.GetFileName(path);
            if(path.IndexOf(Path.DirectorySeparatorChar) == -1)
                return root; // this will be a problem when dealing with relative paths
            
            int toRemoveLength = 1 + dirName.Length; // 1 is added because of path separator (slash)

            path = path.Remove(path.Length - toRemoveLength);

            File parentDir = findFile(path);

            return parentDir;
        }

        /// <param name="path">Directory name or path (absolute/relative).</param>
        /// <returns>True for success, false otherwise.</returns>
        public void makeDirectory(string path)
        {
            File parentDir = findParent(path);
            string dirName = Path.GetFileName(path);

            if (parentDir == null)
                throw new Exception("Parent doesn't exist.");
            if (parentDir.isDir == false)
                throw new Exception("Parent isn't a directory.");

            File newDir = new File(dirName, parentDir, true, DateTime.Now);
            parentDir.directoryContents.insert(newDir);

            newDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            parentDir.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
        }

        /// <summary>
        /// Create text file in the working directory.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="contents"></param>
        public void makeTextFile(string fileName, string contents)
        {
            if(fileName.EndsWith(".txt") == false)
                fileName += ".txt";

            if (currentFolder.directoryContents.search(fileName) != null)
                throw new Exception("File already exists");

            File newFile = new File(fileName, currentFolder, false, DateTime.Now);
            newFile.metadata.data = Encoding.UTF8.GetBytes(contents);

            currentFolder.directoryContents.insert(newFile);

            currentFolder.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            newFile.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);
            //requiresEncryption.Add(parentDir);
            //requiresEncryption.Add(newFile);
        }


        public void encryptFileSystem()
        {
            foreach (File f in requiresEncryption)
                f.encrypt(encryptionKey, CryptoUtilities.getIVlength(encryptionAlgorithm), keyPair, hashingAlgorithm, encryptionAlgorithm);

            requiresEncryption.Clear();
        }

        public List<File> listWorkingDirectory()
        {
            List<File> files;
            currentFolder.directoryContents.traverse(out files);

            return files;
        }

        public string currentPath()
        {
            return currentFolder.metadata.absolutePath;
        }
    }
}
