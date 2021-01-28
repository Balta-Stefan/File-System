﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DokanNet;

namespace CustomFS
{

    /*
     * Every folder will have its own B tree.
     * When creating files and folders - find its parent.
     *      -this is accomplished by breaking the path and descending down the tree
     *      -the last string in the path is the file's (or folder's) name, the string before it is its parent
     * */


    /*
     * PROBLEMS:
     * BTree search function is not working properly because of File.CompareTo method!!!
     * BTree search function is not working properly because, to compare files and folders, we need to know if it's a file or folder.The search function doesn't take that into account because it only compares strings.
     * When adding a file to a directory, size of the parent isn't changed, fix this!
     * When a file is added to a folder, all parent folders need to have their sizes modified!
     */

    /*
     * Questions:
     * 1)When a file is being written via writeFile, how to detect when the writing has ended?
     * 
     * */


    /*
     * To do:
     * 1)Prevent file modification.
     * 
     * 
     * 
     * */

    class CustomFileSystem : IDokanOperations
    {
        private static readonly int capacity = 500*1024*1024; //500 MiB
        private long freeBytesAvailable = capacity;
        private readonly File root;
        private readonly string drivePrefix;
        private readonly string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        private readonly Mutex mutex = new Mutex();
        bool preventFileModification = true;

        public CustomFileSystem(string drivePrefix, File root)
        {
            this.drivePrefix = drivePrefix;
            this.root = root;
        }
        public CustomFileSystem(string drivePrefix)
        {
            root = new File(@"\", null, true);
            root.absoluteParentPath = "";
            this.drivePrefix = drivePrefix;
            File serializationFile = new File("serialize", root, true);
            root.directoryContents.insert(serializationFile);
            serializationFile.absoluteParentPath = @"\";
        }

        private void serializeFileSystem()
        {
            mutex.WaitOne();
            IFormatter formatter = new BinaryFormatter();
            Stream stream = new FileStream("Filesystem tree.bin", FileMode.Create, System.IO.FileAccess.Write, FileShare.None);
            formatter.Serialize(stream, root);
            stream.Close();
            mutex.ReleaseMutex();
        }
        public void Cleanup(string fileName, IDokanFileInfo info)
        {
            //This method is called only for the file that is deleted.
            //When fileName represents a folder, this method WILL NOT be called for all of its contents.It is up to the programmer to delete all contents of the folder.

            File wantedFile = findFile(fileName);
            if (info.DeleteOnClose == true)
            {
                freeBytesAvailable += (wantedFile.isDir == true) ? wantedFile.directoryContents.totalDirectorySize : wantedFile.data.Length;
                wantedFile.parentDir.directoryContents.remove(wantedFile);
            }
        }
 
        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            if (fileName.Contains("txt"))
            {
                access = DokanNet.FileAccess.None;
            }
            if (fileName.Contains(".ini")) //both desktop.ini and Desktop.ini can appear...No clue why...
                return NtStatus.Success;
            //if (fileName.Equals(@"\serialize") && access != DokanNet.FileAccess.Synchronize && access != DokanNet.FileAccess.ReadAttributes && access != DokanNet.FileAccess.GenericRead && access != (DokanNet.FileAccess.ReadAttributes | DokanNet.FileAccess.Synchronize) && access != DokanNet.FileAccess.ReadPermissions)
            if(fileName.Equals(@"\serialize"))
            {
                //there is no way to determine if a file is being opened

                //ReadAttributes | Synchronize - on right click
                //ReadPermissions - on right click
                //GenericRead - on right click
                //ReadAttributes - on right click
                //Synchronize - on right click > properties
                //ReadData | ReadAattributes | Synchronize on opening

                info.IsDirectory = true;
                if(access == (DokanNet.FileAccess.ReadData | DokanNet.FileAccess.ReadAttributes | DokanNet.FileAccess.Synchronize))
                    serializeFileSystem(); //this gets activated even when the folder isn't being opened (like when checking its context menu)
                return NtStatus.Success;
            }
            if(fileName.Contains(@"\serialize"))
            {
                //creating anything inside this folder isn't allowed
                return NtStatus.Error;
            }
            //what to do with root folder (\) and with desktop.ini?
            if(fileName.Equals(@"\"))
            {
                info.IsDirectory = true;
                return NtStatus.Success;
            }

       
            
            //when a file is first created, CreateFile will be called with mode equal to FileMode.Open
            //after that, it will be called with mode equal to FileMode.CreateNew
                //when mode is CreateNew, info.isDirectory seems to be correct.In all other cases, it isn't.
                //therefore, one folder can't hold a file and folder with the same name


            File parent = findParent(fileName);
            if (parent == null)
                return NtStatus.Error;

            File existing = parent.directoryContents.search(Path.GetFileName(fileName));

            //see if the file already exists if mode is CreateNew or Create
            if ((mode == FileMode.CreateNew || mode == FileMode.Create || mode == FileMode.OpenOrCreate) && existing != null)
                return DokanResult.AlreadyExists;



            bool fileIsDirectory = (existing == null) ? false : existing.isDir;

            if (attributes == FileAttributes.Directory || info.IsDirectory == true || fileIsDirectory)
            {
                info.IsDirectory = true;
                switch(mode)
                {
                    case FileMode.CreateNew:
                        File newFolder = new File(Path.GetFileName(fileName), parent, true);
                        string parentName = (parent.name.Equals(@"\")) ? "" : parent.name;
                        newFolder.absoluteParentPath = parent.absoluteParentPath + @"\" + parentName;
                        parent.directoryContents.insert(newFolder);
                        newFolder.dateCreated = DateTime.Now;
                        break;
                }
            }
            else
            {
                info.IsDirectory = false;
                
                switch(mode)
                {
                    case FileMode.CreateNew:
                        //create file
                        File newFile = new File(Path.GetFileName(fileName), parent, false);
                        //newFile.absoluteParentPath = parent.absoluteParentPath + @"\" + parent.name;
                        parent.directoryContents.insert(newFile);
                        newFile.dateCreated = DateTime.Now;
                        break;
                }
            }

            return NtStatus.Success;
        }

        public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info)
        {
            //If fileName represents a folder, this method (or DeleteFile for files) WILL NOT be called for all of the fileName's contents.
            if (fileName.Equals(@"\serialize"))
                return NtStatus.CannotDelete;

            File directory = findFile(fileName);

            if (directory == null || directory.isDir == false)
                return NtStatus.Error;
            // DeleteOnClose gets or sets a value indicating whether the file has to be deleted during the IDokanOperations.Cleanup event. 
            info.DeleteOnClose = true;
            return NtStatus.Success;
        }

        public NtStatus DeleteFile(string fileName, IDokanFileInfo info)
        {
            //If a folder contains a file, deleting that folder won't call this method.Instead, it seems to be up to the programmer to delete the file by himself.

            //File fl = fileTree.search(fileName);
            File file = findFile(fileName);

            if (file == null || file.isDir == true)
                return NtStatus.Error;
            // DeleteOnClose gets or sets a value indicating whether the file has to be deleted during the IDokanOperations.Cleanup event. 
            info.DeleteOnClose = true;
            return NtStatus.Success;
        }

        public File findParent(string fileName)
        {
            //method fins parent of the path specified by fileName

            //format of the path: \first\second\...\last
            if (fileName.Equals(@"\"))
                return root;
            if (fileName.Contains("desktop.ini")) //why does desktop.ini appear and why are files treated as folders that contain desktop.ini?
                return null;
            File folder = root;

            string[] subFolders = fileName.Split('\\'); //first string is an empty string because of the first slash.Last element is the file itself (thus the loop below avoids these two)

            BTree currentTree = root.directoryContents;

            for (int i = 1; i < subFolders.Length-1; i++)
            {
                folder = currentTree.search(subFolders[i]);
                if (folder == null)
                    return null;
                currentTree = folder.directoryContents; //could null pointer exception occur here?
            }

            return folder;
        }

        public File findFile(string fileName)
        {
            //method returns the file specified by the fileName path.If it doesn't exist, null is returned.
            if (fileName.Equals(@"\"))
                return root;
            File parent = findParent(fileName);
            if (parent == null)
                return null;
            File fileToFind = parent.directoryContents.search(Path.GetFileName(fileName));

            return fileToFind;
        }
        
        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            File directory = findFile(fileName);

            files = new List<FileInformation>();
            if (directory != null)
            {
                List<File> traverseResults;
                directory.directoryContents.traverse(out traverseResults);
                if (traverseResults == null) //directory is empty
                    return NtStatus.Success;

           
                //traverseResults.Sort(); //folders come before files.This isn't possible to do in the B tree itself because Dokan has no clue what is a file and what is a folder.It is up to the programmer to find out.
                foreach (File foundFile in traverseResults)
                {
                    long fileLen = (foundFile.data == null) ? 0 : foundFile.data.Length;
                    FileInformation fileInfo = new FileInformation();
                    fileInfo.FileName = foundFile.name;
                    fileInfo.Length = fileLen;
                    fileInfo.CreationTime = DateTime.Now;
                    fileInfo.LastWriteTime = DateTime.Now;
                    if (foundFile.isDir == true)
                        fileInfo.Attributes = FileAttributes.Directory;
                    else
                        fileInfo.Attributes = FileAttributes.Normal;
                    files.Add(fileInfo);
                }
                return NtStatus.Success;
            }
    
            return NtStatus.Error;
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
        {
            files = new FileInformation[0];
            return NtStatus.NotImplemented;
        }

        public NtStatus FindStreams(string fileName, out IList<FileInformation> streams, IDokanFileInfo info)
        {
            streams = new FileInformation[0];
            return NtStatus.NotImplemented;
        }

        public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info)
        {
            return NtStatus.Success;
        }

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
        {
            freeBytesAvailable = this.freeBytesAvailable;
            totalNumberOfFreeBytes = this.freeBytesAvailable;
            totalNumberOfBytes = capacity;
            return NtStatus.Success;
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            //what to do with root directory?This might be the problem when writing larger files.
            File file = findFile(fileName);

                
            if (file != null)
            {
                long fileLen;// = (file.data == null) ? 0 : file.data.Length;
                if (file.isDir)
                    fileLen = file.directoryContents.totalDirectorySize;
                else
                    fileLen = (file.data == null) ? 0 : file.data.Length;
                fileInfo = new FileInformation()
                {
                    FileName = file.name,
                    Length = fileLen,
                    Attributes = (file.isDir == true) ? FileAttributes.Directory : FileAttributes.Normal,
                    CreationTime = file.dateCreated,
                    LastWriteTime = DateTime.Now
                };
            }
            else
            {
                fileInfo = default(FileInformation);
                if (fileName.Contains("ini"))
                    return NtStatus.Success;
                return NtStatus.Error;
            }

            return NtStatus.Success;
        }

        // Adds an ACL entry on the specified file for the specified account.
        public static void AddFileSecurity(string fileName, string account,
            FileSystemRights rights, AccessControlType controlType)
        {

            // Get a FileSecurity object that represents the
            // current security settings.
            FileSecurity fSecurity = System.IO.File.GetAccessControl(fileName);

            // Add the FileSystemAccessRule to the security settings.
            fSecurity.AddAccessRule(new FileSystemAccessRule(account,
                rights, controlType));

            // Set the new access settings.
            System.IO.File.SetAccessControl(fileName, fSecurity);
        }
        public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info)
        {
            //this method is probably used to set file permissions.No clue what SetFilePermissions is for then
            //on NTFS, every file and folder has a set of access control information called security descriptor.
            //permissions are assigned to specific users or groups
            //each assignment of permissions to a user or a group is represented as an ACE (Access Control Entry)
            //the entire set of permission entries in a security descriptor is known as ACL (Access Control List)

  
            if(info.IsDirectory == false && preventFileModification == true)
            {
                security = new FileSecurity();
                var abc = security.AccessRightType;
                int a = 3;
            }

            security = null;
            /*if(fileName.Equals(@"\"))
            {
                //FileSecurity fSecurity = System.IO.File.GetAccessControl(@"Y:\");
                //FileSecurity fSecurity = new FileSecurity(@"\", sections);
                FileSecurity fSecurity = new FileSecurity();
               

                // Add the FileSystemAccessRule to the security settings.
                fSecurity.AddAccessRule(new FileSystemAccessRule(userName,
                    FileSystemRights.FullControl, AccessControlType.Allow));

                // Set the new access settings.
                //System.IO.File.SetAccessControl(@"\", fSecurity);
                security = fSecurity;
                return NtStatus.Success;
            }


            if (info == null)
                throw new ArgumentNullException(nameof(info));


            security = info.IsDirectory ? new DirectorySecurity() : new FileSecurity() as FileSystemSecurity; //as FileSystemSecurity;
            security.AddAccessRule(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, AccessControlType.Allow));

            

            File file = findFile(fileName);
            if (file == null)
                return DokanResult.FileNotFound;*/

            //returning NotImplemented tells the library to set security with the security descriptor of the current process with authenticate user rights for context menu

            return NtStatus.NotImplemented;
            //return NtStatus.Success;
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features, out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
        {
            volumeLabel = "My file system";
            features = FileSystemFeatures.None;
            fileSystemName = "OPOSFileSystem";
            maximumComponentLength = 256; //max file name length?
            return NtStatus.Success;
        }
        public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
        {
            if (oldName.Equals(newName))
                return NtStatus.Success;
            if (newName.Contains(@"\serialize") || oldName.Contains(@"\serialize"))
                return NtStatus.Error;
            

            File fileToMove = findFile(oldName);
            File newParent = findParent(newName);

            //remove the oldName from its parent
            //check if it exists in the new directory

            //this is inefficient and needs to be reworked:
                //when both oldName and newName have the same parent, the file is only being renamed.What needs to be done is:
                    //find the node in which oldName is located
                    //rename oldName to newName
                    //sort the node.Without sorting, the node will become corrupted
                //when oldName's parrent is different from newName's parent (file is being moved):
                    //find the parent of newName
                    //check if the parent already contains oldName file/folder
                        //if it contains:
                            //if replace is false: return alreadyExists message
                        //add oldName to the newName parent

            fileToMove.parentDir.directoryContents.remove(fileToMove);
            fileToMove.changeName(Path.GetFileName(newName));
            File existingFile = newParent.directoryContents.search(fileToMove.name);
            if(existingFile != null)
            {
                //file already exists
                if (replace == false)
                {
                    fileToMove.changeName(Path.GetFileName(oldName));
                    fileToMove.parentDir.directoryContents.insert(fileToMove);
                    return DokanResult.AlreadyExists;
                }
                newParent.directoryContents.remove(existingFile);
            }
            //fileToMove.changeName(Path.GetFileName(newName));
            newParent.directoryContents.insert(fileToMove);
            fileToMove.parentDir = newParent;
            string parentName = (newParent.name.Equals(@"\")) ? "" : newParent.name;
            string absoluteParentPath = (newParent.absoluteParentPath.Equals(@"\")) ? "" : newParent.absoluteParentPath;
            if (fileToMove.isDir == true)
                fileToMove.absoluteParentPath = absoluteParentPath + @"\" + parentName;

            return NtStatus.Success;
        }

        //read file contents into the buffer
        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            if(fileName.Contains("serialize"))
            {
                int a = 3;
            }
            bytesRead = 0;
            File existingFile = findFile(fileName);
            if ((existingFile == null) || (existingFile.data == null))
                return NtStatus.Error;
            int offsetInt = (int)offset;

            //cases:
            //1)buffer is bigger than (existingFile.data.Length - offset)
                //read only (existingFile.data.Length - offset) amount of data
            //2)buffer is smaller than existingFile.data.Length - offset
                //read only buffer.Length data
            
            if(existingFile.data.Length == 0)
            {
                bytesRead = 0;
                return NtStatus.Success;
            }

            long amountOfDataToRead = (buffer.Length > (existingFile.data.Length - offset)) ? (existingFile.data.Length - offset) : buffer.Length;
            Array.Copy(existingFile.data, offset, buffer, 0, amountOfDataToRead);

            bytesRead = (int)amountOfDataToRead;
            return NtStatus.Success;
        }

        //method that writes a file onto the file system
        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            //THE PROBLEM OCCURS WHEN THE DATA CAN'T FIT IN THE BUFFER,it causes some unexpected error.
            //When the entire file can fit into the buffer, the file is copied without any problems.

            //should be called after createFile method


            bytesWritten = 0;
            File file = findFile(fileName); //argument false means that this file already exists in the root tree

            if (file == null)
                return DokanResult.FileNotFound;
        
            //if(preventFileModification == true && file.endOfFile != 0 && file.alreadyWritten == true)
            if(file.alreadyWritten == true)
            {
                //disable file editing
                return NtStatus.Error;
            }
            if (buffer.Length + offset == file.endOfFile)
                file.alreadyWritten = true;

            

            if ((file.data != null) && (offset > file.data.Length))
            {
                bytesWritten = 0;
                return NtStatus.ArrayBoundsExceeded;
            }
            long changeInSize = 0;

            if (file.data.Length < (buffer.Length + offset)) //data buffer too small, expand it
            {
                changeInSize = buffer.Length + offset - file.data.Length;
                byte[] newData = new byte[offset + buffer.Length];
                freeBytesAvailable -= (newData.Length - file.data.Length);
                bytesWritten = (newData.Length - file.data.Length);
                Array.Copy(file.data, 0, newData, 0, offset);
                Array.Copy(buffer, 0, newData, offset, buffer.Length);
                file.data = newData;
            }
            else
            {
                if((buffer.Length + offset) < file.data.Length)
                {
                    changeInSize = buffer.Length + offset - file.data.Length;
                    if(offset != 0)
                    {
                        byte[] newBuffer = new byte[buffer.Length + offset];
                        Array.Copy(file.data, 0, newBuffer, 0, offset);
                        Array.Copy(buffer, 0, newBuffer, offset, buffer.Length);
                        file.data = newBuffer;
                    }
                    else
                    {
                        file.data = new byte[buffer.Length];
                        Array.Copy(buffer, file.data, buffer.Length);
                    }
                }
                else
                    Array.Copy(buffer, file.data, buffer.Length);
                
                freeBytesAvailable -= changeInSize;
                bytesWritten = buffer.Length;
            }

            if (changeInSize == 0)
                return NtStatus.Success;

            File parent = file.parentDir;
            while(parent != null)
            {
                parent.directoryContents.totalDirectorySize += changeInSize;
                parent = parent.parentDir;
            }

            /*if (info.WriteToEndOfFile) //append data.Problem: when offset != 0, this flag isn't set.
            {
                if(file.data.Length < (buffer.Length + offset)) //data buffer too small, expand it
                {
                    byte[] newData = new byte[offset + buffer.Length];
                    freeBytesAvailable -= (newData.Length - file.data.Length);
                    bytesWritten = (newData.Length - file.data.Length);
                    Array.Copy(file.data, 0, newData, 0, offset);
                    Array.Copy(buffer, 0, newData, offset, buffer.Length);
                    file.data = newData;
                }
                else
                {
                    //data can fit into the buffer
                    Array.Copy(buffer, 0, file.data, offset, buffer.Length);
                    freeBytesAvailable -= buffer.Length;
                    bytesWritten = buffer.Length;
                }
            }
            else
            {
                //this will be called even when offset != 0
            }*/

            // TODO: Update date modified.
            if (file.endOfFile == 0)
                file.alreadyWritten = true;
            return NtStatus.Success;
        }

        public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info)
        {
            File file = findFile(fileName);
            if(file != null)
            {
                /*if(file.isDir == true)
                    Directory.SetAccessControl(fileName, (DirectorySecurity)security);
                else
                    System.IO.File.SetAccessControl(fileName, (FileSecurity)security);*/
                return NtStatus.Success;
            }
            return DokanResult.FileNotFound;
        }
        public void CloseFile(string fileName, IDokanFileInfo info) { }
        public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.NotImplemented;
        public NtStatus Mounted(IDokanFileInfo info) => NtStatus.Success;
        
        //if this returns an error, creating new files via cotnext menu will report an error
        public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info)
        {
            //When copying a file from external drive, this method is called after createFile, but before writeFile
            //When editing a file on the virtual drive, writeFile is called before this method.
            File file = findFile(fileName);
            file.endOfFile = length;
            return NtStatus.Success;
        }
        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info) => NtStatus.NotImplemented;
        public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info) => NtStatus.NotImplemented;
        public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.NotImplemented;
        public NtStatus Unmounted(IDokanFileInfo info) => NtStatus.Success;
    }
}
