using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using DokanNet;

namespace CustomFS
{

    /*
     * Every folder will have its own B tree.
     * When creating files and folders- find its parent.
     *      -this is accomplished by breaking the path and descending down the tree
     *      -the last string in the path is the file's (or folder's) name, the string before it is its parent
     * */


    /*
     * PROBLEMS:
     * BTree search function is not working properly because of File.CompareTo method!!!
     * 
     */

    class CustomFileSystem : IDokanOperations
    {
        private static readonly int capacity = 500*1024*1024; //500 MiB
        private long freeBytesAvailable = capacity;
        private static readonly File root = new File(@"\", null, true);

        public CustomFileSystem()
        {
            root.absoluteParentPath = "";
        }
        public void Cleanup(string fileName, IDokanFileInfo info)
        {
            bool isDirectory = info.IsDirectory;
            File wantedFile = findFolder(fileName, false);
            if (info.DeleteOnClose == true)
            {
                if (isDirectory == true) 
                    freeBytesAvailable += wantedFile.directoryContents.totalDirectorySize;
                else 
                    freeBytesAvailable += wantedFile.data.Length;
                wantedFile.parentDir.directoryContents.remove(wantedFile);
            }
        }
 
        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            //what to do with root folder (\) and with desktop.ini?
            if (fileName.Equals(@"\"))
                return NtStatus.Success;

            File parent = findFolder(fileName, mode == FileMode.CreateNew || mode == FileMode.Create);
            if (parent == null)
                return NtStatus.Error;

            //see if the file already exists if mode is CreateNew or Create
            if(mode == FileMode.CreateNew || mode == FileMode.Create)
            {
                File existing = parent.directoryContents.search(Path.GetFileName(fileName));
                if (existing != null)
                    return DokanResult.AlreadyExists;
            }
          

            if (attributes == FileAttributes.Directory || info.IsDirectory == true)
            {
                switch(mode)
                {
                    case FileMode.CreateNew:
                        File newFolder = new File(Path.GetFileName(fileName), parent, true);
                        string parentName = (parent.name == @"\") ? "" : parent.name;
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
                        newFile.absoluteParentPath = parent.absoluteParentPath + @"\" + parent.name;
                        parent.directoryContents.insert(newFile);
                        newFile.dateCreated = DateTime.Now;
                        break;
                }
            }

            return NtStatus.Success;
        }

        public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info)
        {
            if (!info.IsDirectory)
                return NtStatus.Error;
            // DeleteOnClose gets or sets a value indicating whether the file has to be deleted during the IDokanOperations.Cleanup event. 
            info.DeleteOnClose = true;
            return NtStatus.Success;
        }

        public NtStatus DeleteFile(string fileName, IDokanFileInfo info)
        {
            //problem: for some reason, this method is called even when the user isn't deleting the file (it gets called when moving a file)
            //File fl = fileTree.search(fileName);

            if (info.IsDirectory)
                return NtStatus.Error;
            // DeleteOnClose gets or sets a value indicating whether the file has to be deleted during the IDokanOperations.Cleanup event. 
            info.DeleteOnClose = true;
            return NtStatus.Success;
        }

        public File findFolder(string fileName, bool create)
        {
            //flag create tells whether the last part of fileName exists.If it doesn't, find the parent

            //format of the path: \first\second\...\last
            if (fileName.Equals(@"\"))
                return root;
            if (fileName.Contains("desktop.ini")) //why does desktop.ini appear and why are files treated as folders that contain desktop.ini?
                return null;
            File folder = root;

            string[] subFolders = fileName.Split('\\'); //first string is an empty string because of the first slash
            int counter = (create == true) ? subFolders.Length - 1 : subFolders.Length;

            BTree currentTree = root.directoryContents;

            for(int i = 1; i < counter; i++)
            {
                folder = currentTree.search(subFolders[i]);
                if (folder == null)
                    return null;
                currentTree = folder.directoryContents; //could null pointer exception occur here?
            }

            return folder;
        }
        
        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            File directory = findFolder(fileName, false); //assuming that fileName is a path of a directory that exists

            files = new List<FileInformation>();
            if (directory != null)
            {
                List<File> traverseResults;
                directory.directoryContents.traverse(out traverseResults);
                if (traverseResults == null) //directory is empty
                    return NtStatus.Success;

    
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

            File file = findFolder(fileName, false);
          
                
            if (file != null)
            {
                long fileLen = (file.data == null) ? 0 : file.data.Length;
                fileInfo = new FileInformation()
                {
                    FileName = Path.GetFileName(fileName),
                    Length = fileLen,
                    Attributes = (file.isDir == true) ? FileAttributes.Directory : FileAttributes.Normal,
                    CreationTime = file.dateCreated,
                    LastWriteTime = DateTime.Now
                };
            }
            else
            {
                fileInfo = default(FileInformation);
                return NtStatus.Error;
            }

            return NtStatus.Success;
        }

        public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info)
        {
            //what to do in this method?

            if (info == null)
                throw new ArgumentNullException(nameof(info));

            security = info.IsDirectory
                ? new DirectorySecurity() as FileSystemSecurity
                : new FileSecurity() as FileSystemSecurity;
            security.AddAccessRule(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, AccessControlType.Allow));

            return NtStatus.Success;

            //security = null;
            //return NtStatus.NotImplemented;
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
            if (oldName == newName)
                return NtStatus.Success;
            
            if(oldName.Contains("raspored"))
            {
                int a = 3;
            }

            File fileToMove = findFolder(oldName, false);
            File newParent = findFolder(newName, true);
            
            //if oldName's and newName's parent is the same, only name is changed
            if(fileToMove.parentDir.absoluteParentPath.Equals(newParent.absoluteParentPath))
            {
                fileToMove.changeName(Path.GetFileName(newName));
            }
            //else, the file is being moved
            else
            {
                if (newParent == null)
                    return NtStatus.Error;

                //check if such a file already exists
                File exists = newParent.directoryContents.search(Path.GetFileName(newName));
                if(exists != null && replace == false)
                    return DokanResult.AlreadyExists;

                fileToMove.parentDir.directoryContents.remove(fileToMove);
                newParent.directoryContents.insert(fileToMove);
            }
            

            // TODO: Moving a directory.
            //info.isDirectory will be false even when directory is moved

            return NtStatus.Success;
        }

        //read file contents into the buffer
        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;
            File existingFile = findFolder(fileName, false);
            if ((existingFile == null) || (existingFile.data == null))
                return NtStatus.Error;
            int offsetInt = (int)offset;

            //cases:
            //1)buffer is bigger than (existingFile.data.Length - offset)
                //read only (existingFile.data.Length - offset) amount of data
            //2)buffer is smaller than existingFile.data.Length - offset
                //read only buffer.Length data
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
            File file = findFolder(fileName, false); //argument false means that this file already exists in the root tree

            if(file == null)
                return NtStatus.Error;
            

            if ((file.data != null) && (offset > file.data.Length))
            {
                bytesWritten = 0;
                return NtStatus.ArrayBoundsExceeded;
            }

            if (file.data.Length < (buffer.Length + offset)) //data buffer too small, expand it
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
            return NtStatus.Success;
        }

        public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info)
        {
            File file = findFolder(fileName, false);
            if(file != null)
            {
                if(file.isDir == true)
                    Directory.SetAccessControl(fileName, (DirectorySecurity)security);
                else
                    System.IO.File.SetAccessControl(fileName, (FileSecurity)security);
                return NtStatus.Success;
            }
            return NtStatus.Error;
        }

        public void CloseFile(string fileName, IDokanFileInfo info) { } //info.Context = null; }
        public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus Mounted(IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus Unmounted(IDokanFileInfo info) => NtStatus.Success;
    }
}
