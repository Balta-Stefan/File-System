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
    class CustomFileSystem : IDokanOperations
    {
        private static readonly int capacity = 500*1024*1024; //500 MiB
        private long freeBytesAvailable = capacity;
        //private static readonly SystemTree fileSystem = new SystemTree();
        private static readonly BTree fileTree = new BTree();
        private readonly string pathPrefix;

        //private File currentDir;
        public CustomFileSystem(string root)
        {
            pathPrefix = root;
            //fileTree.insert(new File(pathPrefix + @"\", null, true));
        }

        public void Cleanup(string fileName, IDokanFileInfo info)
        {
            bool isDirectory = info.IsDirectory;
            File wantedFile = new File(fileName, null, isDirectory);
            if (info.DeleteOnClose == true)
            {
                fileTree.remove(new File(fileName, null, info.IsDirectory));
                //currentDir.directoryContents.remove(wantedFile);
            }
        }

        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            if (fileName.Equals(@"\"))
                fileName = "";
            string filePath = pathPrefix + fileName;
            File file = fileTree.search(filePath);
 
            if(info.IsDirectory == true)
            {
                //create folder
                /*switch (mode)
                {
                    case FileMode.Open:
                        if(file == null)
                        {
                            return NtStatus.Error;
                        }
                        break;
                    case FileMode.CreateNew:
                        if(file != null || fileName.Equals(""))
                        {
                            return NtStatus.Error;
                        }
                        Directory.CreateDirectory(fileName);
                        File newDirectory = new File(filePath, null, true)
                        newDirectory.dateCreated = DateTime.Now;
                        fileTree.insert(newDirectory);
                        break;
                }*/
            }
            else
            {
                switch(mode)
                {
                    case FileMode.CreateNew:
                        //create file
                        if (file == null)
                        {
                            File newFile = new File(fileName, null, false);
                            newFile.dateCreated = DateTime.Now;
                            fileTree.insert(newFile);
                        }
                           
                        else
                            return DokanResult.AlreadyExists;
                        break;
                    /*case FileMode.Open:
                        if (file == null)
                            return NtStatus.Error;
                        break;*/
                }
                if (System.IO.File.Exists(fileName))
                {
                    FileAttributes new_attributes = attributes;
                    new_attributes |= FileAttributes.Archive; // Files are always created as Archive
                                                              // FILE_ATTRIBUTE_NORMAL is override if any other attribute is set.
                    new_attributes &= ~FileAttributes.Normal;
                    System.IO.File.SetAttributes(fileName, new_attributes);
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
            if (info.IsDirectory)
                return NtStatus.Error;
            // DeleteOnClose gets or sets a value indicating whether the file has to be deleted during the IDokanOperations.Cleanup event. 
            info.DeleteOnClose = true;
            return NtStatus.Success;
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            List<File> traverseResults;
            //currentDir.directoryContents.traverse(out traverseResults);
            fileTree.traverse(out traverseResults);
            
            files = new List<FileInformation>();
            if (fileName.Equals(@"\"))
                fileName = "";
            if (traverseResults != null)
            {
                foreach (File foundFile in traverseResults)
                {
                    long fileLen = (foundFile.data == null) ? 0 : foundFile.data.Length;
                    FileInformation fileInfo = new FileInformation();
                    fileInfo.FileName = Path.GetFileName(foundFile.name);
                    fileInfo.Length = fileLen;
                    fileInfo.CreationTime = DateTime.Now;
                    fileInfo.LastWriteTime = DateTime.Now;
                    files.Add(fileInfo);
                }
            }
    
            return NtStatus.Success;
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
            //File file = currentDir.directoryContents.search(fileName);
            File file = fileTree.search(fileName);
          
                
            if (file != null)
            {
                long fileLen = (file.data == null) ? 0 : file.data.Length;
                fileInfo = new FileInformation()
                {
                    FileName = Path.GetFileName(fileName),
                    Length = fileLen,
                    Attributes = FileAttributes.Normal,
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
            security = null;
            return NtStatus.Success;
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features, out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
        {
            volumeLabel = "My file system";
            features = FileSystemFeatures.None;
            fileSystemName = "OPOSFileSystem";
            maximumComponentLength = 15; //max file name?
            return NtStatus.Success;
        }
        public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
        {
            if (replace)
                return NtStatus.NotImplemented;

            if (oldName == newName)
                return NtStatus.Success;

            // TODO: Moving a directory.

            // TODO: Moving a file.

            return NtStatus.Success;
        }

        //read file contents into the buffer
        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;
            //File existingFile = currentDir.directoryContents.search(fileName);
            File existingFile = fileTree.search(fileName);
            if ((existingFile == null) || (existingFile.data == null))
                return NtStatus.Error;
            int offsetInt = (int)offset;
            existingFile.data.Skip(offsetInt).Take(buffer.Length).ToArray().CopyTo(buffer, 0);
            int diff = existingFile.data.Length - offsetInt;
            bytesRead = buffer.Length > diff ? diff : buffer.Length;
            return NtStatus.Success;
        }

        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            bytesWritten = 0;
            //File file = currentDir.directoryContents.search(fileName);
            File file = fileTree.search(fileName);

            if(file == null)
            {
                return NtStatus.Error;
            }

            else if ((file.data != null) && (offset > file.data.Length))
            {
                bytesWritten = 0;
                return NtStatus.ArrayBoundsExceeded;
            }

            if (info.WriteToEndOfFile)
            {
                // TODO: Appending.
            }
            else
            {
                file.data = new byte[buffer.Length];
                long difference = file.data.Length - offset;
                freeBytesAvailable -= difference;
                for (long i = 0; i < buffer.Length; i++)
                    file.data[i] = buffer[i];
                //file.data = file.data.Take((int)offset).Concat(buffer).ToArray();
                bytesWritten = buffer.Length;
            }

            // TODO: Update date modified.
            return NtStatus.Success;
        }

        public void CloseFile(string fileName, IDokanFileInfo info) { }
        public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus Mounted(IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Error;
        public NtStatus Unmounted(IDokanFileInfo info) => NtStatus.Success;
    }
}
