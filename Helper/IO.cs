namespace NetLock_RMM_Server.Helper
{
    public class IO
    {
        public class File_Or_Directory_Info
        {
            public string name { get; set; }
            public string path { get; set; }
            public string type { get; set; }
            public string size { get; set; }
            public DateTime last_modified { get; set; }
        }

        // Get directories from path
        public static async Task<List<File_Or_Directory_Info>> Get_Directory_Index(string path)
        {
            var directoryDetails = new List<File_Or_Directory_Info>();

            try
            {
                DirectoryInfo rootDirInfo = new DirectoryInfo(path);

                // Directories
                foreach (var directory in rootDirInfo.GetDirectories())
                {
                    var dirDetail = new File_Or_Directory_Info
                    {
                        name = directory.Name,
                        path = directory.FullName,
                        last_modified = directory.LastWriteTime,
                        size = await Get_Directory_Size(directory),
                        type = "0", // 0 = Directory
                    };

                    directoryDetails.Add(dirDetail);
                }

                // Files
                foreach (var file in rootDirInfo.GetFiles())
                {
                    var fileDetail = new File_Or_Directory_Info
                    {
                        name = file.Name,
                        path = file.FullName,
                        last_modified = file.LastWriteTime,
                        size = await Get_File_Size(file.FullName),
                        type = file.Extension,
                    };

                    directoryDetails.Add(fileDetail);
                }

                return directoryDetails;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("IO.GetDirectoryDetails", "General error", ex.ToString());
                return directoryDetails;
            }
        }

        public static async Task<string> GetSizeFormatted(long sizeInBytes)
        {
            return await Task.Run(() =>
            {
                if (sizeInBytes >= 1024 * 1024 * 1024) // Check for GB
                {
                    double sizeInGB = sizeInBytes / (1024.0 * 1024.0 * 1024.0);
                    return sizeInGB.ToString("F2") + " GB";
                }
                else if (sizeInBytes >= 1024 * 1024) // Check for MB
                {
                    double sizeInMB = sizeInBytes / (1024.0 * 1024.0);
                    return sizeInMB.ToString("F2") + " MB";
                }
                else if (sizeInBytes >= 1024) // Check for KB
                {
                    double sizeInKB = sizeInBytes / 1024.0;
                    return sizeInKB.ToString("F2") + " KB";
                }
                else // Bytes
                {
                    return sizeInBytes.ToString() + " Bytes";
                }
            });
        }

        public static async Task<string> Get_Directory_Size(DirectoryInfo directory)
        {
            long size = 0;

            try
            {
                // Add file sizes.
                FileInfo[] fis = directory.GetFiles();
                foreach (FileInfo fi in fis)
                {
                    size += fi.Length;
                }

                // Convert and format size.
                return await GetSizeFormatted(size);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("IO.Get_Directory_Size", "General error", ex.ToString());
                return "0.00 Bytes";
            }
        }

        public static async Task<string> Get_File_Size(string filePath)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                long size = fileInfo.Length;

                // Convert and format size.
                return await GetSizeFormatted(size);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("IO.Get_File_Size", "General error", ex.ToString());
                return "0.00 Bytes";
            }
        }
    }
}