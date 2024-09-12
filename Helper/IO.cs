namespace NetLock_RMM_Server.Helper
{
    public class IO
    {
        public class DirectoryTree
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public List<DirectoryTree> Directories { get; set; } = new List<DirectoryTree>();
            public List<FileTree> Files { get; set; } = new List<FileTree>();
        }

        public class FileTree
        {
            public string Name { get; set; }
            public string Path { get; set; }
        }

        public static async Task<DirectoryTree?> BuildDirectoryTree(string directoryPath)
        {
            try
            {
                var root = new DirectoryTree
                {
                    Name = new DirectoryInfo(directoryPath).Name,
                    Path = directoryPath
                };

                // Add subdirectories recursively
                foreach (var dir in Directory.GetDirectories(directoryPath))
                {
                    root.Directories.Add(await BuildDirectoryTree(dir));
                }

                // Add files
                foreach (var file in Directory.GetFiles(directoryPath))
                {
                    root.Files.Add(new FileTree
                    {
                        Name = Path.GetFileName(file),
                        Path = file
                    });
                }

                return root;
            }
            catch (Exception ex)
            {
                // Error logging
                Logging.Handler.Error("IO.DirectoryTreeBuilder.BuildDirectoryTree", "general_error", ex.ToString());
                return null;
            }
        }
    }
}