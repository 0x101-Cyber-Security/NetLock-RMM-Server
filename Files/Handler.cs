using MySqlConnector;
using NetLock_Server;
using NetLock_Server.MySQL;
using System;
using System.Data.Common;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.FileSystemGlobbing.Internal;
using System.Text.Json;
using System.Diagnostics;

namespace NetLock_RMM_Server.Files
{
    public class Command_Entity
    {
        public string? command { get; set; }
        public string? path { get; set; }
        public string? name { get; set; }
        public string? guid { get; set; }
    }

    public class Download_JSON
    {
        public string? guid{ get; set; }
    }

    public class Handler
    {
        // Verify_Api_Key method
        public static async Task<bool> Verify_Api_Key(string files_api_key)
        {
            try
            {
                bool api_key_exists = false;

                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "SELECT * FROM settings WHERE files_api_key = @files_api_key;";

                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@files_api_key", files_api_key);

                    Logging.Handler.Debug("Files.Verify_Api_Key", "MySQL_Prepared_Query", query);

                    using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (reader.HasRows)
                            api_key_exists = true;
                        else 
                            api_key_exists = false;
                    }
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Verify_Api_Key", "MySQL_Query", ex.ToString());
                }
                finally
                {
                    conn.Close();
                }

                return api_key_exists;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Verify_Api_Key", "general_error", ex.ToString());
                return false;
            }
        }

        public static async Task Register_File(string file_path, string directory_path)
        {
            try
            {
                // Ensure the file_path is relative to _private_files_admin
                string relativePath = Path.GetRelativePath(Application_Paths._private_files, file_path);

                // Extract file information
                string name = Path.GetFileName(file_path);
                string path = Path.GetRelativePath(Application_Paths._private_files, directory_path); // Use the directory path

                // If the path equals base directory, set it to an empty string
                if (string.IsNullOrEmpty(path) || path == ".")
                {
                    path = string.Empty;
                }

                string sha512 = await Helper.IO.Get_SHA512(file_path);
                string guid = Guid.NewGuid().ToString();
                string access = "Private";

                Logging.Handler.Debug("Files.Register_File", "name", name);
                Logging.Handler.Debug("Files.Register_File", "path", path);
                Logging.Handler.Debug("Files.Register_File", "sha512", sha512);
                Logging.Handler.Debug("Files.Register_File", "guid", guid);
                Logging.Handler.Debug("Files.Register_File", "access", access);

                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    // Check if the file already exists
                    string query = "SELECT * FROM files WHERE name = @name AND path = @path;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Parameters.AddWithValue("@path", path);

                    Logging.Handler.Debug("Files.Register_File", "MySQL_Prepared_Query", query);

                    bool fileExists = false;

                    using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        fileExists = reader.HasRows; // Check if file exists
                    }

                    if (fileExists)
                    {
                        // Update file
                        query = "UPDATE files SET name = @name, path = @path, sha512 = @sha512, guid = @guid, password = @password, access = @access, date = @date WHERE name = @name AND path = @path;";
                    }
                    else
                    {
                        // Insert file
                        query = "INSERT INTO files (name, path, sha512, guid, password, access, date) VALUES (@name, @path, @sha512, @guid, @password, @access, @date);";
                    }

                    cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Parameters.AddWithValue("@path", path);
                    cmd.Parameters.AddWithValue("@sha512", sha512);
                    cmd.Parameters.AddWithValue("@guid", guid);
                    cmd.Parameters.AddWithValue("@password", Guid.NewGuid().ToString());
                    cmd.Parameters.AddWithValue("@access", access);
                    cmd.Parameters.AddWithValue("@date", DateTime.Now);

                    Logging.Handler.Debug("Files.Register_File", "MySQL_Prepared_Query", query);

                    await cmd.ExecuteNonQueryAsync();
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Register_File", "MySQL_Query", ex.ToString());
                }
                finally
                {
                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Register_File", "general_error", ex.ToString());
            }
        }



        private static async Task Unregister_File(string guid)
        {
            try
            {
                Console.WriteLine("Unregistering file with GUID: " + guid);

                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "DELETE FROM files WHERE guid = @guid;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@guid", guid);

                    Logging.Handler.Debug("Files.Unregister_File", "MySQL_Prepared_Query", query);

                    await cmd.ExecuteNonQueryAsync();
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Unregister_File", "MySQL_Query", ex.ToString());
                }
                finally
                {
                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Unregister_File", "general_error", ex.ToString());
            }
        }

        // Command method
        public static async Task Command(string json)
        {
            try
            {
                Logging.Handler.Debug("Files.Command", "json", json);

                Command_Entity command = JsonSerializer.Deserialize<Command_Entity>(json);

                Logging.Handler.Debug("Files.Command", "command", command.command);
                Logging.Handler.Debug("Files.Command", "path", command.path);
                Logging.Handler.Debug("Files.Command", "name", command.name);
                Logging.Handler.Debug("Files.Command", "guid", command.guid);

                // Normalize the path based on the base path
                string normalizedPath = command.path;

                // Replace "base1337" with the actual base path if needed
                if (normalizedPath.Contains("base1337"))
                {
                    normalizedPath = normalizedPath.Replace("base1337", Application_Paths._private_files);
                }

                // Sanitize and get the full path
                string safePath = Path.GetFullPath(Path.Combine(Application_Paths._private_files, normalizedPath))
                    .Replace('\\', '/').TrimEnd('/');

                // Remove the base path for storage or processing
                string relativePath = safePath.Replace(Application_Paths._private_files.Replace('\\', '/'), string.Empty).TrimStart('/');

                if (command.command == "create_directory")
                {
                    if (!Directory.Exists(safePath))
                        Directory.CreateDirectory(safePath);
                }
                else if (command.command == "delete_directory")
                {
                    Console.WriteLine("Deleting directory with GUID: " + command.guid);
                    Console.WriteLine("Safe path: " + safePath);
                    DirectoryInfo di = new DirectoryInfo(safePath);

                    // Recursively delete files and directories if the directory exists
                    if (di.Exists)
                    {
                        await DeleteDirectoryRecursively(di);
                    }
                }
                else if (command.command == "delete_file")
                {
                    Console.WriteLine("Deleting file with GUID: " + command.guid);
                    Console.WriteLine("Safe path: " + Path.Combine(safePath, command.name));

                    if (File.Exists(Path.Combine(safePath, command.name))) 
                    {
                        await Unregister_File(command.guid); // Remove the file from the DB
                        File.Delete(Path.Combine(safePath, command.name));
                    }
                }
                else if (command.command == "rename")
                {
                    string oldPath = Path.GetDirectoryName(safePath);
                    string newPath = Path.Combine(oldPath, command.name);

                    if (File.Exists(safePath))
                    {
                        // Rename file
                        File.Move(safePath, newPath);

                        // Update the path and name in the DB
                        using (MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String()))
                        {
                            try
                            {
                                await conn.OpenAsync();

                                string query = "UPDATE files SET name = @name, path = @path WHERE guid = @guid;";
                                MySqlCommand cmd = new MySqlCommand(query, conn);
                                cmd.Parameters.AddWithValue("@guid", command.guid);
                                cmd.Parameters.AddWithValue("@name", command.name);
                                cmd.Parameters.AddWithValue("@path", relativePath);

                                Logging.Handler.Debug("Files.Command", "MySQL_Prepared_Query", query);

                                await cmd.ExecuteNonQueryAsync();
                            }
                            catch (Exception ex)
                            {
                                Logging.Handler.Error("Files.Command", "MySQL_Query", ex.ToString());
                            }
                        }
                    }
                    else if (Directory.Exists(safePath))
                    {
                        // Rename directory
                        Directory.Move(safePath, newPath);
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Command", "general_error", ex.ToString());
            }
        }


        // Recursive method for deleting files and directories
        private static async Task DeleteDirectoryRecursively(DirectoryInfo directory)
        {
            try
            {
                // First delete all files in the current directory
                foreach (FileInfo file in directory.GetFiles())
                {
                    await Unregister_File(file.FullName); // Remove the file from the DB
                    file.Delete(); // Delete the file from the file system
                }

                // Recursively run through and delete all subdirectories
                foreach (DirectoryInfo subDirectory in directory.GetDirectories())
                {
                    await DeleteDirectoryRecursively(subDirectory);
                }

                // If the directory is empty, delete it yourself
                directory.Delete();
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.DeleteDirectoryRecursively", "general_error", ex.ToString());
            }
        }

        // Download file
        public static async Task<bool> Verify_File_Access(string guid, string password, string api_key)
        {
            bool access_granted = false;

            try
            {
                Logging.Handler.Debug("Files.Verify_File_Access", "guid", guid);

                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "SELECT * FROM files WHERE guid = @guid;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@guid", guid);

                    Logging.Handler.Debug("Files.Verify_File_Access", "MySQL_Prepared_Query", query);

                    using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (reader.HasRows)
                        {
                            Logging.Handler.Debug("Files.Verify_File_Access", "File exists in DB", "true"); 

                            await reader.ReadAsync();

                            string access = reader.GetString(reader.GetOrdinal("access"));

                            if (access == "Public")
                                access_granted = true;
                            else if (access == "Private")
                            {
                                // Check if the API key is valid
                                if (await Verify_Api_Key(api_key))
                                    access_granted = true;
                                else
                                    access_granted = false;

                                // Check if the password is valid
                                if (password == reader.GetString(reader.GetOrdinal("password")))
                                    access_granted = true;
                                else
                                    access_granted = false;
                            }
                        }
                        else
                        {
                            Logging.Handler.Debug("Files.Verify_File_Access", "File exists in DB", "false");
                            access_granted = false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Verify_File_Access", "MySQL_Query", ex.ToString());
                    access_granted = false;
                }
                finally
                {
                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Command", "general_error", ex.ToString());
                access_granted = false;
            }

            return access_granted;
        }

        // Get file path by GUID
        public static async Task<string> Get_File_Path_By_GUID(string guid)
        {
            string file_path = String.Empty;

            try
            {
                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "SELECT * FROM files WHERE guid = @guid;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@guid", guid);

                    Logging.Handler.Debug("Files.Get_File_Path_By_GUID", "MySQL_Prepared_Query", query);

                    using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (reader.HasRows)
                        {
                            await reader.ReadAsync();

                            string path = reader.GetString(reader.GetOrdinal("path"));
                            string name = reader.GetString(reader.GetOrdinal("name"));

                            file_path = Path.Combine(path, name);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Get_File_Path_By_GUID", "MySQL_Query", ex.ToString());
                }
                finally
                {
                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Get_File_Path_By_GUID", "general_error", ex.ToString());
            }

            return file_path;
        }

        // Get file name by GUID
        public static async Task<string> Get_File_Name_By_GUID(string json)
        {
            string guid = String.Empty;

            // Deserialize JSON
            try
            {
                Download_JSON download = JsonSerializer.Deserialize<Download_JSON>(json);
                guid = download.guid;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Get_File_Name_By_GUID", "json_deserialize", ex.ToString());
            }

            string file_name = String.Empty;

            try
            {
                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "SELECT * FROM files WHERE guid = @guid;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@guid", guid);

                    Logging.Handler.Debug("Files.Get_File_Name_By_GUID", "MySQL_Prepared_Query", query);

                    using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (reader.HasRows)
                        {
                            await reader.ReadAsync();

                            file_name = reader.GetString(reader.GetOrdinal("name"));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logging.Handler.Error("Files.Get_File_Name_By_GUID", "MySQL_Query", ex.ToString());
                }
                finally
                {
                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Get_File_Name_By_GUID", "general_error", ex.ToString());
            }

            return file_name;
        }
    }
}
