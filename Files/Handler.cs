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

        public static async Task Register_File(string file_path)
        {
            try
            {
                // Read file info
                string name = Path.GetFileName(file_path);
                string path = Path.GetDirectoryName(file_path);
                path = Regex.Replace(path, @"^.*?(?=\\admin)", "");
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

                    // Check if already exists, if so, do update instead of insert.
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
                        query = "UPDATE files SET name = @name, path = @path, sha512 = @sha512, guid = @guid, access = @access, date = @date WHERE path = @path;";
                    }
                    else
                    {
                        // Insert file
                        query = "INSERT INTO files (name, path, sha512, guid, access, date) VALUES (@name, @path, @sha512, @guid, @access, @date);";
                    }

                    cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Parameters.AddWithValue("@path", path);
                    cmd.Parameters.AddWithValue("@sha512", sha512);
                    cmd.Parameters.AddWithValue("@guid", guid);
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

        private static async Task Unregister_File(string file_path)
        {
            try
            {
                // Read file info
                string name = Path.GetFileName(file_path);
                string path = Path.GetDirectoryName(file_path);
                path = Regex.Replace(path, @"^.*?(?=\\admin)", "");

                MySqlConnection conn = new MySqlConnection(await Config.Get_Connection_String());

                try
                {
                    await conn.OpenAsync();

                    string query = "DELETE FROM files WHERE name = @name AND path = @path;";
                    MySqlCommand cmd = new MySqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Parameters.AddWithValue("@path", path);

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

                // Check if path contains base1337, cut the base1337 part out and replace it with the actual path
                if (command.path.Contains("base1337"))
                    command.path = command.path.Replace("base1337", Application_Paths._private_files_admin);

                if (command.command == "create_directory")
                {
                    if (!Directory.Exists(command.path))
                        Directory.CreateDirectory(command.path);
                }
                else if (command.command == "delete_directory")
                {
                    DirectoryInfo di = new DirectoryInfo(command.path);

                    // Recursively delete files and directories if the directory exists
                    if (di.Exists)
                    {
                        await DeleteDirectoryRecursively(di);
                    }
                }
                else if (command.command == "delete_file")
                {
                    if (File.Exists(command.path))
                    {
                        await Unregister_File(command.path); // Remove the file from the DB
                        File.Delete(command.path);
                    }
                }
                else if (command.command == "rename")
                {
                    string newPath = Path.Combine(Path.GetDirectoryName(command.path), command.name);

                    if (File.Exists(command.path))
                    {
                        // Rename file
                        File.Move(command.path, newPath);
                    }
                    else if (Directory.Exists(command.path))
                    {
                        // Rename directory
                        Directory.Move(command.path, newPath);
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
        public static async Task<bool> Verify_File_Access(string guid, string api_key)
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
        public static async Task<string> Get_File_Path_By_GUID(string json)
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
                Logging.Handler.Error("Files.Get_File_Path_By_GUID", "json_deserialize", ex.ToString());
            }

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
