using MySqlConnector;
using NetLock_Server;
using NetLock_Server.MySQL;
using System;
using System.Data.Common;
using System.IO;
using System.Security.Cryptography;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Text.RegularExpressions;
using Microsoft.Extensions.FileSystemGlobbing.Internal;
using System.Text.Json;

namespace NetLock_RMM_Server.Files
{
    public class Command_Entity
    {
        public string? command { get; set; }
        public string? path { get; set; }
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

        // Command method
        public static async Task Command(string json)
        {
            try
            {
                Command_Entity command = JsonSerializer.Deserialize<Command_Entity>(json);

                if (command.command == "create_directory")
                {
                    if (!Directory.Exists(command.path))
                        Directory.CreateDirectory(command.path);
                }
                else if (command.command == "delete_directory")
                {
                    if (Directory.Exists(command.path))
                        Directory.Delete(command.path);
                }
                else if (command.command == "delete_file")
                {
                    if (File.Exists(command.path))
                        File.Delete(command.path);
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Files.Command", "general_error", ex.ToString());
            }
        }
    }
}
