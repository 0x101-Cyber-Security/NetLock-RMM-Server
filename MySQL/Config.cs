using System.Text.Json;

namespace NetLock_Server.MySQL
{
    public class Config
    {
        public string Server { get; set; }
        public int Port { get; set; }
        public string Database { get; set; }
        public string User { get; set; }
        public string Password { get; set; }
        public string SslMode { get; set; }

        public class MySQL
        {
            public string Server { get; set; }
            public int Port { get; set; }
            public string Database { get; set; }
            public string User { get; set; }
            public string Password { get; set; }
            public string SslMode { get; set; }
        }

        public class RootData
        {
            public MySQL MySQL { get; set; }
        }

        // Read appssettings.json file and load MySQL configuration
        public static async Task<string> Get_Connection_String()
        {
            try
            {
                // Read appssettings.json file
                string json = await File.ReadAllTextAsync("appsettings.json");

                //Logging.Handler.Debug("Classes.MySQL.MySQLConfig.Get_Connection_String", "json", json);

                // Deserialize JSON string
                RootData rootData = JsonSerializer.Deserialize<RootData>(json);

                // Get MySQL configuration
                string server = rootData.MySQL.Server;
                int port = rootData.MySQL.Port;
                string database = rootData.MySQL.Database;
                string user = rootData.MySQL.User;
                string password = rootData.MySQL.Password;
                string sslMode = rootData.MySQL.SslMode;

                // Return MySQL configuration
                string connectionString = $"Server={server};Port={port};Database={database};User={user};Password={password};SslMode={sslMode};";
                //Logging.Handler.Debug("Classes.MySQL.MySQLConfig.Get_Connection_String", "connectionString", connectionString);
                return connectionString;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.MySQL.MySQLConfig.Get_Connection_String", "General error", ex.ToString());
                return String.Empty;
            }
        }

        // Read appsettings.json file and get mysql database name
        public static async Task<string> Get_Database_Name()
        {
            try
            {
                // Read appssettings.json file
                string json = await File.ReadAllTextAsync("appsettings.json");

                //Logging.Handler.Debug("Classes.MySQL.MySQLConfig.Get_Database_Name", "json", json);

                // Deserialize JSON string
                RootData rootData = JsonSerializer.Deserialize<RootData>(json);

                // Get MySQL configuration
                string database = rootData.MySQL.Database;

                // Return MySQL configuration
                //Logging.Handler.Debug("Classes.MySQL.MySQLConfig.Get_Database_Name", "database", database);
                return database;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.MySQL.MySQLConfig.Get_Database_Name", "General error", ex.ToString());
                return String.Empty;
            }
        }
    }
}
