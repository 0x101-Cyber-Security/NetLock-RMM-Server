using MySqlConnector;
using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;
using System.Configuration;
using System.ComponentModel;

namespace NetLock_RMM_Server.MySQL
{
    public class Handler
    {
        // Check connection
        public static async Task<bool> Check_Connection()
        {
            MySqlConnection conn = new MySqlConnection(Configuration.MySQL.Connection_String);

            try
            {
                await conn.OpenAsync();
                return true;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.MySQL.Database.Check_Connection", "Result", ex.Message);
                Console.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }

        public static async Task<bool> Check_Duplicate(string query)
        {
            MySqlConnection conn = new MySqlConnection(Configuration.MySQL.Connection_String);

            try
            {
                await conn.OpenAsync();

                MySqlCommand cmd = new MySqlCommand(query, conn);
                cmd.ExecuteNonQuery();

                Logging.Handler.Debug("Classes.MySQL.Handler.Execute_Command", "Query", query);

                return true;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.MySQL.Handler.Execute_Command", "Query: " + query, ex.Message);
                conn.Close();
                return false;
            }
            finally
            {
                conn.Close();
            }
        }


        public static async Task<bool> Execute_Command(string query)
        {
            MySqlConnection conn = new MySqlConnection(Configuration.MySQL.Connection_String);

            try
            {
                await conn.OpenAsync();

                MySqlCommand cmd = new MySqlCommand(query, conn);
                cmd.ExecuteNonQuery();

                Logging.Handler.Debug("Classes.MySQL.Handler.Execute_Command", "Query", query);

                return true;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.MySQL.Handler.Execute_Command", "Query: " + query,  ex.Message);
                conn.Close();
                return false;
            }
            finally
            {
                conn.Close();
            }
        }
    }
}
