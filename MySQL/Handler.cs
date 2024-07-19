using MySqlConnector;
using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;
using System.Configuration;
using System.ComponentModel;

namespace NetLock_Server.MySQL
{
    public class Handler
    {
        public static async Task<bool> Test_Connection()
        {
            MySqlConnection conn = new MySqlConnection(await MySQL.Config.Get_Connection_String());

            try
            {
                conn.Open();

                string sql = "SELECT * FROM clients;";
                MySqlCommand cmd = new MySqlCommand(sql, conn);
                cmd.ExecuteNonQuery();

                conn.Close();
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> Check_Duplicate(string query)
        {
            MySqlConnection conn = new MySqlConnection(await MySQL.Config.Get_Connection_String());

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
            MySqlConnection conn = new MySqlConnection(await MySQL.Config.Get_Connection_String());

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
