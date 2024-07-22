using System.Data.Common;
using MySqlConnector;
using System.Text.Json;
using System.Threading.Tasks;
using NetLock_Server.Agent.Windows;

namespace NetLock_Server.Events
{
    public class Sender
    {
        public class Notifications
        {
            public bool mail { get; set; }
            public bool microsoft_teams { get; set; }
            public bool telegram { get; set; }
            public bool ntfy_sh { get; set; }
        }

        public static async Task Process()
        {
            MySqlConnection conn = new MySqlConnection(await MySQL.Config.Get_Connection_String());

            try
            {
                await conn.OpenAsync();

                string query = "SELECT * FROM `events` WHERE mail_status = 0;";

                MySqlCommand cmd = new MySqlCommand(query, conn);
                
                Logging.Handler.Debug("Events.Sender.Process", "MySQL_Prepared_Query", query);

                using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            string notification_json = reader["notification_json"].ToString() ?? String.Empty;

                            //Extract JSON
                            Notifications notifications = JsonSerializer.Deserialize<Notifications>(notification_json);

                            if (notifications.mail)
                            {
                                Helper.Notifications.Smtp.Send_Mail()
                            }

                            //date = reader["date"].ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Events.Sender.Process", "MySQL_Query", ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }
    }
}
