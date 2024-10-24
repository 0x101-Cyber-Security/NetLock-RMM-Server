using System.Data.Common;
using MySqlConnector;
using System.Text.Json;
using System.Threading.Tasks;
using NetLock_RMM_Server.Agent.Windows;
using System.Runtime.CompilerServices;

namespace NetLock_RMM_Server.Events
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

        public static async Task Smtp(string type, string table)
        {
            MySqlConnection conn = new MySqlConnection(Configuration.MySQL.Connection_String);

            try
            {
                await conn.OpenAsync();

                string query = "SELECT * FROM `events` WHERE @type = 0;";
                MySqlCommand cmd = new MySqlCommand(query, conn);
                cmd.Parameters.AddWithValue("@type", type);

                Logging.Handler.Debug("Events.Sender.Smtp", "MySQL_Prepared_Query", query);

                using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            try
                            {
                                string notification_json = reader["notification_json"].ToString() ?? String.Empty;

                                // Extract JSON
                                Notifications notifications = JsonSerializer.Deserialize<Notifications>(notification_json);

                                if (type == "mail_status" && notifications.mail)
                                {
                                    await Check_Notifications(reader["id"].ToString() ?? String.Empty, type, "mail_notifications", reader["severity"].ToString() ?? String.Empty, reader["reported_by"].ToString() ?? String.Empty, reader["_event"].ToString() ?? String.Empty, reader["description"].ToString() ?? String.Empty);
                                }
                                else if (type == "ms_teams_status" && notifications.microsoft_teams)
                                {
                                    await Check_Notifications(reader["id"].ToString() ?? String.Empty, type, "microsoft_teams_notifications", reader["severity"].ToString() ?? String.Empty, reader["reported_by"].ToString() ?? String.Empty, reader["_event"].ToString() ?? String.Empty, reader["description"].ToString() ?? String.Empty);
                                }
                                else if (type == "telegram_status" && notifications.telegram)
                                {
                                    await Check_Notifications(reader["id"].ToString() ?? String.Empty, type, "telegram_notifications", reader["severity"].ToString() ?? String.Empty, reader["reported_by"].ToString() ?? String.Empty, reader["_event"].ToString() ?? String.Empty, reader["description"].ToString() ?? String.Empty);
                                }
                                else if (type == "ntfy_sh_status" && notifications.ntfy_sh)
                                {
                                    await Check_Notifications(reader["id"].ToString() ?? String.Empty, type, "ntfy_sh_notifications", reader["severity"].ToString() ?? String.Empty, reader["reported_by"].ToString() ?? String.Empty, reader["_event"].ToString() ?? String.Empty, reader["description"].ToString() ?? String.Empty);
                                }
                            }
                            catch (Exception ex)
                            {
                                // Set all notifications to true if an error occurs
                                await MySQL.Handler.Execute_Command("UPDATE `events` SET mail_status = 1, ms_teams_status = 1, telegram_status = 1, ntfy_sh_status = 1 WHERE id = " + reader["id"].ToString() + ";");
                                Logging.Handler.Error("Events.Sender.Smtp", "MySQL_Query", ex.ToString());
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Events.Sender.Smtp", "MySQL_Query", ex.Message);
            }
            finally
            {
                await conn.CloseAsync();
            }
        }

        private static async Task Check_Notifications(string id, string type, string table, string severity, string reported_by, string _event, string description)
        {
            MySqlConnection conn = new MySqlConnection(Configuration.MySQL.Connection_String);

            try
            {
                await conn.OpenAsync();

                string query = "SELECT * FROM " + table + ";";

                MySqlCommand cmd = new MySqlCommand(query, conn);
                
                Logging.Handler.Debug("Events.Sender.Check_Notifications", "MySQL_Prepared_Query", query);

                using (DbDataReader reader = await cmd.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            bool success = false;

                            if (severity == reader["severity"].ToString() || reader["severity"].ToString() == "4")
                            {
                                if (table == "mail_notifications")
                                {
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "mail_notifications", "true");
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "recipient", reader["mail_address"].ToString() ?? String.Empty);
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "subject", reported_by + ": " + _event);
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "body", description);
                                    string recipient = reader["mail_address"].ToString() ?? String.Empty;

                                    success = await Helper.Notifications.Smtp.Send_Mail(recipient, reported_by + ": " + _event, description);
                                }
                                else if (table == "microsoft_teams_notifications")
                                {
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "microsoft_teams_notifications", "true");
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "subject", reported_by + ": " + _event);
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "body", description);

                                    success = await Helper.Notifications.Microsoft_Teams.Send_Message(reader["id"].ToString() ?? String.Empty, reported_by + ": " + _event + Environment.NewLine + Environment.NewLine + description);
                                }
                                else if (table == "telegram_notifications")
                                {
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "telegram_notifications", "true");
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "subject", reported_by + ": " + _event);
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "body", description);

                                    success = await Helper.Notifications.Telegram.Send_Message(reader["id"].ToString() ?? String.Empty, reported_by + ": " + _event + Environment.NewLine + Environment.NewLine + description);
                                }
                                else if (table == "ntfy_sh_notifications")
                                {
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "ntfy_sh_notifications", "true");
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "subject", reported_by + ": " + _event);
                                    Logging.Handler.Debug("Events.Sender.Check_Notifications", "body", description);

                                    success = await Helper.Notifications.Ntfy_sh.Send_Message(reader["id"].ToString() ?? String.Empty, reported_by + ": " + _event + Environment.NewLine + Environment.NewLine + description);
                                }
                            }

                            // Update event
                            if (success)
                                await MySQL.Handler.Execute_Command("UPDATE `events` SET " + type + " = 1 WHERE id = " + id + ";");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Events.Sender.Check_Notifications", "MySQL_Query", ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }

        public static async Task Mark_Old_Read(string started_time, string finished_time)
        {
            try
            {
                Logging.Handler.Debug("Events.Sender.Mark_Old_Read", "started_time & finished_time", started_time + " " + finished_time);
                await MySQL.Handler.Execute_Command("UPDATE events SET mail_status = '1', ms_teams_status = '1', telegram_status = '1', ntfy_sh_status = '1' WHERE date < '" + finished_time + "';");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Events.Sender.Mark_Old_Read", "MySQL_Query", ex.Message);
            }
        }
    }
}
