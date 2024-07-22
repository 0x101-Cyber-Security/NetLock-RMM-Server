using MySqlConnector;
using System.Data.Common;
using System.Net.Mail;
using System.Net;
using System.Text.Json;
using NetLock_Server;

namespace Helper.Notifications
{
    public class Microsoft_Teams
    {
        public static async Task<string> Send_Message(string connector_name, string message)
        {
            string connector_url = String.Empty;

            MySqlConnection conn = new MySqlConnection(await NetLock_Server.MySQL.Config.Get_Connection_String());

            try
            {
                await conn.OpenAsync();

                MySqlCommand command = new MySqlCommand("SELECT * FROM microsoft_teams_notifications WHERE connector_name = '" + connector_name + "';", conn);
                using (DbDataReader reader = await command.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            connector_url = await Base64.Handler.Decode(reader["connector_url"].ToString() ?? "");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Microsoft_Teams", "Send_Message.Query_Connector_Info", ex.Message);
            }
            finally
            {
                conn.Close();
            }

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Erstellen Sie eine JSON-Payload für die Nachricht
                    string jsonPayload = $"{{ \"text\": \"{message}\" }}";

                    // Erstellen Sie den Inhalt der Anfrage
                    StringContent content = new StringContent(jsonPayload);

                    // Setzen Sie den Content-Type-Header auf "application/json"
                    content.Headers.Clear();
                    content.Headers.Add("Content-Type", "application/json");

                    // Senden Sie die POST-Anfrage an die Webhook-URL
                    HttpResponseMessage response = await client.PostAsync(connector_url, content);

                    // Überprüfen Sie die Antwort und behandeln Sie sie entsprechend
                    if (response.IsSuccessStatusCode) //Message sent successfully 
                    {
                        return "success";
                    }
                    else //Sending message failed
                    {
                        Logging.Handler.Error("Classes.Helper.Notifications.Microsoft_Teams", "Send_Message.Send", "status_code: " + response.StatusCode.ToString());

                        return response.StatusCode.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Microsoft_Teams", "Send_Message.Send", "status_code: " + ex.Message);
                return ex.Message;
            }
        }
    }
}
