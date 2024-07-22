using MySqlConnector;
using System.Data.Common;
using System.Text;

namespace Helper.Notifications
{
    public class Ntfy_sh
    {
        public static async Task<string> Send_Message(string topic_name, string message)
        {
            string topic_url = String.Empty;
            string access_token = String.Empty;

            MySqlConnection conn = new MySqlConnection(await NetLock_Server.MySQL.Config.Get_Connection_String());
            try
            {
                await conn.OpenAsync();

                MySqlCommand command = new MySqlCommand("SELECT * FROM ntfy_sh_notifications WHERE topic_name = '" + await Base64.Handler.Encode(topic_name) + "';", conn);
                using (DbDataReader reader = await command.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            topic_url = await Base64.Handler.Decode(reader["topic_url"].ToString() ?? "");
                            access_token = await Base64.Handler.Decode(reader["access_token"].ToString() ?? "");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Ntfy_sh", "Send_Message.Query_Connector_Info", ex.Message);
            }
            finally
            {
                conn.Close();
            }

            //Send message
            try
            {
                if (access_token.Length < 3)
                {
                    using (var httpClient = new HttpClient())
                    {
                        var content = new StringContent(message, Encoding.UTF8, "text/plain");
                        var response = await httpClient.PostAsync(topic_url, content);

                        if (response.IsSuccessStatusCode) //Message sent successfully 
                        {
                            return "success";
                        }
                        else //Sending message failed
                        {
                            Logging.Handler.Error("Classes.Helper.Notifications.Microsoft_Teams", "Send_Message.Send(no auth)", "status_code: " + response.StatusCode.ToString() + " Url: " + topic_url);

                            return response.StatusCode.ToString();
                        }
                    }
                }
                else
                {
                    using (var httpClient = new HttpClient())
                    {
                        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {access_token}");

                        var content = new StringContent(message, Encoding.UTF8, "text/plain");
                        var response = await httpClient.PostAsync(topic_url, content);

                        if (response.IsSuccessStatusCode) //Message sent successfully 
                        {
                            return "success";
                        }
                        else //Sending message failed
                        {
                            Logging.Handler.Error("Classes.Helper.Notifications.Microsoft_Teams", "Send_Message.Send(with auth)", "status_code: " + response.StatusCode.ToString() + " Url: " + topic_url);

                            return response.StatusCode.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Ntfy_sh", "Send_Message.Send", "status_code: " + ex.Message + " Url: " + topic_url);
                return ex.Message;
            }
        }
    }
}
