using Microsoft.AspNetCore.Http;
using MySqlConnector;
using System.Data.Common;
using System.Net;
using Telegram.Bot;

namespace Helper.Notifications
{
    public class Telegram
    {
        public static async Task<string> Send_Message(string bot_name, string message)
        {
            string bot_token = String.Empty;
            string chat_id = String.Empty;

            MySqlConnection conn = new MySqlConnection(await NetLock_Server.MySQL.Config.Get_Connection_String());

            try
            {
                await conn.OpenAsync();

                MySqlCommand command = new MySqlCommand("SELECT * FROM telegram_notifications WHERE bot_name = '" + bot_name + "';", conn);
                using (DbDataReader reader = await command.ExecuteReaderAsync())
                {
                    if (reader.HasRows)
                    {
                        while (await reader.ReadAsync())
                        {
                            bot_token = reader["bot_token"].ToString() ?? String.Empty;
                            chat_id = reader["chat_id"].ToString() ?? String.Empty;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Telegram", "Send_Message.Query_Connector_Info", ex.Message);
            }
            finally
            {
                conn.Close();
            }

            //Send message
            try
            {
                var botClient = new TelegramBotClient(bot_token);
                var messageText = message;

                await botClient.SendTextMessageAsync(chat_id, messageText);

                return "success";
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.Helper.Notifications.Telegram", "Send_Message.Send", "status_code: " + ex.Message);
                return ex.Message;
            }       

        }
    }
}
