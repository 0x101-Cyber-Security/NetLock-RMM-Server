using MySqlConnector;
using System.Data.Common;
using System.Text.Json;
using static NetLock_Server.Agent.Windows.Device_Handler;

namespace NetLock_Server.Agent.Windows
{
    public class Event_Handler
    {
        public class Device_Identity_Entity
        {
            public string agent_version { get; set; }
            public string device_name { get; set; }
            public string location_name { get; set; }
            public string tenant_name { get; set; }
            public string access_key { get; set; }
            public string hwid { get; set; }
            public string ip_address_internal { get; set; }
            public string operating_system { get; set; }
            public string domain { get; set; }
            public string antivirus_solution { get; set; }
            public string architecture { get; set; }
            public string last_boot { get; set; }
            public string timezone { get; set; }
            public string cpu { get; set; }
            public string mainboard { get; set; }
            public string gpu { get; set; }
            public string ram { get; set; }
            public string tpm { get; set; }
            public string environment_variables { get; set; }
        }

        public class Event_Entity
        {
            public string severity { get; set; }
            public string reported_by { get; set; }
            public string _event { get; set; }
            public string description { get; set; }
            public string type { get; set; }
            public string language { get; set; }
        }

        public class Root
        {
            public Device_Identity_Entity device_identity { get; set; }
            public Event_Entity _event { get; set; }
        }

        public static async Task<string> Consume(string json)
        {
            Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "json", json);

            MySqlConnection conn = new MySqlConnection(Application_Settings.connectionString);

            try
            {
                //Extract JSON
                Root rootData = JsonSerializer.Deserialize<Root>(json);
                Device_Identity_Entity device_identity = rootData.device_identity;
                Event_Entity _event = rootData._event;

                //Event data
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "severity", _event.severity);
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "reported_by", _event.reported_by);
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "_event", _event._event);
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "description", _event.description);
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "type", _event.type);
                Logging.Handler.Debug("Agent.Windows.Event_Handler.Consume", "language", _event.language);

                //Insert into database
                await conn.OpenAsync();

                string execute_query = "INSERT INTO `events` (`tenant_name`, `location_name`, `device_name`, `date`, `severity`, `reported_by`, `_event`, `description`, `type`, `language`) VALUES (@tenant_name, @location_name, @device_name, @date, @severity, @reported_by, @event, @description, @type, @language)";

                MySqlCommand cmd = new MySqlCommand(execute_query, conn);

                cmd.Parameters.AddWithValue("@tenant_name", device_identity.tenant_name);
                cmd.Parameters.AddWithValue("@location_name", device_identity.location_name);
                cmd.Parameters.AddWithValue("@device_name", device_identity.device_name);
                cmd.Parameters.AddWithValue("@date", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@severity", _event.severity);
                cmd.Parameters.AddWithValue("@reported_by", _event.reported_by);
                cmd.Parameters.AddWithValue("@event", _event._event);
                cmd.Parameters.AddWithValue("@description", _event.description);
                cmd.Parameters.AddWithValue("@type", _event.type);
                cmd.Parameters.AddWithValue("@language", _event.language);

                cmd.ExecuteNonQuery();

                await conn.CloseAsync();

                return "authorized";
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Agent.Windows.Event_Handler.Consume", "Result", ex.Message);
                return "invalid";
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
    }
}
