using MySqlConnector;
using System.Data.Common;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using System;
using Microsoft.AspNetCore.Mvc.Formatters;

namespace NetLock_Server.Agent.Windows
{
    public class Version_Handler
    {
        public class Device_Identity_Entity
        {
            public string? agent_version { get; set; }
            public string? device_name { get; set; }
            public string? location_name { get; set; }
            public string? tenant_name { get; set; }
            public string? access_key { get; set; }
            public string? hwid { get; set; }
            public string? ip_address_internal { get; set; }
            public string? operating_system { get; set; }
            public string? domain { get; set; }
            public string? antivirus_solution { get; set; }
            public string? firewall_status { get; set; }
            public string? architecture { get; set; }
            public string? last_boot { get; set; }
            public string? timezone { get; set; }
            public string? cpu { get; set; }
            public string? mainboard { get; set; }
            public string? gpu { get; set; }
            public string? ram { get; set; }
            public string? tpm { get; set; }
            public string? environment_variables { get; set; }
        }

        public class Root_Entity
        {
            public Device_Identity_Entity? device_identity { get; set; }
        }

        public static async Task<string> Check_Version(string json)
        {
            try
            {
                // Extract JSON
                Root_Entity rootData = JsonSerializer.Deserialize<Root_Entity>(json);
                Device_Identity_Entity device_identity = rootData.device_identity;

                // Log the communicated agent version
                string agent_version = device_identity.agent_version;
                Logging.Handler.Debug("Agent.Windows.Version_Handler.Check_Version", "Communicated agent version", agent_version);

                // Read the appsettings.json file
                string appsettings_json = File.ReadAllText(Environment.CurrentDirectory + @"\appsettings.json");
                Logging.Handler.Debug("Agent.Windows.Version_Handler.Check_Version", "appsettings_json", appsettings_json);

                string windowsAgentVersion = string.Empty;

                // Deserialisierung des gesamten JSON-Strings
                using (JsonDocument document = JsonDocument.Parse(appsettings_json))
                {
                    JsonElement root = document.RootElement;

                    // Zugriff auf das "Version_Information"-Objekt
                    JsonElement versionInfoElement = root.GetProperty("Version_Information");

                    // Zugriff auf das "Windows_Agent"-Attribut innerhalb von "Version_Information"
                    JsonElement windowsElement = versionInfoElement.GetProperty("Windows");

                    // Zugriff auf das "Windows_Agent"-Attribut innerhalb von "Version_Information"
                    JsonElement commAgentElement = windowsElement.GetProperty("Comm_Agent");

                    // Konvertierung des Werts von "Windows_Agent" in einen String
                    windowsAgentVersion = commAgentElement.GetString();
                }

                Logging.Handler.Debug("Agent.Windows.Version_Handler.Check_Version", "windowsAgentVersion", windowsAgentVersion);

                // Check if the communicated agent version is equal to the version in the appsettings.json file
                if (agent_version == windowsAgentVersion)
                {
                    return "identical";
                }
                else
                {
                    return "different";
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Agent.Windows.Version_Handler.Check_Version", "", ex.ToString());
                return "Invalid request.";
            }
        }
    }
}
