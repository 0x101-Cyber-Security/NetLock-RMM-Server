using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

using static NetLock_Server.Agent.Windows.Authentification;

namespace NetLock_Server.SignalR
{
    public class CommandHub : Hub
    {
        public class Device_Identity
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
            // public string? environment_variables { get; set; }
        }

        public class Admin_Identity
        {
            public string admin_username { get; set; }
            public string admin_password { get; set; } // hashed
            public string api_key { get; set; }
            public string session_id { get; set; }

        }

        public class Target_Device
        {
            public string device_name { get; set; }
            public string location_name { get; set; } // hashed
            public string tenant_name { get; set; }
        }

        public class Command
        {
            public int type { get; set; }
            public bool wait_response { get; set; }
            public string powershell_code { get; set; } // hashed
        }

        public class Root_Entity
        {
            public Device_Identity? device_identity { get; set; }
            public Admin_Identity? admin_identity { get; set; }
            public Target_Device? target_device { get; set; }
            public Command? command { get; set; }
        }

        private readonly ConcurrentDictionary<string, string> _clientConnections;
        private readonly ConcurrentDictionary<string, string> _adminCommands = new ConcurrentDictionary<string, string>();
        private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _responseTasks;


        public CommandHub()
        {
            _clientConnections = ConnectionManager.Instance.ClientConnections;
            //_responseTasks = new ConcurrentDictionary<string, TaskCompletionSource<string>>();

        }

        public override Task OnConnectedAsync()
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "OnConnectedAsync", "Client connected");

                var clientId = Context.ConnectionId;

                // Extract the device identity from the request headers
                var deviceIdentityEncoded = Context.GetHttpContext().Request.Headers["Device-Identity"];
                var adminIdentityEncoded = Context.GetHttpContext().Request.Headers["Admin-Identity"];

                if (string.IsNullOrEmpty(deviceIdentityEncoded) && string.IsNullOrEmpty(adminIdentityEncoded))
                {
                    Logging.Handler.Debug("SignalR CommandHub", "OnConnectedAsync", "Neither Device-Identity nor Admin-Identity was provided.");
                    Context.Abort();
                    return Task.CompletedTask;
                }

                string decodedIdentityJson = string.Empty;

                if (!string.IsNullOrEmpty(deviceIdentityEncoded))
                {
                    decodedIdentityJson = Uri.UnescapeDataString(deviceIdentityEncoded);
                    Logging.Handler.Debug("SignalR CommandHub", "OnConnectedAsync", "Device identity: " + decodedIdentityJson);
                }
                else if (!string.IsNullOrEmpty(adminIdentityEncoded))
                {
                    decodedIdentityJson = Uri.UnescapeDataString(adminIdentityEncoded);
                    Logging.Handler.Debug("SignalR CommandHub", "OnConnectedAsync", "Admin identity: " + decodedIdentityJson);
                }

                // Save clientId and any other relevant data in your data structure
                _clientConnections.TryAdd(clientId, decodedIdentityJson);    
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "OnConnectedAsync", ex.ToString());
            }

            return base.OnConnectedAsync();
        }

        public override Task OnDisconnectedAsync(Exception exception)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "OnDisconnectedAsync", "Client disconnected");

                var clientId = Context.ConnectionId;

                // Remove the client from the data structure when it logs out
                _clientConnections.TryRemove(clientId, out _);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "OnDisconnectedAsync", ex.ToString());
            }

            return base.OnDisconnectedAsync(exception);
        }

        public async Task<string> Get_Device_ClientId(string device_name, string location_name, string tenant_name)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "Get_Device_ClientID", $"Device: {device_name}, Location: {location_name}, Tenant: {tenant_name}");

                // List all connected clients
                foreach (var client in _clientConnections)
                {
                    Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Connected clients: {client.Key}, {client.Value}");
                }

                var clientId = _clientConnections.FirstOrDefault(x =>
                {
                    try
                    {
                        var rootData = JsonSerializer.Deserialize<Root_Entity>(x.Value);
                        return rootData?.device_identity != null &&
                               rootData.device_identity.device_name == device_name &&
                               rootData.device_identity.location_name == location_name &&
                               rootData.device_identity.tenant_name == tenant_name;
                    }
                    catch (JsonException)
                    {
                        return false;
                    }
                }).Key;

                if (string.IsNullOrEmpty(clientId))
                {
                    Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", "Client ID not found.");
                }

                return clientId;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "Get_Device_ClientID", ex.ToString());
                return null;
            }
        }

        public async Task<string> Get_Admin_ClientId_By_ResponseId(string responseId)
        {
            try
            {
                // list all connected admin clients
                foreach (var client in _adminCommands)
                {
                    Logging.Handler.Debug("SignalR CommandHub", "Get_Admin_ClientId_By_ResponseId", $"Connected admin clients: {client.Key}, {client.Value}");
                }

                if (_adminCommands.TryGetValue(responseId, out string clientId))
                {
                    return clientId;
                }

                return null; // If the responseId is not found
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "Get_Admin_ClientId_By_ResponseId", ex.ToString());
                return null;
            }
        }

        public async Task SendMessageToClient(string client_id, string command_json)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Sending command to client {client_id}: {command_json}");

                // Send the command to the client
                await Clients.Client(client_id).SendAsync("ReceiveMessage", command_json);

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Command sent to client {client_id}: {command_json}");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "SendMessageToClient", ex.ToString());
            }
        }

        public async Task SendMessageToClientAndWaitForResponse(string admin_client_id, string client_id, string command_json)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Sending command to client {client_id}: {command_json}");

                // Generate a unique responseId for the command
                var responseId = Guid.NewGuid().ToString();

                // Save responseId & admin_client_id
                _adminCommands.TryAdd(responseId, admin_client_id);

                // Add the responseId to the command JSON
                command_json = AddResponseIdToJson(command_json, responseId);

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Modified command JSON with responseId: {command_json}");

                // Send the command to the client
                await Clients.Client(client_id).SendAsync("SendMessageToClientAndWaitForResponse", command_json);

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Command sent to client {client_id}: {command_json}");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", ex.ToString());
            }
        }

        // Receive response from client and send it back to the admin client
        public async Task ReceiveClientResponse(string responseId, string response)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "ReceiveClientResponse", $"Received response from client. ResponseId: {responseId} response: {response}");
                
                // Get the admin client ID from the dictionary
                string admin_client_id = await Get_Admin_ClientId_By_ResponseId(responseId);

                Logging.Handler.Debug("SignalR CommandHub", "ReceiveClientResponse", $"Admin client ID: {admin_client_id}");

                if (string.IsNullOrEmpty(admin_client_id))
                {
                    Logging.Handler.Debug("SignalR CommandHub", "ReceiveClientResponse", "Admin client ID not found.");
                    return;
                }

                // Send the response back to the admin client
                await Clients.Client(admin_client_id).SendAsync("ReceiveClientResponse", response);

                Logging.Handler.Debug("SignalR CommandHub", "ReceiveClientResponse", $"Response sent to admin client {admin_client_id}: {response}");

                // Remove the responseId from the dictionary
                _adminCommands.TryRemove(responseId, out _);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "ReceiveClientResponse", ex.ToString());
            }
        }


        // Method to receive commands from the webconsole
        public async Task MessageReceivedFromWebconsole(string message)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Received message from client: {message}");

                // Decode the received JSON
                string adminIdentityJson = String.Empty;
                adminIdentityJson = Uri.UnescapeDataString(message);
                Logging.Handler.Debug("Agent.Windows.Authentification.MessageReceivedFromWebconsole", "adminIdentityJson", adminIdentityJson);

                // Deserialize the JSON
                Root_Entity rootData = new Root_Entity();
                rootData = JsonSerializer.Deserialize<Root_Entity>(adminIdentityJson);
                
                Admin_Identity admin_identity = new Admin_Identity();
                admin_identity = rootData.admin_identity;
                
                Target_Device target_device = new Target_Device();
                target_device = rootData.target_device;

                Command command = new Command();
                command = rootData.command;

                Logging.Handler.Debug("Agent.Windows.Authentification.MessageReceivedFromWebconsole", "rootData", "extracted");
                Logging.Handler.Debug("Agent.Windows.Authentification.MessageReceivedFromWebconsole", "target_device.device_name", target_device.device_name);

                string commandJson = JsonSerializer.Serialize(command);

                Logging.Handler.Debug("Agent.Windows.Authentification.MessageReceivedFromWebconsole", "commandJson", commandJson);

                // Get client id
                string client_id = await Get_Device_ClientId(target_device.device_name, target_device.location_name, target_device.tenant_name);

                Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Client ID: {client_id}");

                if (String.IsNullOrEmpty(client_id))
                {
                    Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", "Client ID not found.");
                    await Clients.Caller.SendAsync("ReceiveCommandResponse", "Device not connected.");

                    return;
                }

                // Get admins client id
                var admin_client_id = Context.ConnectionId;

                // Send the command to the client and wait for the response
                if (command.wait_response)
                {
                    await SendMessageToClientAndWaitForResponse(admin_client_id, client_id, commandJson);
                    
                    Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Triggered command with waiting for response.");
                }
                else // Send the command to the client without waiting for the response
                {
                    await SendMessageToClient(client_id, commandJson);
                    
                    Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Triggered command without waiting for response.");
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "MessageReceivedFromWebconsole", ex.ToString());
            }
        }

        private string AddResponseIdToJson(string json, string responseId)
        {
            try
            {
                // Parse the existing JSON string
                using (JsonDocument document = JsonDocument.Parse(json))
                {
                    // Create a dictionary to hold the properties
                    Dictionary<string, JsonElement> properties = new Dictionary<string, JsonElement>();

                    // Iterate over the properties of the existing JSON and add them to the new JSON object
                    foreach (var property in document.RootElement.EnumerateObject())
                    {
                        properties.Add(property.Name, property.Value.Clone());
                    }

                    // Add the responseId to the new JSON object
                    properties.Add("response_id", JsonDocument.Parse($"\"{responseId}\"").RootElement);

                    // Serialize the new JSON object back to string
                    return JsonSerializer.Serialize(properties);
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "AddResponseIdToJson", $"Error adding responseId to JSON: {ex.ToString()}");
                throw; // Rethrow the exception to handle it appropriately in the calling method
            }
        }

    }
}

