using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;

namespace NetLock_Server.SignalR
{
    public class CommandHub : Hub
    {
        private readonly ConcurrentDictionary<string, string> _clientConnections;

        public CommandHub()
        {
            _clientConnections = ConnectionManager.Instance.ClientConnections;
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

        /*public async Task SendCommand(string command)
        {
            Logging.Handler.Debug("SignalR CommandHub", "SendCommand", "Command sent to all clients: " + command);
            
            await Clients.All.SendAsync("ReceiveCommand", command);
        }*/

        public async Task SendMessageToClient(string device_name, string location_name, string tenant_name, string command)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Command sent to client: {device_name}, {location_name}, {tenant_name}: {command}");

                var clientId = _clientConnections.FirstOrDefault(x => x.Value.Contains(device_name) && x.Value.Contains(location_name) && x.Value.Contains(tenant_name)).Key;
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Client ID: {clientId}");

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Command sent to client {clientId}: {command}");

                await Clients.Client(clientId).SendAsync("ReceiveMessage", command);

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClient", $"Command sent to client {clientId}: {command}");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "SendMessageToClient", ex.ToString());
            }
        }

        // hier weiter 28.06.2024 00:45

        public async Task<string> SendMessageToClientAndWaitForResponse(string device_name, string location_name, string tenant_name, string command)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Command sent to client: {device_name}, {location_name}, {tenant_name}: {command}");

                var clientId = _clientConnections.FirstOrDefault(x => x.Value.Contains(device_name) && x.Value.Contains(location_name) && x.Value.Contains(tenant_name)).Key;
                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Client ID: {clientId}");

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Command sent to client {clientId}: {command}");

                // Send command to client and wait for response
                var response = await Clients.Client(clientId).InvokeAsync<string>("ReceiveMessageAndWaitForResponse", command, CancellationToken.None);

                Logging.Handler.Debug("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", $"Response received from client {clientId}: {response}");

                // Process the response here (e.g., update UI, log, etc.)

                return response;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "SendMessageToClientAndWaitForResponse", ex.ToString());
                return null;
            }
        }


        // Method to receive commands from the webconsole
        public async Task MessageReceivedFromWebconsole(string message)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromWebconsole", $"Received message from client: {message}");

                // Process the message here
                // For example, you can log the message or perform some action based on the content

                // Optionally, you can send a response back to the client
                await Clients.Caller.SendAsync("ReceiveCommandResponse", "Message received and processed.");

                // Send the command to the device
                await SendMessageToClient("DeviceName", "LocationName", "TenantName", message);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "MessageReceivedFromWebconsole", ex.ToString());
            }
        }

        // Method to receive commands from the devices
        public async Task MessageReceivedFromDevice(string message)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "MessageReceivedFromDevice", $"Received message from client: {message}");

                // Process the message here
                // For example, you can log the message or perform some action based on the content

                // Optionally, you can send a response back to the client
                await Clients.Caller.SendAsync("ReceiveCommandResponse", "Message received and processed.");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "MessageReceivedFromDevice", ex.ToString());
            }
        }


    }


    /*public class ApiKeyMiddleware
    {
        private readonly RequestDelegate _next;
        private const string API_KEY_HEADER_NAME = "X-API-KEY";

        public ApiKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue(API_KEY_HEADER_NAME, out var extractedApiKey))
            {
                context.Response.StatusCode = 401; // Unauthorized
                await context.Response.WriteAsync("API Key was not provided.");
                return;
            }

            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = "123456789";

            if (!apiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 401; // Unauthorized
                await context.Response.WriteAsync("Unauthorized client.");
                return;
            }

            await _next(context);
        }
    }*/
}

