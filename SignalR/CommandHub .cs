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
                var deviceIdentityEncoded = Context.GetHttpContext().Request.Headers["Device-Identity"];

                // Decode the received JSON
                var deviceIdentityJson = Uri.UnescapeDataString(deviceIdentityEncoded);

                Logging.Handler.Debug("SignalR CommandHub", "OnConnectedAsync", "Device identity: " + deviceIdentityJson);

                // Save clientId and any other relevant data in your data structure
                _clientConnections.TryAdd(clientId, deviceIdentityJson);
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

        public async Task SendCommandToClient(string device_name, string location_name, string tenant_name, string command)
        {
            try
            {
                Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client: {device_name}, {location_name}, {tenant_name}: {command}");

                var clientId = _clientConnections.FirstOrDefault(x => x.Value.Contains(device_name) && x.Value.Contains(location_name) && x.Value.Contains(tenant_name)).Key;
                Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Client ID: {clientId}");

                Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client {clientId}: {command}");

                await Clients.Client(clientId).SendAsync("ReceiveCommand", command);

                Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client {clientId}: {command}");
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("SignalR CommandHub", "SendCommandToClient", ex.ToString());
            }
        }
    }

    public class ApiKeyMiddleware
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
    }
}
