using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using NetLock_Server.Agent.Windows;
using System.Security.Principal;
using Microsoft.AspNetCore.SignalR;
using NetLock_Server.SignalR;
using System.Net;
using System;
using System.Text.Json;
using static NetLock_Server.Agent.Windows.Authentification;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddSignalR();
builder.Services.AddSingleton<CommandHub>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseRouting();

//app.UseMiddleware<ApiKeyMiddleware>();

// Only use the middleware for the commandHub, to verify the signalR connection
app.UseWhen(context => context.Request.Path.StartsWithSegments("/commandHub"), appBuilder =>
{
    appBuilder.UseMiddleware<JsonAuthMiddleware>();
});

app.MapHub<CommandHub>("/commandHub");

app.UseHttpsRedirection();

//API URLs*
//Check Version
app.MapPost("/Agent/Windows/Check_Version", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Check_Version", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Features.Get<IHttpConnectionFeature>()?.RemoteIpAddress?.ToString();

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        // Check the version of the device
        string version_status = await Version_Handler.Check_Version(json);

        // Return the device status
        context.Response.StatusCode = 200;
        await context.Response.WriteAsync(version_status);
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Check_Version", ex.Message);
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger0").WithOpenApi();

//Verify Device
app.MapPost("/Agent/Windows/Verify_Device", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Verify_Device", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        // Verify the device
        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        await context.Response.WriteAsync(device_status);
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Verify_Device", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger1").WithOpenApi();


//Update device information
app.MapPost("/Agent/Windows/Update_Device_Information", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Update_Device_Information", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        // Verify the device
        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        // Check if the device is authorized, synced or not synced. If so, update the device information
        if (device_status == "authorized" || device_status == "synced" || device_status == "not_synced")
        {
            await Device_Handler.Update_Device_Information(json);
            context.Response.StatusCode = 200;
        }
        else
        {
            context.Response.StatusCode = 403;
        }

        await context.Response.WriteAsync(device_status);
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Update_Device_Information", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger2").WithOpenApi();


//Insert events
app.MapPost("/Agent/Windows/Events", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Events", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        // Verify the device
        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        // Check if the device is authorized. If so, consume the events
        if (device_status == "authorized" || device_status == "synced" || device_status == "not_synced")
        {
            device_status = await Event_Handler.Consume(json);
            context.Response.StatusCode = 200;
        }
        else
        {
            context.Response.StatusCode = 403;
        }

        await context.Response.WriteAsync(device_status);
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Events", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger3").WithOpenApi();



//Get policy
app.MapPost("/Agent/Windows/Policy", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Policy", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        // Verify the device
        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        string device_policy_json = string.Empty;

        // Check if the device is authorized, synced, or not synced. If so, get the policy
        if (device_status == "authorized" || device_status == "synced" || device_status == "not_synced")
        {
            device_policy_json = await Policy_Handler.Get_Policy(json, ip_address_external);
            context.Response.StatusCode = 200;
            await context.Response.WriteAsync(device_policy_json);
        }
        else // If the device is not authorized, return the device status as unauthorized
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync(device_status);
        }
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Policy", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger4").WithOpenApi();

//Check Version
app.MapPost("/Agent/Windows/Remote/Command", async (HttpContext context, IHubContext<CommandHub> hubContext) =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Remote/Command", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Features.Get<IHttpConnectionFeature>()?.RemoteIpAddress?.ToString();

        string api_key = string.Empty;

        // Read the JSON data
        string json;
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            json = await reader.ReadToEndAsync() ?? string.Empty;
        }

        bool api_key_status = await NetLock_Server.SignalR.Webconsole.Handler.Verify_Api_Key(json);

        if (api_key_status == false)
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("Invalid api key.");
            return;
        }

        // Get the command
        string command = await NetLock_Server.SignalR.Webconsole.Handler.Get_Command(json);

        // Get list of all connected clients
        var clients = ConnectionManager.Instance.ClientConnections;
        
        foreach (var client in clients)
            Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Remote/Command", "Client: " + client.Key + " - " + client.Value);

        // Check if the command is "sync_all" that means all devices should sync with the server
        if (command == "sync_all")
        {
            await hubContext.Clients.All.SendAsync("ReceiveCommand", "sync"); // Send command to all clients
        }
        else if (command == "client_powershell")
        {
            //          CommandHub commandHub = new CommandHub();

            //await hubContext.Clients.Client("DEV01").SendAsync("ReceiveCommand", "powershell_command");
            //            await commandHub.SendCommandToClient("DEV01", "Köln1", "0x101 Cyber Security", "powershell_command");

            // Create an instance of CommandHub
            var commandHub = new CommandHub();

            string device_name = "DEV01";
            string location_name = "Köln1";
            string tenant_name = "0x101 Cyber Security";

            //await commandHub.SendCommandToClient(hubContext, deviceName, locationName, tenantName, command);
            // hier weiter machen. SignalR Backend weiter überarbeiten, dann Funktion hinzufügen, das Client A (Webconsole) Befehle an Client B (Agent) senden kann und eine entsprechende Antwort erhält. Befehls Modell implementieren und dokumentieren
            Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client: {device_name}, {location_name}, {tenant_name}: {command}");

            var clientId = clients.FirstOrDefault(x => x.Value.Contains(device_name) && x.Value.Contains(location_name) && x.Value.Contains(tenant_name)).Key;
            Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Client ID: {clientId}");

            Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client {clientId}: {command}");

            await hubContext.Clients.Client(clientId).SendAsync("ReceiveMessage", command);

            Logging.Handler.Debug("SignalR CommandHub", "SendCommandToClient", $"Command sent to client {clientId}: {command}");
        }

        // Return the device status
        context.Response.StatusCode = 200;
        await context.Response.WriteAsync("ok");
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Remote/Command", ex.Message);
        await context.Response.WriteAsync("Invalid request.");
    }
}).WithName("Swagger5").WithOpenApi();


//Start server
app.Run();

