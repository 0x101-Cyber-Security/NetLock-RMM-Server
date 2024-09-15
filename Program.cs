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
using NetLock_Server;
using NetLock_Server.Events;
using Microsoft.Extensions.Primitives;
using LettuceEncrypt;
using System.Threading;
using System.IO;
using NetLock_RMM_Server.Helper;

var builder = WebApplication.CreateBuilder(args);

// Load configuration from appsettings.json
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Get UseHttps from config
var https = builder.Configuration.GetValue<bool>("Kestrel:Endpoint:Https:Enabled");
var https_force = builder.Configuration.GetValue<bool>("Kestrel:Endpoint:Https:Force");
var hsts = builder.Configuration.GetValue<bool>("Kestrel:Endpoint:Https:Hsts:Enabled");
var hsts_max_age = builder.Configuration.GetValue<int>("Kestrel:Endpoint:Https:Hsts:MaxAge");
var letsencrypt = builder.Configuration.GetValue<bool>("LettuceEncrypt:Enabled");
var cert_path = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Path"];
var cert_password = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Password"];

var role_comm = builder.Configuration.GetValue<bool>("Kestrel:Roles:Comm");
var role_update = builder.Configuration.GetValue<bool>("Kestrel:Roles:Update");
var role_trust = builder.Configuration.GetValue<bool>("Kestrel:Roles:Trust");
var role_remote = builder.Configuration.GetValue<bool>("Kestrel:Roles:Remote");
var role_notification = builder.Configuration.GetValue<bool>("Kestrel:Roles:Notification");
var role_file = builder.Configuration.GetValue<bool>("Kestrel:Roles:File");

Console.WriteLine("Version: " + Application_Settings.version);

Console.WriteLine("Configuration loaded from appsettings.json");

// Output kestrel configuration
Console.WriteLine($"Server role (comm): {role_comm}");
Console.WriteLine($"Server role (update): {role_update}");
Console.WriteLine($"Server role (trust): {role_trust}");
Console.WriteLine($"Server role (remote): {role_remote}");
Console.WriteLine($"Server role (notification): {role_notification}");
Console.WriteLine($"Server role (file): {role_file}");

Console.WriteLine($"Http: {builder.Configuration.GetValue<bool>("Kestrel:Endpoint:Http:Enabled")}");
Console.WriteLine($"Http Port: {builder.Configuration.GetValue<int>("Kestrel:Endpoint:Http:Port")}");
Console.WriteLine($"Https: {https}");
Console.WriteLine($"Https Port: {builder.Configuration.GetValue<int>("Kestrel:Endpoint:Https:Port")}");
Console.WriteLine($"Https (force): {https_force}");
Console.WriteLine($"Hsts: {hsts}");
Console.WriteLine($"Hsts Max Age: {hsts_max_age}");
Console.WriteLine($"LetsEncrypt: {letsencrypt}");

Console.WriteLine($"Custom Certificate Path: {cert_path}");
Console.WriteLine($"Custom Certificate Password: {cert_password}");

// Output mysql configuration
var mysqlConfig = builder.Configuration.GetSection("MySQL").Get<NetLock_Server.MySQL.Config>();
Console.WriteLine($"MySQL Server: {mysqlConfig.Server}");
Console.WriteLine($"MySQL Port: {mysqlConfig.Port}");
Console.WriteLine($"MySQL Database: {mysqlConfig.Database}");
Console.WriteLine($"MySQL User: {mysqlConfig.User}");
Console.WriteLine($"MySQL Password: {mysqlConfig.Password}");
Console.WriteLine($"MySQL SSL Mode: {mysqlConfig.SslMode}");
Console.WriteLine($"MySQL additional parameters: {mysqlConfig.AdditionalConnectionParameters}");

// Output firewall status
bool microsoft_defender_firewall_status = NetLock_Server.Microsoft_Defender_Firewall.Handler.Status();

if (microsoft_defender_firewall_status)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("Microsoft Defender Firewall is enabled.");
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("Microsoft Defender Firewall is disabled. You should enable it for your own safety. NetLock adds firewall rules automatically according to your configuration.");
}

Console.ResetColor();

// Check logs dir
if (!Directory.Exists(Application_Paths.logs_dir))
    Directory.CreateDirectory(Application_Paths.logs_dir);

// Add firewall rule for HTTP
NetLock_Server.Microsoft_Defender_Firewall.Handler.Rule_Inbound(builder.Configuration.GetValue<int>("Kestrel:Endpoint:Http:Port").ToString());
NetLock_Server.Microsoft_Defender_Firewall.Handler.Rule_Outbound(builder.Configuration.GetValue<int>("Kestrel:Endpoint:Http:Port").ToString());

if (https)
{
    // Add firewall rule for HTTPS
    NetLock_Server.Microsoft_Defender_Firewall.Handler.Rule_Inbound(builder.Configuration.GetValue<int>("Kestrel:Endpoint:Https:Port").ToString());
    NetLock_Server.Microsoft_Defender_Firewall.Handler.Rule_Outbound(builder.Configuration.GetValue<int>("Kestrel:Endpoint:Https:Port").ToString());

    if (letsencrypt)
        builder.Services.AddLettuceEncrypt();
}

// Configure Kestrel server options
builder.WebHost.UseKestrel(k =>
{
    IServiceProvider appServices = k.ApplicationServices;

    if (https)
    {
        k.Listen(IPAddress.Any, builder.Configuration.GetValue<int>("Kestrel:Endpoint:Https:Port"), o =>
        {
            if (letsencrypt)
            {
                o.UseHttps(h =>
                {
                    h.UseLettuceEncrypt(appServices);
                });
            }
            else
            {
                if (!string.IsNullOrEmpty(cert_password) && File.Exists(cert_path))
                {
                    o.UseHttps(cert_path, cert_password);
                }
                else
                {
                    Console.WriteLine("Default certificate file not found and Let's Encrypt certificate is not enabled.");
                }
            }
        });
    }

    k.Listen(IPAddress.Any, builder.Configuration.GetValue<int>("Kestrel:Endpoint:Http:Port"));
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddSignalR();
builder.Services.AddSingleton<CommandHub>();
builder.Services.AddSignalR(options =>
{
    options.MaximumReceiveMessageSize = 102400000; // Increase maximum message size to 100 MB
});

// Add timer to process events for notifications
async Task Events_Task()
{
    string started_time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

    Console.WriteLine("Periodic task executed at: " + started_time);
    await NetLock_Server.Events.Sender.Smtp("mail_status", "mail_notifications");
    await NetLock_Server.Events.Sender.Smtp("ms_teams_status", "microsoft_teams_notifications");
    await NetLock_Server.Events.Sender.Smtp("telegram_status", "telegram_notifications");
    await NetLock_Server.Events.Sender.Smtp("ntfy_sh_status", "ntfy_sh_notifications");

    string finished_time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    Console.WriteLine("Periodic task finished at: " + finished_time);

    await NetLock_Server.Events.Sender.Mark_Old_Read(started_time, finished_time);
}

// Wrapper for Timer
void Events_TimerCallback(object state)
{
    if (role_notification)
    {
        // Call the asynchronous method and do not block it
        _ = Events_Task();
    }
}

Timer events_timer = new Timer(Events_TimerCallback, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");

    if (hsts)
    {
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }
}

if (https_force)
{
    app.UseHttpsRedirection();
}

app.UseRouting();

// Only use the middleware for the commandHub, to verify the signalR connection
app.UseWhen(context => context.Request.Path.StartsWithSegments("/commandHub"), appBuilder =>
{
    appBuilder.UseMiddleware<JsonAuthMiddleware>();
});

app.MapHub<CommandHub>("/commandHub");

//API URLs*
//Check Version
if (role_comm)
{
    app.MapPost("/Agent/Windows/Check_Version", async context =>
    {
        try
        {
            Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Check_Version", "Request received.");

            // Add headers
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

            // Get the remote IP address
            string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Features.Get<IHttpConnectionFeature>()?.RemoteIpAddress?.ToString();

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

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
            Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Check_Version", ex.ToString());
            await context.Response.WriteAsync("Invalid request.");
        }
    }).WithName("Swagger0").WithOpenApi();
}

if (role_comm)
{
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

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Verify_Device", "No guid provided. Unauthorized.");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

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
            Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Verify_Device", ex.ToString());

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Invalid request.");
        }
    }).WithName("Swagger1").WithOpenApi();
}

if (role_comm)
{
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

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

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
}

if (role_comm)
{
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

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

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
}

if (role_comm)
{
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

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

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
}

//Remote Command: Will be used in later development
/*app.MapPost("/Agent/Windows/Remote/Command", async (HttpContext context, IHubContext<CommandHub> hubContext) =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Remote/Command", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Features.Get<IHttpConnectionFeature>()?.RemoteIpAddress?.ToString();

        // Verify package guid
        bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

        if (hasPackageGuid == false)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized.");
            return;
        }
        else
        {
            bool package_guid_status = await Helper.Verify_Package_Guid(package_guid);

            if (package_guid_status == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
        }

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
*/

// File upload public
/*
app.MapPost("/public/upload", async context =>
{
    try
    {
        Logging.Handler.Debug("/public/upload", "Request received.", "");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

        // Check if the request has a file
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid request. No file uploaded #1.");
            return;
        }

        var form = await context.Request.ReadFormAsync();
        var file = form.Files.FirstOrDefault();
        if (file == null || file.Length == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid request. No file uploaded #2.");
            return;
        }

        // Set the upload path
        var uploadPath = Application_Paths._public_uploads_user;

        Logging.Handler.Debug("/public/upload", "uploadPath", uploadPath);

        // Ensure the upload directory exists
        if (!Directory.Exists(uploadPath))
            Directory.CreateDirectory(uploadPath);

        // Save the file
        var filePath = Path.Combine(uploadPath, file.FileName);
        Logging.Handler.Debug("/public/upload", "filePath", filePath);

        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        context.Response.StatusCode = 200;
        await context.Response.WriteAsync("0"); // success
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("/public/upload", "General error", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("1"); // something went wrong
    }
}).WithName("public_upload").WithOpenApi();
*/

if (role_file)
{
    // File download public
    app.MapGet("/public/downloads/{fileName}", async context =>
    {
        try
        {
            Logging.Handler.Debug("/public/downloads", "Request received.", "");

            var fileName = (string)context.Request.RouteValues["fileName"];
            var downloadPath = Application_Paths._public_downloads_user + "\\" + fileName;

            if (!File.Exists(downloadPath))
            {
                Logging.Handler.Error("GET Request Mapping", "/public_download", "File not found: " + downloadPath);
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("File not found.");
                return;
            }

            var memory = new MemoryStream();
            using (var stream = new FileStream(downloadPath, FileMode.Open))
            {
                await stream.CopyToAsync(memory);
            }
            memory.Position = 0;

            context.Response.ContentType = "application/octet-stream";
            context.Response.Headers.Add("Content-Disposition", $"attachment; filename={fileName}");
            await memory.CopyToAsync(context.Response.Body);
        }
        catch (Exception ex)
        {
            Logging.Handler.Error("GET Request Mapping", "/public_download", ex.Message);

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("An error occurred while downloading the file.");
        }
    }).WithName("public_download").WithOpenApi();
}

// File upload private - admin, will be use in later development
if (role_file)
{
    app.MapPost("/private/upload/remote/temp", async context =>
    {
        try
        {
            Logging.Handler.Debug("/private/upload", "Request received.", "");

            // Add headers
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

            // Get the remote IP address from the X-Forwarded-For header
            string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

            // Check authorization
            bool hasAdminUsername = context.Request.Headers.TryGetValue("username", out StringValues admin_username);
            bool hasAdminPassword = context.Request.Headers.TryGetValue("password", out StringValues admin_password);
            Logging.Handler.Debug("/private/upload", "hasAdminUsername", hasAdminUsername.ToString());
            Logging.Handler.Debug("/private/upload", "hasAdminPassword", hasAdminPassword.ToString());


            if (!hasAdminUsername || !hasAdminPassword)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            // Verify admin identity
            bool adminIdentityStatus = await Authentification.Verify_Admin(admin_username, admin_password);

            if (!adminIdentityStatus)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            // Check if the request has a file
            if (!context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid request. No file uploaded #1.");
                return;
            }

            var form = await context.Request.ReadFormAsync();
            var file = form.Files.FirstOrDefault();
            if (file == null || file.Length == 0)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid request. No file uploaded #2.");
                return;
            }

            // Set the upload path
            var uploadPath = Application_Paths._private_uploads_remote_temp;

            Logging.Handler.Debug("/private/upload", "uploadPath", uploadPath);

            // Ensure the upload directory exists
            if (!Directory.Exists(uploadPath))
                Directory.CreateDirectory(uploadPath);

            // Delete existing file
            var existingFile = Path.Combine(uploadPath, file.FileName);
            if (File.Exists(existingFile))
                File.Delete(existingFile);

            // Save the file
            var filePath = Path.Combine(uploadPath, file.FileName);
            Logging.Handler.Debug("/private/upload", "filePath", filePath);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            context.Response.StatusCode = 200;
            await context.Response.WriteAsync("0"); // success
        }
        catch (Exception ex)
        {
            Logging.Handler.Error("/private/upload", "General error", ex.Message);

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("1"); // something went wrong
        }
    }).WithName("private_upload").WithOpenApi();
}

if (role_file)
{
    // File download private - admin, will be use in later development
    app.MapGet("/private/downloads/remote/temp/{fileName}", async context =>
    {
        try
        {
            Logging.Handler.Debug("private/downloads/", "Request received.", "");

            // Add headers
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

            // Get the remote IP address from the X-Forwarded-For header
            string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

            // Check authorization
            bool hasAdminUsername = context.Request.Headers.TryGetValue("username", out StringValues admin_username);
            bool hasAdminPassword = context.Request.Headers.TryGetValue("password", out StringValues admin_password);
            Logging.Handler.Debug("/private/upload", "hasAdminUsername", hasAdminUsername.ToString());
            Logging.Handler.Debug("/private/upload", "hasAdminPassword", hasAdminPassword.ToString());

            if (!hasAdminUsername || !hasAdminPassword)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            // Verify admin identity
            bool adminIdentityStatus = await Authentification.Verify_Admin(admin_username, admin_password);

            if (!adminIdentityStatus)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            var fileName = (string)context.Request.RouteValues["fileName"];
            var downloadPath = Application_Paths._private_downloads_remote_temp + "\\" + fileName;

            if (!File.Exists(downloadPath))
            {
                Logging.Handler.Error("GET Request Mapping", "/public_download", "File not found: " + downloadPath);
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("File not found.");
                return;
            }

            var memory = new MemoryStream();
            using (var stream = new FileStream(downloadPath, FileMode.Open))
            {
                await stream.CopyToAsync(memory);
            }
            memory.Position = 0;

            context.Response.ContentType = "application/octet-stream";
            context.Response.Headers.Add("Content-Disposition", $"attachment; filename={fileName}");
            await memory.CopyToAsync(context.Response.Body);
        }
        catch (Exception ex)
        {
            Logging.Handler.Error("GET Request Mapping", "/public_download", ex.ToString());

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("An error occurred while downloading the file.");
        }
    }).WithName("private_download").WithOpenApi();
}

// NetLock private support files, get index
if (role_file)
{
    app.MapPost("/admin/files/index/{path}", async (HttpContext context, string path) =>
    {
        try
        {
            // Check if path is empty
            if (string.IsNullOrEmpty(path))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid request.");
                return;
            }

            // Check if base path
            if (string.IsNullOrEmpty(path) || path.Equals("base1337", StringComparison.OrdinalIgnoreCase))
            {
                path = String.Empty;
            }
            else
            {
                // Decode the URL-encoded path
                path = Uri.UnescapeDataString(path);
            }

            Logging.Handler.Debug("/admin/files", "Request received.", path);

            // Add headers
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

            // Get the remote IP address from the X-Forwarded-For header
            string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue)
                ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

            // Verify API key
            bool hasApiKey = context.Request.Headers.TryGetValue("x-api-key", out StringValues files_api_key);

            Logging.Handler.Debug("/admin/files", "hasApiKey", hasApiKey.ToString());

            if (!hasApiKey || !await NetLock_RMM_Server.Files.Handler.Verify_Api_Key(files_api_key))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            // Combine the base path with the requested path
            var fullPath = Path.Combine(Application_Paths._private_files_admin, path);

            // Ensure the path exists and is a directory
            if (!Directory.Exists(fullPath))
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("Directory not found.");
                return;
            }

            // Get folders and files in the directory
            var directoryTree = NetLock_RMM_Server.Helper.IO.Get_Directory_Index(fullPath);

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(directoryTree.Result));
        }
        catch (Exception ex)
        {
            Logging.Handler.Error("/private/downloads/netlock", "General error", ex.ToString());

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("An error occurred while processing the request.");
        }
    }).WithName("private_download_netlock_index").WithOpenApi();

}

// NetLock files download private - GUID, used for update server & trust server
if (role_update || role_trust)
{
    app.MapGet("/private/downloads/netlock/{fileName}", async context =>
    {
        try
        {
            Logging.Handler.Debug("/private/downloads/netlock", "Request received.", "");

            // Add headers
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

            // Get the remote IP address from the X-Forwarded-For header
            string ip_address_external = context.Request.Headers.TryGetValue("X-Forwarded-For", out var headerValue) ? headerValue.ToString() : context.Connection.RemoteIpAddress.ToString();

            // Verify package guid
            bool hasPackageGuid = context.Request.Headers.TryGetValue("Package_Guid", out StringValues package_guid);

            Logging.Handler.Debug("/private/downloads/netlock", "hasGuid", hasPackageGuid.ToString());

            if (hasPackageGuid == false)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }
            else
            {
                bool package_guid_status = await Verify_NetLock_Package_Configurations_Guid(package_guid);

                if (package_guid_status == false)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

            var fileName = (string)context.Request.RouteValues["fileName"];

            var downloadPath = Path.Combine(Application_Paths._private_downloads_netlock, fileName);

            // Verify roles
            if (!role_update)
            {
                if (fileName == "comm.package" || fileName == "health.package" || fileName == "remote.package" || fileName == "uninstaller.package")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

            if (!role_trust)
            {
                if (fileName == "comm.package.sha512" || fileName == "health.package.sha512" || fileName == "remote.package.sha512" || fileName == "uninstaller.package.sha512")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized.");
                    return;
                }
            }

            if (!File.Exists(downloadPath))
            {
                Logging.Handler.Error("/private/downloads/netlock", "File not found", downloadPath);
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("File not found.");
                return;
            }

            var memory = new MemoryStream();
            using (var stream = new FileStream(downloadPath, FileMode.Open))
            {
                await stream.CopyToAsync(memory);
            }
            memory.Position = 0;

            context.Response.ContentType = "application/octet-stream";
            context.Response.Headers.Add("Content-Disposition", $"attachment; filename={fileName}");
            await memory.CopyToAsync(context.Response.Body);
        }
        catch (Exception ex)
        {
            Logging.Handler.Error("/private/downloads/netlock", "General error", ex.Message);

            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("An error occurred while downloading the file.");
        }
    }).WithName("private_download_netlock").WithOpenApi();
}

//Start server
app.Run();

Console.WriteLine("Server running!");