using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using NetLock_Server.Agent.Windows;
using System.Security.Principal;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

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








//Start server
app.Run();