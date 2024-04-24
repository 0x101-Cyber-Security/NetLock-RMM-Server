using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
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

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? string.Empty;

        string device_status = await Version_Handler.Check_Version(json);

        context.Response.StatusCode = 200;
        await context.Response.WriteAsync(device_status);
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Check_Version", ex.Message);

        context.Response.StatusCode = 500;
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
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? string.Empty;

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
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? string.Empty;

        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        if (device_status == "authorized")
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

//Update events
app.MapPost("/Agent/Windows/Events", async context =>
{
    try
    {
        Logging.Handler.Debug("POST Request Mapping", "/Agent/Windows/Events", "Request received.");

        // Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); // protect against XSS 

        // Get the remote IP address from the X-Forwarded-For header
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? string.Empty;

        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        if (device_status == "authorized")
        {
            await Event_Handler.Consume(json);
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









//Start server
app.Run();