using Microsoft.AspNetCore.Http;
using NetLock_Server.Agent.Windows;

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

//Test
app.MapGet("/test1", () =>
{
    return "huso";
})
.WithName("test1")
.WithOpenApi();

//API URLs*
//Verify Device
app.MapPost("/Agent/Windows/Verify_Device", async context =>
{
    try
    {
        //Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); //protect against XSS 

        // Versuchen, die Remote-IP-Adresse aus dem X-Forwarded-For-Header zu erhalten
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? String.Empty;

        // Wenn X-Forwarded-For-Header nicht verfügbar ist, verwenden Sie die Remote-IP-Adresse direkt
        if (string.IsNullOrEmpty(ip_address_external))
            ip_address_external = context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? String.Empty;

        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        context.Response.StatusCode = 200;
        await context.Response.WriteAsync(device_status.ToString());
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Auth/Login", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync($"Invalid request.");
    }
}).WithName("Swagger1").WithOpenApi();

//Update device information
app.MapPost("/Agent/Windows/Update_Device_Information", async context =>
{
    try
    {
        //Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); //protect against XSS 

        // Versuchen, die Remote-IP-Adresse aus dem X-Forwarded-For-Header zu erhalten
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? String.Empty;

        // Wenn X-Forwarded-For-Header nicht verfügbar ist, verwenden Sie die Remote-IP-Adresse direkt
        if (string.IsNullOrEmpty(ip_address_external))
            ip_address_external = context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? String.Empty;

        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        if (device_status == "authorized")
            await Device_Handler.Update_Device_Information(json);

        context.Response.StatusCode = 200;
        await context.Response.WriteAsync(device_status.ToString());
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Update_Device_Information", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync($"Invalid request.");
    }
}).WithName("Swagger2").WithOpenApi();

//Update device information
app.MapPost("/Agent/Windows/Events", async context =>
{
    try
    {
        //Add headers
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'"); //protect against XSS 

        // Versuchen, die Remote-IP-Adresse aus dem X-Forwarded-For-Header zu erhalten
        string ip_address_external = context.Request.Headers["X-Forwarded-For"].ToString() ?? String.Empty;

        // Wenn X-Forwarded-For-Header nicht verfügbar ist, verwenden Sie die Remote-IP-Adresse direkt
        if (string.IsNullOrEmpty(ip_address_external))
            ip_address_external = context.Connection.RemoteIpAddress.ToString();

        string json = await new StreamReader(context.Request.Body).ReadToEndAsync() ?? String.Empty;

        string device_status = await Authentification.Verify_Device(json, ip_address_external);

        if (device_status == "authorized")
            await Event_Handler.Consume(json);

        context.Response.StatusCode = 200;
        await context.Response.WriteAsync(device_status.ToString());
    }
    catch (Exception ex)
    {
        Logging.Handler.Error("POST Request Mapping", "/Agent/Windows/Events", ex.Message);

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync($"Invalid request.");
    }
}).WithName("Swagger3").WithOpenApi();









//Start server
app.Run();