using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace NetLock_Server
{
    public class Application_Paths
    {
        public static string program_data_logs = @"C:\ProgramData\0x101 Cyber Security\NetLock RMM\Server\Logs";
        public static string _public_uploads = Directory.GetCurrentDirectory() + @"\www\public\uploads";
        public static string _public_downloads = Directory.GetCurrentDirectory() + @"\www\public\downloads";

        public static string _private_uploads = Directory.GetCurrentDirectory() + @"\www\private\uploads";
        public static string _private_downloads = Directory.GetCurrentDirectory() + @"\www\private\downloads";

        //URLs
        public static string redirect_path = "/";
    }
}
