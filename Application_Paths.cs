using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace NetLock_Server
{
    public class Application_Paths
    {
        public static string program_data_logs = @"C:\ProgramData\0x101 Cyber Security\NetLock RMM\Server\Logs";
        public static string _public_uploads_user = Directory.GetCurrentDirectory() + @"\www\public\uploads\user";
        public static string _public_downloads_user = Directory.GetCurrentDirectory() + @"\www\public\downloads\user";

        public static string _private_downloads_netlock = Directory.GetCurrentDirectory() + @"\www\private\downloads\netlock";

        public static string _private_uploads_remote_temp = Directory.GetCurrentDirectory() + @"\www\private\uploads\remote\temp";
        public static string _private_downloads_remote_temp = Directory.GetCurrentDirectory() + @"\www\private\downloads\remote\temp";
        
        //URLs
        public static string redirect_path = "/";
    }
}
