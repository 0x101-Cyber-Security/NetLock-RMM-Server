using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace NetLock_Server
{
    public class Application_Paths
    {
        public static string logs_dir = @"C:\ProgramData\0x101 Cyber Security\NetLock RMM\Server\Logs";
        //public static string logs_dir = @".\Logs";
        public static string debug_txt_path = @"C:\ProgramData\0x101 Cyber Security\NetLock RMM\Server\debug.txt";
        //public static string debug_txt_path = @".\debug.txt";
        
        public static string _public_uploads_user = @".\www\public\uploads\user";
        public static string _public_downloads_user = @".\www\public\downloads\user";

        public static string _private_downloads_netlock = @".\www\private\downloads\netlock";

        public static string _private_uploads_remote_temp = @".\www\private\uploads\remote\temp";
        public static string _private_downloads_remote_temp = @".\www\private\downloads\remote\temp";
        
        //URLs
        public static string redirect_path = "/";
    }
}
