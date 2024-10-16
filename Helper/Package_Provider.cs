using NetLock_RMM_Server;
using NetLock_RMM_Server.Configuration;
using System.Net;
using System.IO.Compression;

namespace Helper
{
    public class Package_Provider
    {
        public static async Task Check_Packages()
        {
            try
            {
                if (Roles.Update || Roles.Trust)
                {
                    string version = String.Empty;

                    // Check if version.txt exists
                    if (File.Exists(Path.Combine(Application_Paths._private_files_netlock, "version.txt")))
                        version = File.ReadAllText(Path.Combine(Application_Paths._private_files_netlock, "version.txt"));

                    if (version != Application_Settings.version || String.IsNullOrEmpty(version))
                    {
                        Console.ForegroundColor = ConsoleColor.DarkYellow;
                        Console.WriteLine("Packages are not setup. Trying to setup.");

                        if (Directory.Exists(Application_Paths._private_files_netlock))
                        {
                            // Delete files & folders in netlock files
                            foreach (string dir in Directory.GetDirectories(Application_Paths._private_files_netlock))
                                Directory.Delete(dir, true);

                            foreach (string file in Directory.GetFiles(Application_Paths._private_files_netlock))
                                File.Delete(file);

                            // Delete files in temp folder

                            if (Directory.Exists(Application_Paths._private_files_netlock_temp))
                            {
                                foreach (string file in Directory.GetFiles(Application_Paths._private_files_netlock_temp))
                                    File.Delete(file);
                            }
                        }

                        if (!Directory.Exists(Application_Paths._private_files_netlock_temp))
                            Directory.CreateDirectory(Application_Paths._private_files_netlock_temp);

                        string package_url = await NetLock_RMM_Server.MySQL.Handler.Quick_Reader("SELECT * FROM settings;", "package_provider_url");
                        string package_download_location = Path.Combine(Application_Paths._private_files_netlock_temp, "package.zip");

                        // Download the new version
                        using (WebClient client = new WebClient())
                        {
                            client.DownloadFile(package_url, package_download_location);
                        }

                        // Unzip the new version
                        ZipFile.ExtractToDirectory(package_download_location, Application_Paths._private_files_netlock);

                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Packages are setup...");
                        Console.ResetColor();
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Helper.Package_Provider.Check_Packages", "Result", ex.ToString());

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Packages could not be setup. Please make sure you provided a package provider url in the webconsole and that it can be accessed from the backend. Otherwise you cannot install or update agents with this backend.");
                Console.ResetColor();
            }
        }
    }
}
