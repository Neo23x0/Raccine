using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace RaccineSettings
{
    class RulesSync
    {

        public static bool fCompileRules = false;
        static public void Main(String[] args)
        {
            var contentsUrl = $"https://api.github.com/repos/Neo23x0/Raccine/contents/yara?ref=main";
            //var contentsUrl = $"https://api.github.com/repos/Neo23x0/Raccine/contents/yara?ref=yara-mem-matching";
            SyncContentFromUrl(contentsUrl, "");
        }

        public static string GetYaraDefines()
        {
            return " -d Name=\"\" -d ExecutablePath=\"\" -d CommandLine=\"\" -d TimeSinceExeCreation=0 -d ParentName=\"\" -d ParentExecutablePath=\"\" -d ParentCommandLine= -d ParentTimeSinceExeCreation=0 -d GrandParentName=\"\" -d GrandParentExecutablePath=\"\" -d GrandParentCommandLine=\"\" -d GrandParentTimeSinceExeCreation=0 ";
        }

        public static bool SyncContentFromUrl(string contentsUrl, string subdir)
        {
            String newLinePattern = "([\r]?\n)";
            var httpClient = new HttpClient();

            Console.WriteLine("Downloading rules from " + contentsUrl);
            var jsonData = string.Empty;

            try
            {
                using (var webClient = new System.Net.WebClient())
                {
                    webClient.Headers.Add("user-agent", "Mozilla/4.0");
                    jsonData = webClient.DownloadString(contentsUrl);
                }

                string szRulesDir = RulesDir;

                JavaScriptSerializer js = new JavaScriptSerializer();
                Rule[] rules = js.Deserialize<Rule[]>(jsonData);
                uint iRuleCount = 0;
                foreach (Rule rule in rules)
                {
                    string type = rule.type;
                    if (rule.name.EndsWith(".yar"))
                    {
                        using (var webClient = new System.Net.WebClient())
                        {
                            webClient.Headers.Add("user-agent", "Mozilla/4.0");
                            string yararule = webClient.DownloadString(rule.download_url);

                            string szDir = szRulesDir + "\\" + subdir;
                            System.IO.Directory.CreateDirectory(szDir);

                            string szRulePath = szDir + rule.name;
                            Console.WriteLine("Updating rule " + szRulePath);

                            using (System.IO.StreamWriter file =
                                new System.IO.StreamWriter(szRulePath, false))
                            {
                                file.WriteLine(Regex.Replace(yararule, newLinePattern, "\r\n"));
                                file.Flush();
                                file.Close();
                                iRuleCount++;

                                if (fCompileRules)
                                {
                                    string szCompiledRulePath = szRulePath + "c";  // e.g. rule_file.yarc
                                    string compilation_program = "";
                                    if (Environment.Is64BitOperatingSystem)
                                    {
                                        compilation_program = "%ProgramFiles%\\Raccine\\yarac64.exe";
                                    }
                                    else
                                    {
                                        compilation_program = "%ProgramFiles%\\Raccine\\yarac32.exe";
                                    }
                                    compilation_program = Environment.ExpandEnvironmentVariables(compilation_program);

                                    if (File.Exists(compilation_program))
                                    {
                                        string command_line = GetYaraDefines() + "\"" + szRulePath + "\" \"" + szCompiledRulePath + "\"";
                                        compilation_program = "\"" + compilation_program + "\"";

                                        ProcessStartInfo psi = new ProcessStartInfo(compilation_program);
                                        psi.Arguments = command_line;
                                        psi.UseShellExecute = false;
                                        Process.Start(psi);
                                        if (File.Exists(szCompiledRulePath))
                                        {
                                            Console.WriteLine("Compiled rule to {0}", szCompiledRulePath);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("Can't find yara rule compiler: " + compilation_program);
                                    }
                                }
                            }
                        }
                    } 
                    else if (rule.type == "dir")
                    {
                        SyncContentFromUrl(rule.url, rule.name + "\\");

                    }
                }
                Console.WriteLine("Updated {0} rules.", iRuleCount);
                Thread.Sleep(2000);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Thread.Sleep(4000);
            }

            return true;
        }

        public static string RulesDir
        {
            get
            {
                RegistryKey RaccineKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Raccine", false);
                String setting = (String)RaccineKey.GetValue("RulesDir");
                if (String.IsNullOrEmpty(setting))
                {
                    setting = Environment.ExpandEnvironmentVariables(@"%PROGRAMFILES%\Raccine\yara");
                }
                Console.WriteLine("YARA Rules directory is: {0}", setting);
                return setting;
            }

        }
    }

    class Rule
    {
        public string name { get; set; }
        public string path { get; set; }
        public string sha { get; set; }
        public uint size { get; set; }

        public string url { get; set; }
        public string html_url { get; set; }
        public string git_url { get; set; }
        public string download_url { get; set; }
        public string type { get; set; }
    }
}
