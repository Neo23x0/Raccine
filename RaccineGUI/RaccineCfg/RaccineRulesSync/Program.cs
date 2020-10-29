using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Web.Script.Serialization;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace RaccineSettings
{
    class RulesSync
    {
        static public void Main(String[] args)
        {
            SyncContent();
        }

        public static bool SyncContent()
        {
            var httpClient = new HttpClient();
            var contentsUrl = $"https://api.github.com/repos/Neo23x0/Raccine/contents/yara?ref=main";

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
                    if (rule.name.EndsWith(".yar"))
                    {
                        using (var webClient = new System.Net.WebClient())
                        {
                            webClient.Headers.Add("user-agent", "Mozilla/4.0");
                            string yararule = webClient.DownloadString(rule.download_url);

                            string szRulePath = szRulesDir + "\\" + rule.name;
                            Console.WriteLine("Updating rule " + szRulePath);

                            using (System.IO.StreamWriter file =
                                new System.IO.StreamWriter(szRulePath, false))
                            {
                                file.WriteLine(yararule);
                                iRuleCount++;
                            }
                        }
                    }
                }
                Console.WriteLine("Updated {0} rules.", iRuleCount);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return true;
        }

        public static string RulesDir
        {
            get
            {
                string setting = Convert.ToString(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "RulesDir", null));

                if (String.IsNullOrEmpty(setting))
                {
                    setting = Environment.ExpandEnvironmentVariables(@"%PROGRAMDATA%\Raccine\yara");
                }
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
