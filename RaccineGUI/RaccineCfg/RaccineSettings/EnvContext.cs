using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;

/// <summary>
/// Build up environment context and save it so raccine rules can use it
/// author: @JohnLaTwC
/// </summary>
namespace RaccineSettings
{
    public class EnvMonitor
    {
        ManagementEventWatcher processStartEvent = new ManagementEventWatcher("SELECT * FROM Win32_ProcessStartTrace");
        ManagementEventWatcher processStopEvent = new ManagementEventWatcher("SELECT * FROM Win32_ProcessStopTrace");
        private UInt32 SessionId = 0;
        private static string RaccineUserContextRootFolder = null;
        System.Timers.Timer cleanupTimer = null;
        public EnvMonitor(string RaccineUserContextRootFolder)
        {
            EnvMonitor.RaccineUserContextRootFolder = RaccineUserContextRootFolder;
            this.SessionId = (UInt32)System.Diagnostics.Process.GetCurrentProcess().SessionId; // only watch processes in this session

            CleanupOldContextFiles();

            LogInitialProcesses();

            string queryString = "SELECT * FROM __InstanceCreationEvent WITHIN 0.25 WHERE TargetInstance ISA 'Win32_Process'";
            ManagementEventWatcher processStartEvent = new ManagementEventWatcher(@"\\.\root\CIMV2", queryString);
            ManagementEventWatcher processStopEvent = new ManagementEventWatcher("SELECT * FROM __InstanceDeletionEvent WITHIN .025 WHERE TargetInstance ISA 'Win32_Process'");
            processStartEvent.EventArrived += new EventArrivedEventHandler(processStartEvent_EventArrived);
            processStopEvent.EventArrived += new EventArrivedEventHandler(processStopEvent_EventArrived);
            processStartEvent.Start();
            processStopEvent.Start();


            this.cleanupTimer = new System.Timers.Timer();
            this.cleanupTimer.Elapsed += new ElapsedEventHandler(OnTimedEvent);
            this.cleanupTimer.Interval = 1000 * 60;  // every 60 seconds do cleanup procedure
            this.cleanupTimer.Enabled = true;
        }

        private static void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            uint SessionId = (uint)System.Diagnostics.Process.GetCurrentProcess().SessionId; // only watch processes in this session

            string qry = "SELECT * FROM Win32_Process WHERE SessionId =" + SessionId;

            ManagementObjectSearcher moSearch = new ManagementObjectSearcher(qry);
            ManagementObjectCollection moCollection = moSearch.Get();

            List<string> lstFileNames = new List<string>();

            foreach (ManagementObject mo in moCollection)
            {
                Win32Process process = new Win32Process(mo);
                if (process.SessionId == SessionId)
                    lstFileNames.Add(GenerateContextFileName(process));
            }

            //sweep time
            // we don't get reliable notification in the current implementation
            // to avoid excessive saving of context files, we periodically sweep any file not associated with a running process
            try
            {
                var files = Directory.EnumerateFiles(EnvMonitor.RaccineUserContextRootFolder, "RaccineYaraContext*.txt");

                foreach (string currentFile in files)
                {
                    string fileName = Path.GetFileName (currentFile);
                    if (lstFileNames.Contains(fileName))
                    {
                        ; // keep it as the process is still running
                    }
                    else
                    {
                        ;
                        //File.Delete currentFile;
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        public void LogInitialProcesses()
        {
            string qry = "SELECT * FROM Win32_Process WHERE SessionId =" + this.SessionId;

            ManagementObjectSearcher moSearch = new ManagementObjectSearcher(qry);
            ManagementObjectCollection moCollection = moSearch.Get();

            foreach (ManagementObject mo in moCollection)
            {
                Win32Process process = new Win32Process(mo);
                if (process.SessionId == this.SessionId)
                    WriteContextFile(process);
            }
        }

        public void Stop()
        {
            processStartEvent.Stop();
            processStopEvent.Stop();
            this.cleanupTimer.Stop();
            this.cleanupTimer.Dispose();

        }

        private string GenerateContextFileName(PropertyDataCollection props)
        {
            string szFileName = String.Format("RaccineYaraContext-{0}-{1}-{2}.txt",
                    (UInt32)(props["SessionId"].Value),
                    (UInt32)(props["ProcessId"].Value),
                    (UInt32)(props["ParentProcessId"].Value));
            return szFileName;
        }
        private static string GenerateContextFileName(Win32Process process)
        {
            string szFileName = String.Format("RaccineYaraContext-{0}-{1}-{2}.txt",
                    process.SessionId,
                    process.ProcessId,
                    process.ParentProcessId);
            return szFileName;
        }

        private void CleanupOldContextFiles()
        {
            var lstFiles = Directory.EnumerateFiles(RaccineUserContextRootFolder, "RaccineYaraContext*.txt", SearchOption.AllDirectories);

            foreach (string currFileName in lstFiles)
            {
                File.Delete(currFileName);
            }
        }

        private string EscapeString(string szValue)
        {
            string szOut = "";
            if (szValue != null)
            {
                szOut = szValue.Replace("\"","'");
                
                if (szOut.Contains(" ") && !szOut.StartsWith("\""))
                    szOut = '"' + szOut + '"';
            }
            return szOut;
        }
        private void WriteContextFile(Win32Process process)
        {
            string szContextPath = RaccineUserContextRootFolder + @"\" + GenerateContextFileName(process);

            if (Directory.Exists(RaccineUserContextRootFolder))
            {
                using (StreamWriter outputFile = new StreamWriter(szContextPath))
                {
                    string szName = "-d Caption";
                    string szValue = EscapeString(process.Caption);
                    outputFile.Write(" " + szName + "=" + szValue + " ");

                    szName = "-d CommandLine";
                    szValue = EscapeString(process.CommandLine);
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d ExecutablePath";
                    szValue = EscapeString(process.ExecutablePath);
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d HandleCount";
                    szValue = process.HandleCount.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d Name";
                    szValue = EscapeString(process.Name);
                    outputFile.Write(szName + "=\"" + szValue + "\" ");

                    szName = "-d OSName";
                    szValue = EscapeString(process.OSName);
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d Priority";
                    szValue = process.Priority.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d SessionId";
                    szValue = process.SessionId.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d ThreadCount";
                    szValue = process.ThreadCount.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d WindowsVersion";
                    szValue = process.WindowsVersion;
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d WriteOperationCount";
                    szValue = process.WriteOperationCount.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");

                    szName = "-d WriteTransferCount";
                    szValue = process.WriteTransferCount.ToString();
                    outputFile.Write(szName + "=" + szValue + " ");
                }
            }
        }
        private void WriteContextFile(PropertyDataCollection props)
        {
            string szContextPath = RaccineUserContextRootFolder + @"\" + GenerateContextFileName(props);

            if (Directory.Exists(RaccineUserContextRootFolder))
            {
                // Write the string array to a new file named "WriteLines.txt".
                using (StreamWriter outputFile = new StreamWriter(szContextPath))
                {
                    List<string> lstPropsToLog = new List<string>() { "Caption", "CommandLine", "ExecutablePath", "HandleCount", "Name", "OSName", "Priority", "ProcessId", "ParentProcessId", "SessionId", "ThreadCount", "WindowsVersion", "WriteOperationCount", "WriteTransferCount" };

                    foreach (PropertyData subprop in props)
                    {
                        if (lstPropsToLog.Contains(subprop.Name))
                        {
                            string szValue = "";
                            if (subprop.Value == null)
                                szValue = "";
                            else
                                szValue = EscapeString(subprop.Value.ToString());
                            if (subprop.Name == "Name" && szValue.IndexOf("\"") == -1)
                                szValue = "\"" + szValue + "\"";

                            outputFile.Write(" -d " + subprop.Name + "=" + szValue + " ");
                        }
                    }
                }
            }
        }

        private void DeleteContextFile(PropertyDataCollection props)
        {
            string szContextPath = RaccineUserContextRootFolder + @"\" + GenerateContextFileName(props);

            try
            {
                File.Delete(szContextPath);
            }
            catch (Exception )
            {
                ;
                //MessageBox.Show("Error deleting " + szContextPath + "\n" + e.Message); //error deleting file
            }

        }

        void processStartEvent_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                PropertyData prop = e.NewEvent.Properties["TargetInstance"];

                if (prop.Name == "TargetInstance")
                {
                    ManagementBaseObject eventDetails = (ManagementBaseObject)prop.Value;

                    if ((UInt32)(eventDetails.Properties["SessionId"].Value) == this.SessionId)
                    {
                        WriteContextFile(eventDetails.Properties);
                    }
                    else
                    {
                        ;//skip processes not in the user's session

                    }
                }
            }
            catch (Exception e1)
            {
                MessageBox.Show(e1.Message);
            }


        }
    

        void processStopEvent_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                PropertyData prop = e.NewEvent.Properties["TargetInstance"];

                if (prop.Name == "TargetInstance")
                {
                    ManagementBaseObject eventDetails = (ManagementBaseObject)prop.Value;

                    if ((UInt32)(eventDetails.Properties["SessionId"].Value) == this.SessionId)
                    {
                        DeleteContextFile(eventDetails.Properties);
                    }
                    else
                    {
                        ;//skip processes not in the user's session

                    }
                }
            }
            catch (Exception e1)
            {
                Console.Write(e1.Message);
            }

        }

    }
    public class Win32Process
    {
        public string Caption;
        public string CommandLine;
        public string ExecutablePath;
        public string OSName;
        public string Name;
        public uint? Priority;
        public string WindowsVersion;
        public uint SessionId;
        public uint? ThreadCount;
        public uint? HandleCount;
        public uint ProcessId;
        public uint ParentProcessId;
        public ulong? WriteOperationCount;
        public ulong? WriteTransferCount;

        public Win32Process(ManagementObject process)
        {
            this.Caption = process[nameof(this.Caption)] as string;
            this.CommandLine = process[nameof(this.CommandLine)] as string;
            this.ExecutablePath = process[nameof(this.ExecutablePath)] as string;
            this.HandleCount = (uint?)process[nameof(this.HandleCount)];
            this.Name = process[nameof(this.Name)] as string;
            this.OSName = process[nameof(this.OSName)] as string;
            this.Priority = (uint?)process[nameof(this.Priority)];
            this.ProcessId = (uint)process[nameof(this.ProcessId)];
            this.ParentProcessId = (uint)process[nameof(this.ParentProcessId)];
            this.SessionId = (uint)process[nameof(this.SessionId)];
            this.ThreadCount = (uint?)process[nameof(this.ThreadCount)];
            this.WindowsVersion = process[nameof(this.WindowsVersion)] as string;
            this.WriteOperationCount = (ulong?)process[nameof(this.WriteOperationCount)];
            this.WriteTransferCount = (ulong?)process[nameof(this.WriteTransferCount)];
        }
    }
}
