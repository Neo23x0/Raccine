using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

/// <summary>
/// Raccine settings launcher
/// Initial code by @JohnLaTwC
/// </summary>

namespace RaccineSettings
{
    public partial class frmBootstrap : Form
    {
        private IntPtr alertEvent = IntPtr.Zero;
        System.Threading.Mutex singleInstanceMutex = null;
        EnvMonitor envMonitor = null;

        public frmBootstrap()
        {
            InitializeComponent();
            this.Visible = false;

            string szSingleInstanceMutexName = "Local\\" + System.Diagnostics.Process.GetCurrentProcess().ProcessName + "_mutex";
            bool fMutexCreated = false;
            this.singleInstanceMutex = new System.Threading.Mutex(true, szSingleInstanceMutexName, out fMutexCreated);

            if (!fMutexCreated)
            {
                string szMessage = String.Format("{0} is already running. Exiting this instance.", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
                MessageBox.Show(szMessage, "Raccine Startup Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.singleInstanceMutex.Close();
                Close();
            }
            this.alertEvent = NativeApi.CreateEvent(IntPtr.Zero, false, false, "RaccineAlertEvent");
            if (this.alertEvent == IntPtr.Zero)
            {
                ;
                // An error occurred creating the handle...
            }

            Thread watcher = new Thread(new ThreadStart(WatcherThread.ThreadProc));
            WatcherThread.alertEvent = this.alertEvent;
            watcher.Name = String.Format("RaccineAlertWatcherThread");
            watcher.Start();

            string szRaccineUserContextDirectory = Environment.ExpandEnvironmentVariables("%TEMP%") + "\\RaccineUserContext";
            try
            {
                Directory.CreateDirectory(szRaccineUserContextDirectory);
                this.envMonitor = new EnvMonitor(szRaccineUserContextDirectory);
            }
            catch (Exception ex)
            {
                MessageBox.Show(String.Format("Raccine was unable to create user context folder for Yara rules {0}\n{1}",
                    szRaccineUserContextDirectory, ex.Message));
            }

        }
        private void mnuLastAlert_Click(object sender, EventArgs e)
        {
            NativeApi.SetEvent(this.alertEvent);
        }

        private void mnuExit_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void mnuSettings_Click(object sender, EventArgs e)
        {
            string  dir = AppDomain.CurrentDomain.BaseDirectory;

            ProcessStartInfo psi = new ProcessStartInfo(dir + "\\RaccineElevatedCfg.exe");
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            Process.Start(psi);
        }
        private void ReleaseResources()
        {
            this.singleInstanceMutex.Close();
            this.envMonitor.Stop();
        }

        private void CreateTroubleShootingLogs()
        {
            try
            {
                string szRaccineTroubleshootingDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\RaccineLogs";
                Directory.CreateDirectory(szRaccineTroubleshootingDir);

                string[] RegCommands = {
                    @"EXPORT HKLM\Software\Raccine """ +  szRaccineTroubleshootingDir + "\\" + @"HKLM-Raccine-settings.reg.txt"" /y",
                    @"EXPORT HKLM\Software\Policies\Raccine " +  szRaccineTroubleshootingDir + "\\" + @"HKLM-Raccine-Policies-settings.reg.txt"" /y",
                    @"EXPORT HKLM\Software\WOW6432Node\Raccine " +  szRaccineTroubleshootingDir + "\\" + @"HKLM-Raccine-WOW6432Node.reg.txt"" /y",
                    @"EXPORT ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"" """ +  szRaccineTroubleshootingDir + "\\" + @"HKLM-Raccine-IFEO.reg.txt"" /y /reg:64",
                    @"EXPORT ""HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"" """ +  szRaccineTroubleshootingDir + "\\" + @"HKLM-Raccine-IFEO-WOW6432Node.reg.txt"" /y"};

                Dictionary<string, string> dictSaveCmdOutput = new Dictionary<string, string>();
                dictSaveCmdOutput["eventlogs.txt"] = @"wevtutil qe /rd Application /q:""*[System[Provider[@Name='Raccine']]]"" /uni:false /f:text ";
                dictSaveCmdOutput["PROGRAMDATA.txt"] = @"dir /s %PROGRAMDATA%\Raccine";
                dictSaveCmdOutput["PROGRAMFILES.txt"] = @"dir /s ""%PROGRAMFILES%\Raccine""";

                foreach (string command in RegCommands)
                {
                    ProcessStartInfo psi = new ProcessStartInfo("REG.EXE");
                    psi.Arguments = command;
                    psi.WindowStyle = ProcessWindowStyle.Minimized;
                    psi.UseShellExecute = true;
                    Process.Start(psi);
                }
                foreach (string savefile in dictSaveCmdOutput.Keys)
                {
                    string command = dictSaveCmdOutput[savefile];
                    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe");
                    psi.Arguments = "/c " + command + " > \"" + szRaccineTroubleshootingDir + "\\" + savefile+ "\"";
                    psi.WindowStyle = ProcessWindowStyle.Minimized;
                    Process.Start(psi);
                }
                string szRaccineLogFile = Environment.ExpandEnvironmentVariables("%PROGRAMDATA%") + @"\Raccine\Raccine_log.txt";
                if (File.Exists(szRaccineLogFile))
                {
                    File.Copy(szRaccineLogFile, szRaccineTroubleshootingDir + @"\Raccine_log.txt",true);
                }
                MessageBox.Show("Troubleshooting logs saved to " + szRaccineTroubleshootingDir, "Logs Saved", MessageBoxButtons.OK,MessageBoxIcon.Information );

            }
            catch (Exception e)
            {
                MessageBox.Show("Error creating logs: " + e.Message);
            }

        }

        private void createTroubleshootingLogsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            CreateTroubleShootingLogs();
        }
    }

    public class NativeApi
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll")]
        public static extern bool SetEvent(IntPtr hEvent);

        [DllImport("kernel32.dll")]
        public static extern bool ResetEvent(IntPtr hEvent);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

        public static UInt32 INFINITE = 0xFFFFFFFF;
        public const UInt32 WAIT_TIMEOUT = 0x00000102;

    }
    public class WatcherThread
    {
        public static bool exit = false;
        public static IntPtr alertEvent = IntPtr.Zero;

        private static DateTime? lastEventTimeGenerated = null;

        public WatcherThread()
        {
        }

        public static void DoWork()
        {
            EventLogQuery elQuery = new EventLogQuery("Application", PathType.LogName, "*[System/Provider/@Name=\"Raccine\"]");
            elQuery.ReverseDirection = true;
            using (var elReader = new System.Diagnostics.Eventing.Reader.EventLogReader(elQuery))
            {
                EventRecord eventInstance = null;
                try
                {
                    eventInstance = elReader.ReadEvent();
                    if (eventInstance != null)
                    {
                        if (eventInstance.TimeCreated != null)
                        {
                            TimeSpan ts = ((DateTime) eventInstance.TimeCreated - DateTime.Now);
                            if (ts.TotalDays < 2)  // it should be recent
                            {
                                // if we already saw an event, don't show it again. wait for a new one.
                                if ((WatcherThread.lastEventTimeGenerated == null) ||
                                    WatcherThread.lastEventTimeGenerated != null  &&
                                    (((TimeSpan)(WatcherThread.lastEventTimeGenerated - (DateTime)eventInstance.TimeCreated)).TotalMinutes >0 ))
                                {
                                    frmAlert frmAlertInstance = new frmAlert(eventInstance);
                                    //WatcherThread.lastEventTimeGenerated = eventInstance.TimeCreated;
                                    frmAlertInstance.ShowDialog();
                                }
                            }
                        }
                    }
                }
                finally
                {
                    if (eventInstance != null)
                        eventInstance.Dispose();
                }
            }
        }

        public static void ThreadProc()
        {
            while (true)
            {
                UInt32 RetVal = NativeApi.WaitForSingleObject(alertEvent, 5000);
                if (RetVal == NativeApi.WAIT_TIMEOUT)
                {
                    if (exit)
                    {
                        return;
                    }
                }
                else
                {
                    NativeApi.ResetEvent(alertEvent);
                    DoWork();
                }
            }
        }
    }

}
