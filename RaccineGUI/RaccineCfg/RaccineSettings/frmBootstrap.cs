using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

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
