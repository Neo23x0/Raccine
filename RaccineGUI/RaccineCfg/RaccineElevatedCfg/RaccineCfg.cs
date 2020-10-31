using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.CompilerServices;

/// Raccine settings launcher
/// Initial code by @JohnLaTwC
namespace RaccineElevatedCfg
{

    public partial class RaccineCfg : Form
    {
        public static RaccineCfg thisForm = null;
        RaccineRegistrySettings settings = null;
        bool fDirty = false;
        public RaccineCfg()
        {
            InitializeComponent();
            RaccineCfg.thisForm = this;

            this.settings = new RaccineRegistrySettings();
            txtRulesDir.Text = settings.RulesDir;
            if (settings.LogOnly == 0x1)
            {
                chkSimulationMode.Checked = true;
            }
            else
            {
                chkSimulationMode.Checked = false;
            }
            if (settings.ScanMemory == 0x1)
            {
                chkScanMemory.Checked = true;
            }
            else
            {
                chkScanMemory.Checked = false;
            }

        }

        private void btnRuleBrowse_Click(object sender, EventArgs e)
        {
            string dir = settings.RulesDir;
            folderBrowserDialog1.ShowNewFolderButton = true;
            if (dir.Contains('%'))
            {
                dir = Environment.ExpandEnvironmentVariables(dir);
            }
            folderBrowserDialog1.SelectedPath = dir;
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                fDirty = true;
                txtRulesDir.Text = folderBrowserDialog1.SelectedPath;
            }
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            if (fDirty)
            {
                if (chkSimulationMode.Checked)
                {
                    settings.LogOnly = 0x1;
                }
                else
                {
                    settings.LogOnly = 0;
                }

                if (chkScanMemory.Checked)
                {
                    settings.ScanMemory= 0x1;
                }
                else
                {
                    settings.ScanMemory = 0;
                }
                string szFolder = txtRulesDir.Text;
                settings.RulesDir = szFolder;
            }
            Close();

        }

        private void btnViewLog_Click(object sender, EventArgs e)
        {
            if (File.Exists(settings.LogFilePath))
            {
                ProcessStartInfo psi = new ProcessStartInfo(settings.LogFilePath);
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
        }

        private void tabControl1_Selected(object sender, TabControlEventArgs e)
        {
            if (tabControl1.SelectedIndex == 1 && dataGridView1.Rows.Count == 0)
            {
                Cursor.Current = Cursors.WaitCursor;

                EventLogQuery elQuery = new EventLogQuery("Application", PathType.LogName, "*[System/Provider/@Name=\"Raccine\"]");
                elQuery.ReverseDirection = true;

                using (var elReader = new System.Diagnostics.Eventing.Reader.EventLogReader(elQuery))
                {

                    List<EventRecord> eventList = new List<EventRecord>();
                    EventRecord eventInstance = elReader.ReadEvent();
                    try
                    {
                        while (eventInstance != null)
                        {
                            eventInstance = elReader.ReadEvent();
                            if (eventInstance != null)
                            {
                                if (eventInstance.TimeCreated != null)
                                {
                                    TimeSpan ts = ((DateTime)eventInstance.TimeCreated - DateTime.Now);
                                    if (ts.TotalDays < 1)
                                    {
                                        eventList.Add(eventInstance);
                                    }
                                    else
                                    {
                                        break;
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
                    dataGridView1.Columns.Add("TimeCreated", "TimeCreated");
                    dataGridView1.Columns.Add("EventData", "EventData");
                    foreach (EventRecord evt in eventList)
                    {
                        int rowId = dataGridView1.Rows.Add();

                        // Grab the new row!
                        DataGridViewRow row = dataGridView1.Rows[rowId];

                        // Add the data
                        row.Cells["TimeCreated"].Value = evt.TimeCreated;
                        row.Cells["EventData"].Value = evt.FormatDescription();
                    }
                }
                Cursor.Current = Cursors.Default;
            }
        }

        private void chkSimulationMode_CheckStateChanged(object sender, EventArgs e)
        {
            fDirty = true;
        }

        private void mnuSettings_Click(object sender, EventArgs e)
        {
            RaccineCfg.thisForm.Show();
        }

        private void mnuExit_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void btnRulesFolder_Click(object sender, EventArgs e)
        {
            string folder_name = settings.RulesDir;
            folder_name = Environment.ExpandEnvironmentVariables(folder_name);
            if (Directory.Exists(folder_name))
            {
                if (!folder_name.EndsWith("\\"))
                    folder_name += "\\";
                ProcessStartInfo psi = new ProcessStartInfo(folder_name);
                psi.UseShellExecute = true;
                psi.Verb = "open";
                Process.Start(psi);
            }
        }

        private void chkScanMemory_CheckedChanged(object sender, EventArgs e)
        {
            fDirty = true;
        }

    }


    public class RaccineRegistrySettings
    {
        public RaccineRegistrySettings()
        {

        }

        public uint LogOnly
        {
            get
            {
                uint setting = Convert.ToUInt32(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "LogOnly", 1));
                return setting;
            }
            set
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "LogOnly", value ,RegistryValueKind.DWord);
            }
        }
        public uint ScanMemory
        {
            get
            {
                uint setting = Convert.ToUInt32(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "ScanMemory", 0));
                return setting;
            }
            set
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "ScanMemory", value, RegistryValueKind.DWord);
            }
        }


        public string RulesDir
        {
            get
            {
                string dir_name = Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Raccine\yara"); 
                string setting = Convert.ToString(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "RulesDir", dir_name));
                return setting;
            }
            set
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Raccine", "RulesDir", value, RegistryValueKind.String);
            }
        }
        public string LogFilePath
        {
            get
            {
                string logpath =  Environment.ExpandEnvironmentVariables(@"%ProgramData%\Raccine\Raccine_log.txt");
                return logpath;
            }
        }
    }
}
