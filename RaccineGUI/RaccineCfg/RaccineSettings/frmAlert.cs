using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

/// Raccine settings launcher
/// Initial code by @JohnLaTwC
namespace RaccineSettings
{
    public partial class frmAlert : Form
    {
        public frmAlert(EventRecord e)
        {
            InitializeComponent();
            txtLog.Text = e.TimeCreated + "\r\n" + e.FormatDescription().Trim();
        }

        private void lnkWebsite_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("https://github.com/Neo23x0/Raccine/");
        }
    }
}
