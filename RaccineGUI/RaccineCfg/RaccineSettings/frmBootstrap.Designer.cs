namespace RaccineSettings
{
    partial class frmBootstrap
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(frmBootstrap));
            this.notifyIcon1 = new System.Windows.Forms.NotifyIcon(this.components);
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.mnuSettings = new System.Windows.Forms.ToolStripMenuItem();
            this.createTroubleshootingLogsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.mnuLastAlert = new System.Windows.Forms.ToolStripMenuItem();
            this.mnuExit = new System.Windows.Forms.ToolStripMenuItem();
            this.updateRulesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.contextMenuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // notifyIcon1
            // 
            this.notifyIcon1.ContextMenuStrip = this.contextMenuStrip1;
            this.notifyIcon1.Icon = ((System.Drawing.Icon)(resources.GetObject("notifyIcon1.Icon")));
            this.notifyIcon1.Text = "Raccine";
            this.notifyIcon1.Visible = true;
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mnuSettings,
            this.createTroubleshootingLogsToolStripMenuItem,
            this.updateRulesToolStripMenuItem,
            this.mnuLastAlert,
            this.mnuExit});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(312, 197);
            // 
            // mnuSettings
            // 
            this.mnuSettings.Name = "mnuSettings";
            this.mnuSettings.Size = new System.Drawing.Size(311, 32);
            this.mnuSettings.Text = "Settings";
            this.mnuSettings.Click += new System.EventHandler(this.mnuSettings_Click);
            // 
            // createTroubleshootingLogsToolStripMenuItem
            // 
            this.createTroubleshootingLogsToolStripMenuItem.Name = "createTroubleshootingLogsToolStripMenuItem";
            this.createTroubleshootingLogsToolStripMenuItem.Size = new System.Drawing.Size(311, 32);
            this.createTroubleshootingLogsToolStripMenuItem.Text = "Create &Troubleshooting Logs";
            this.createTroubleshootingLogsToolStripMenuItem.Click += new System.EventHandler(this.createTroubleshootingLogsToolStripMenuItem_Click);
            // 
            // mnuLastAlert
            // 
            this.mnuLastAlert.Name = "mnuLastAlert";
            this.mnuLastAlert.Size = new System.Drawing.Size(311, 32);
            this.mnuLastAlert.Text = "Last Alert";
            this.mnuLastAlert.Click += new System.EventHandler(this.mnuLastAlert_Click);
            // 
            // mnuExit
            // 
            this.mnuExit.Name = "mnuExit";
            this.mnuExit.Size = new System.Drawing.Size(311, 32);
            this.mnuExit.Text = "Exit";
            this.mnuExit.Click += new System.EventHandler(this.mnuExit_Click);
            // 
            // updateRulesToolStripMenuItem
            // 
            this.updateRulesToolStripMenuItem.Name = "updateRulesToolStripMenuItem";
            this.updateRulesToolStripMenuItem.Size = new System.Drawing.Size(311, 32);
            this.updateRulesToolStripMenuItem.Text = "Update &Rules";
            this.updateRulesToolStripMenuItem.Click += new System.EventHandler(this.updateRulesToolStripMenuItem_Click);
            // 
            // frmBootstrap
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(408, 155);
            this.Name = "frmBootstrap";
            this.ShowInTaskbar = false;
            this.Text = "Form1";
            this.WindowState = System.Windows.Forms.FormWindowState.Minimized;
            this.contextMenuStrip1.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.NotifyIcon notifyIcon1;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem mnuSettings;
        private System.Windows.Forms.ToolStripMenuItem mnuExit;
        private System.Windows.Forms.ToolStripMenuItem mnuLastAlert;
        private System.Windows.Forms.ToolStripMenuItem createTroubleshootingLogsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem updateRulesToolStripMenuItem;
    }
}