namespace RaccineElevatedCfg
{
    partial class RaccineCfg
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(RaccineCfg));
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.btnRulesFolder = new System.Windows.Forms.Button();
            this.chkScanMemory = new System.Windows.Forms.CheckBox();
            this.label4 = new System.Windows.Forms.Label();
            this.btnViewLog = new System.Windows.Forms.Button();
            this.btnOK = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.chkSimulationMode = new System.Windows.Forms.CheckBox();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.btnRuleBrowse = new System.Windows.Forms.Button();
            this.txtRulesDir = new System.Windows.Forms.TextBox();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.dataGridView1 = new System.Windows.Forms.DataGridView();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage3.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).BeginInit();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage3);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(0, 0);
            this.tabControl1.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(776, 399);
            this.tabControl1.TabIndex = 1;
            this.tabControl1.Selected += new System.Windows.Forms.TabControlEventHandler(this.tabControl1_Selected);
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.btnRulesFolder);
            this.tabPage1.Controls.Add(this.chkScanMemory);
            this.tabPage1.Controls.Add(this.label4);
            this.tabPage1.Controls.Add(this.btnViewLog);
            this.tabPage1.Controls.Add(this.btnOK);
            this.tabPage1.Controls.Add(this.btnCancel);
            this.tabPage1.Controls.Add(this.chkSimulationMode);
            this.tabPage1.Controls.Add(this.label3);
            this.tabPage1.Controls.Add(this.label2);
            this.tabPage1.Controls.Add(this.btnRuleBrowse);
            this.tabPage1.Controls.Add(this.txtRulesDir);
            this.tabPage1.Location = new System.Drawing.Point(4, 29);
            this.tabPage1.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage1.Size = new System.Drawing.Size(768, 366);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Logging Settings";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // btnRulesFolder
            // 
            this.btnRulesFolder.Location = new System.Drawing.Point(234, 295);
            this.btnRulesFolder.Name = "btnRulesFolder";
            this.btnRulesFolder.Size = new System.Drawing.Size(183, 41);
            this.btnRulesFolder.TabIndex = 10;
            this.btnRulesFolder.Text = "S&how Rules Folder";
            this.btnRulesFolder.UseVisualStyleBackColor = true;
            this.btnRulesFolder.Click += new System.EventHandler(this.btnRulesFolder_Click);
            // 
            // chkScanMemory
            // 
            this.chkScanMemory.AutoSize = true;
            this.chkScanMemory.Location = new System.Drawing.Point(184, 145);
            this.chkScanMemory.Name = "chkScanMemory";
            this.chkScanMemory.Size = new System.Drawing.Size(56, 24);
            this.chkScanMemory.TabIndex = 9;
            this.chkScanMemory.Text = "On";
            this.chkScanMemory.UseVisualStyleBackColor = true;
            this.chkScanMemory.CheckedChanged += new System.EventHandler(this.chkScanMemory_CheckedChanged);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(41, 150);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(110, 20);
            this.label4.TabIndex = 8;
            this.label4.Text = "Scan Memory:";
            // 
            // btnViewLog
            // 
            this.btnViewLog.Location = new System.Drawing.Point(36, 295);
            this.btnViewLog.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.btnViewLog.Name = "btnViewLog";
            this.btnViewLog.Size = new System.Drawing.Size(183, 41);
            this.btnViewLog.TabIndex = 7;
            this.btnViewLog.Text = "&Show Raccine Logs";
            this.btnViewLog.UseVisualStyleBackColor = true;
            this.btnViewLog.Click += new System.EventHandler(this.btnViewLog_Click);
            // 
            // btnOK
            // 
            this.btnOK.Location = new System.Drawing.Point(504, 295);
            this.btnOK.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.btnOK.Name = "btnOK";
            this.btnOK.Size = new System.Drawing.Size(113, 41);
            this.btnOK.TabIndex = 6;
            this.btnOK.Text = "OK";
            this.btnOK.UseVisualStyleBackColor = true;
            this.btnOK.Click += new System.EventHandler(this.btnOK_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.Location = new System.Drawing.Point(641, 295);
            this.btnCancel.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(101, 41);
            this.btnCancel.TabIndex = 5;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // chkSimulationMode
            // 
            this.chkSimulationMode.AutoSize = true;
            this.chkSimulationMode.Location = new System.Drawing.Point(184, 84);
            this.chkSimulationMode.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.chkSimulationMode.Name = "chkSimulationMode";
            this.chkSimulationMode.Size = new System.Drawing.Size(56, 24);
            this.chkSimulationMode.TabIndex = 4;
            this.chkSimulationMode.Text = "On";
            this.chkSimulationMode.UseVisualStyleBackColor = true;
            this.chkSimulationMode.CheckStateChanged += new System.EventHandler(this.chkSimulationMode_CheckStateChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(20, 78);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(131, 20);
            this.label3.TabIndex = 3;
            this.label3.Text = "Simulation Mode:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(55, 25);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(103, 20);
            this.label2.TabIndex = 2;
            this.label2.Text = "Rules Folder:";
            // 
            // btnRuleBrowse
            // 
            this.btnRuleBrowse.Location = new System.Drawing.Point(641, 22);
            this.btnRuleBrowse.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.btnRuleBrowse.Name = "btnRuleBrowse";
            this.btnRuleBrowse.Size = new System.Drawing.Size(101, 47);
            this.btnRuleBrowse.TabIndex = 1;
            this.btnRuleBrowse.Text = "B&rowse...";
            this.btnRuleBrowse.UseVisualStyleBackColor = true;
            this.btnRuleBrowse.Click += new System.EventHandler(this.btnRuleBrowse_Click);
            // 
            // txtRulesDir
            // 
            this.txtRulesDir.Location = new System.Drawing.Point(172, 22);
            this.txtRulesDir.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.txtRulesDir.Name = "txtRulesDir";
            this.txtRulesDir.Size = new System.Drawing.Size(362, 26);
            this.txtRulesDir.TabIndex = 0;
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.dataGridView1);
            this.tabPage3.Location = new System.Drawing.Point(4, 29);
            this.tabPage3.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Size = new System.Drawing.Size(768, 366);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Eventlog";
            // 
            // dataGridView1
            // 
            this.dataGridView1.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dataGridView1.Location = new System.Drawing.Point(0, 0);
            this.dataGridView1.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.RowHeadersWidth = 62;
            this.dataGridView1.Size = new System.Drawing.Size(768, 366);
            this.dataGridView1.TabIndex = 0;
            this.dataGridView1.Text = "dataGridView1";
            // 
            // tabPage2
            // 
            this.tabPage2.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("tabPage2.BackgroundImage")));
            this.tabPage2.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.tabPage2.Controls.Add(this.textBox1);
            this.tabPage2.Controls.Add(this.label1);
            this.tabPage2.Location = new System.Drawing.Point(4, 29);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage2.Size = new System.Drawing.Size(768, 366);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "About";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // textBox1
            // 
            this.textBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox1.Location = new System.Drawing.Point(121, 31);
            this.textBox1.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(297, 19);
            this.textBox1.TabIndex = 1;
            this.textBox1.Text = "v1.4.1 BETA";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(37, 31);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(67, 20);
            this.label1.TabIndex = 0;
            this.label1.Text = "Version:";
            // 
            // RaccineCfg
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(776, 399);
            this.Controls.Add(this.tabControl1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.Name = "RaccineCfg";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Raccine Configuration";
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.tabPage3.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).EndInit();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button btnRuleBrowse;
        private System.Windows.Forms.TextBox txtRulesDir;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
        private System.Windows.Forms.CheckBox chkSimulationMode;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button btnOK;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.Button btnViewLog;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.DataGridView dataGridView1;
        private System.Windows.Forms.Button btnRulesFolder;
        private System.Windows.Forms.CheckBox chkScanMemory;
        private System.Windows.Forms.Label label4;
    }
}
