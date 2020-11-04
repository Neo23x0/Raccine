using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RaccineSettings
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            frmBootstrap f = new frmBootstrap();
            f.Visible = false;
            if (!f.IsDisposed) // our single instance check will exit the constructor early
                Application.Run(f);
        }
    }
}
