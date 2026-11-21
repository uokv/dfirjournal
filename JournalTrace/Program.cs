using JournalTrace.Language;
using JournalTrace.View.Util;
using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace JournalTrace
{
    internal static class Program
    {
        /// <summary>
        /// Ponto de entrada principal para o aplicativo.
        /// </summary>
        [STAThread]
        private static void Main()
        {
            _ = new LanguageManager();
            _ = new ContextMenuHelper();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://discord.gg/DFIR",
                    UseShellExecute = true
                });
            }
            catch (Exception)
            {
            }
            Application.Run(new FormMain());
        }
    }
}