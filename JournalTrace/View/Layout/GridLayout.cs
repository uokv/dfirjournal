using JournalTrace.Language;
using JournalTrace.Entry;
using JournalTrace.Native;
using System;
using System.Data;
using System.Windows.Forms;
using System.Threading.Tasks;
using JournalTrace.View.Util;
using System.Collections.Generic;
using System.Linq;

namespace JournalTrace.View.Layout
{
    public partial class GridLayout : UserControl, ILayout
    {
        private EntryManager entryManager;
        private readonly List<DataRow> syntheticCleanedRows = new List<DataRow>();
        private bool cleanedsBusy;
        private bool cleanedsSuppress;

        public GridLayout(EntryManager mngr)
        {
            this.entryManager = mngr;

            InitializeComponent();

            comboSearch.SelectedIndex = 1;
            //campos de tradução
            datagJournalEntries.Tag = new string[] { null, "name", "date", "reason", "directory" };
            comboSearch.Tag = new string[] { null, "name", "date", "reason", "directory" };
        }
        public void Clean()
        {
            datagJournalEntries.DataSource = null;
            dataSourceEntries.Clear();
            dataSourceEntries.Dispose();
            datagJournalEntries.Rows.Clear();
            datagJournalEntries.Dispose();
            GC.Collect();
        }

        public Control GetControl()
        {
            return this;
        }

        public DataTable dataSourceEntries;

        public async void LoadData(FormMain frm)
        {
            dataSourceEntries = new DataTable();

            dataSourceEntries.Columns.Add("USN", typeof(long));
            dataSourceEntries.Columns.Add("name", typeof(string));
            dataSourceEntries.Columns.Add("date", typeof(string));
            dataSourceEntries.Columns.Add("reason", typeof(string));
            dataSourceEntries.Columns.Add("directory", typeof(string));

            await Task.Run(() =>
            {
                foreach (var item in entryManager.USNEntries)
                {
                    USNEntry entry = item.Value;
                    dataSourceEntries.Rows.Add(entry.USN, entry.Name, entry.Time, entry.Reason, entryManager.parentFileReferenceIdentifiers[entry.ParentFileReference].ResolvedID);
                }
            });

            datagJournalEntries.DataSource = dataSourceEntries;

            LanguageManager.INSTANCE.UpdateControl(datagJournalEntries);

            //tamanho das colunas
            int[] widthColumns = new int[] { 88, 200, 115, 300, 500 };

            for (int i = 0; i < widthColumns.Length; i++)
            {
                datagJournalEntries.Columns[i].Width = widthColumns[i];
            }

            frm.ShowLayoutOption(true);
        }
        private void performSearch()
        {
            string filterText = txtSearch.Text.Trim();
            string reasonColumn = "reason";
            string combinedFilter = "";

            if (!string.IsNullOrWhiteSpace(filterText))
            {
                if (filterText.Contains(":") && !IsValidPath(filterText))
                {
                    string[] filterConditions = filterText.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string condition in filterConditions)
                    {
                        string[] parts = condition.Split(new[] { ':' }, 2);
                        if (parts.Length != 2) continue;

                        string columnName = parts[0].Trim();
                        string filterValue = parts[1].Trim();

                        if (!dataSourceEntries.Columns.Contains(columnName) && !IsValidPath(filterValue))
                            continue;

                        string columnFilter = BuildColumnFilter(columnName, filterValue);
                        if (!string.IsNullOrEmpty(columnFilter))
                            combinedFilter = AppendFilter(combinedFilter, columnFilter);
                    }
                }
                else
                {
                    string columnName;
                    string searchValue;

                    if (IsValidPath(filterText))
                    {
                        columnName = "directory";
                        searchValue = filterText;
                    }
                    else if (comboSearch.SelectedIndex > 0)
                    {
                        columnName = dataSourceEntries.Columns[comboSearch.SelectedIndex].ColumnName;
                        searchValue = filterText;
                    }
                    else
                    {
                        dataSourceEntries.DefaultView.RowFilter = "";
                        return;
                    }

                    string columnFilter = BuildColumnFilter(columnName, searchValue);
                    if (!string.IsNullOrEmpty(columnFilter))
                        combinedFilter = AppendFilter(combinedFilter, columnFilter);
                }
            }

            combinedFilter = AppendCheckBoxFilters(combinedFilter, reasonColumn);
            if (CBcleaneds.Checked && dataSourceEntries.Columns.Contains("cleaned"))
                combinedFilter = AppendFilter(combinedFilter, "(ISNULL(cleaned, '') <> '')");
            dataSourceEntries.DefaultView.RowFilter = combinedFilter;
        }

        private bool IsValidPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            return path.Contains(":\\") ||
                   path.StartsWith("\\\\") ||
                   path.StartsWith("/") ||
                   path.StartsWith("./") ||
                   path.StartsWith("../");
        }

        private string BuildColumnFilter(string columnName, string filterValue)
        {
            if (string.IsNullOrWhiteSpace(filterValue))
                return string.Empty;

            string columnFilter = "";

            if (filterValue.Contains("!!"))
            {
                string[] parts = filterValue.Split(new[] { "!!" }, StringSplitOptions.None);
                if (!string.IsNullOrWhiteSpace(parts[0]))
                    columnFilter = $"{columnName} LIKE '%{parts[0].Trim()}%'";

                for (int i = 1; i < parts.Length; i++)
                {
                    if (!string.IsNullOrWhiteSpace(parts[i]))
                        columnFilter = AppendFilter(columnFilter, $"{columnName} NOT LIKE '%{parts[i].Trim()}%'", "AND");
                }
            }
            else if (filterValue.Contains("&&"))
            {
                var parts = filterValue.Split(new[] { "&&" }, StringSplitOptions.RemoveEmptyEntries);
                columnFilter = string.Join(" AND ", parts.Select(p => $"{columnName} LIKE '%{p.Trim()}%'"));
            }
            else if (filterValue.Contains("||"))
            {
                var parts = filterValue.Split(new[] { "||" }, StringSplitOptions.RemoveEmptyEntries);
                columnFilter = string.Join(" OR ", parts.Select(p => $"{columnName} LIKE '%{p.Trim()}%'"));
            }
            else
            {
                columnFilter = $"{columnName} LIKE '%{filterValue}%'";
            }

            return !string.IsNullOrEmpty(columnFilter) ? $"({columnFilter})" : string.Empty;
        }

        private string AppendFilter(string existingFilter, string newFilter, string conjunction = "AND")
        {
            if (string.IsNullOrEmpty(existingFilter))
                return newFilter;
            if (string.IsNullOrEmpty(newFilter))
                return existingFilter;
            return $"{existingFilter} {conjunction} {newFilter}";
        }

        private string AppendCheckBoxFilters(string currentFilter, string reasonColumn)
        {
            var checkBoxFilters = new Dictionary<CheckBox, string>
    {
        { CBdeleted, "File delete" },
        { CBrenamednew, "Rename: new name" },
        { CBrenamedold, "Rename: old name" },
        { CBstreamchange, "Stream change" },
        { CBbasicinfochange, "Basic info change" }
    };

            foreach (var checkBox in checkBoxFilters)
            {
                if (checkBox.Key.Checked)
                {
                    string newFilter = $"({reasonColumn} LIKE '%{checkBox.Value}%')";
                    currentFilter = AppendFilter(currentFilter, newFilter);
                }
            }

            return currentFilter;
        }
        private void btSearch_Click(object sender, EventArgs e)
        {
            performSearch();
        }

        private void txtSearch_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                btSearch_Click(this, null);
            }
        }

        private void btSearchClear_Click(object sender, EventArgs e)
        {
            dataSourceEntries.DefaultView.RowFilter = "";
        }

        private void datagJournalEntries_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            ContextMenuHelper.INSTANCE.ShowContext(datagJournalEntries, e);
        }

        private void CBdataextend_CheckedChanged(object sender, EventArgs e)
        {
            performSearch();
        }

        private void CBrenamed_CheckedChanged(object sender, EventArgs e)
        {
            performSearch();
        }

        private void CBdeleted_CheckedChanged(object sender, EventArgs e)
        {
            performSearch();
        }

        private void CBrenamedold_CheckedChanged(object sender, EventArgs e)
        {
            performSearch();
        }

        private void CBbasicinfochange_CheckedChanged(object sender, EventArgs e)
        {
            performSearch();
        }

        private async void CBcleaneds_CheckedChanged(object sender, EventArgs e)
        {
            if (cleanedsSuppress)
                return;

            if (!CBcleaneds.Checked)
            {
                RemoveSyntheticCleanedRows();
                CBcleaneds.Text = "cleaneds";
                performSearch();
                return;
            }

            if (datagJournalEntries.DataSource == null || dataSourceEntries == null)
            {
                MessageBox.Show("Espere o journal terminar de carregar.", "cleaneds");
                SetCleanedsChecked(false);
                return;
            }

            var volume = entryManager.SelectedVolume;
            if (volume == null || string.IsNullOrEmpty(volume.Name))
            {
                MessageBox.Show("Nenhum volume selecionado.", "cleaneds");
                SetCleanedsChecked(false);
                return;
            }

            if (entryManager.CleanedScan == null)
            {
                if (cleanedsBusy)
                    return;

                cleanedsBusy = true;
                CBcleaneds.Enabled = false;
                CBcleaneds.Text = "cleaneds...";
                char letter = volume.Name[0];
                UsnJournalIntegrity.ScanResult result;
                try
                {
                    result = await Task.Run(() => UsnJournalIntegrity.ScanVolume(letter, 500));
                }
                catch (Exception ex)
                {
                    result = new UsnJournalIntegrity.ScanResult();
                    result.Status = UsnJournalIntegrity.Status.Unverified;
                    result.Reason = ex.Message;
                }

                cleanedsBusy = false;
                if (IsDisposed)
                    return;

                CBcleaneds.Enabled = true;
                entryManager.CleanedScan = result;
                if (!CBcleaneds.Checked)
                {
                    CBcleaneds.Text = "cleaneds";
                    return;
                }
            }

            ShowCleaned(entryManager.CleanedScan);
        }

        private void ShowCleaned(UsnJournalIntegrity.ScanResult result)
        {
            if (result == null || result.Status == UsnJournalIntegrity.Status.Inactive || result.Status == UsnJournalIntegrity.Status.Unverified)
            {
                string reason = result == null || string.IsNullOrEmpty(result.Reason)
                    ? "Não foi possível verificar o journal."
                    : result.Reason;
                MessageBox.Show(reason, "cleaneds");
                CBcleaneds.Text = "cleaneds";
                SetCleanedsChecked(false);
                performSearch();
                return;
            }

            long total = result.SignalCount;

            if (result.Status == UsnJournalIntegrity.Status.Clean || total == 0)
            {
                MessageBox.Show("Nenhum indício de limpeza no journal.", "cleaneds");
                CBcleaneds.Text = "cleaneds";
                SetCleanedsChecked(false);
                performSearch();
                return;
            }

            CBcleaneds.Text = "cleaneds (" + total + ")";
            ApplyCleanedFindings(result);
            performSearch();
        }

        private void ApplyCleanedFindings(UsnJournalIntegrity.ScanResult result)
        {
            if (!dataSourceEntries.Columns.Contains("cleaned"))
                dataSourceEntries.Columns.Add("cleaned", typeof(string));

            if (datagJournalEntries.Columns.Contains("cleaned"))
            {
                datagJournalEntries.Columns["cleaned"].HeaderText = "cleaned";
                datagJournalEntries.Columns["cleaned"].Width = 280;
            }

            if (syntheticCleanedRows.Count > 0)
                return;

            var byUsn = new Dictionary<long, List<UsnJournalIntegrity.Finding>>();
            foreach (UsnJournalIntegrity.Finding finding in result.Findings)
            {
                if (finding.Usn <= 0)
                    continue;
                List<UsnJournalIntegrity.Finding> list;
                if (!byUsn.TryGetValue(finding.Usn, out list))
                {
                    list = new List<UsnJournalIntegrity.Finding>();
                    byUsn.Add(finding.Usn, list);
                }
                list.Add(finding);
            }

            var seen = new HashSet<long>();
            foreach (DataRow row in dataSourceEntries.Rows)
            {
                if (row.RowState == DataRowState.Deleted || row.RowState == DataRowState.Detached)
                    continue;
                if (row["USN"] == DBNull.Value)
                    continue;

                long usn = Convert.ToInt64(row["USN"]);
                List<UsnJournalIntegrity.Finding> list;
                if (!byUsn.TryGetValue(usn, out list))
                    continue;

                seen.Add(usn);
                row["cleaned"] = string.Join(" | ", list.Select(item => item.Formatted));
            }

            foreach (UsnJournalIntegrity.Finding finding in result.Findings)
            {
                if (finding.Usn > 0 && seen.Contains(finding.Usn))
                    continue;
                AddSyntheticCleanedRow(finding.Usn > 0 ? finding.Usn : 0L, finding);
            }

            foreach (string line in result.ExtraLines)
            {
                DataRow row = dataSourceEntries.NewRow();
                row["USN"] = 0L;
                row["name"] = line;
                row["date"] = "";
                row["reason"] = "";
                row["directory"] = "";
                row["cleaned"] = line;
                dataSourceEntries.Rows.Add(row);
                syntheticCleanedRows.Add(row);
            }
        }

        private void AddSyntheticCleanedRow(long usn, UsnJournalIntegrity.Finding finding)
        {
            DataRow row = dataSourceEntries.NewRow();
            row["USN"] = usn;
            row["name"] = string.IsNullOrEmpty(finding.Residual) ? finding.Formatted : finding.Residual;
            row["date"] = finding.Timestamp ?? "";
            row["reason"] = finding.Code ?? "";
            row["directory"] = "";
            row["cleaned"] = string.IsNullOrEmpty(finding.Formatted) ? finding.Code : finding.Formatted;
            dataSourceEntries.Rows.Add(row);
            syntheticCleanedRows.Add(row);
        }

        private void RemoveSyntheticCleanedRows()
        {
            if (dataSourceEntries == null || syntheticCleanedRows.Count == 0)
                return;

            dataSourceEntries.DefaultView.RowFilter = "";
            foreach (DataRow row in syntheticCleanedRows)
            {
                if (row.RowState != DataRowState.Detached && row.RowState != DataRowState.Deleted)
                    row.Delete();
            }
            syntheticCleanedRows.Clear();
            dataSourceEntries.AcceptChanges();
        }

        private void SetCleanedsChecked(bool value)
        {
            cleanedsSuppress = true;
            CBcleaneds.Checked = value;
            cleanedsSuppress = false;
        }
    }
}
