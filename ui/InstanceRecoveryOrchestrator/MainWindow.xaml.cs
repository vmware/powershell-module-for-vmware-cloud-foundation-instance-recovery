using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace InstanceRecoveryOrchestrator
{
    public partial class MainWindow : Window
    {
        private const string ModuleManifestFileName = "VMware.CloudFoundation.InstanceRecovery.psd1";

        private readonly ObservableCollection<WorkloadDomainViewModel> _domains = new();
        private readonly ObservableCollection<StepViewModel> _steps = new();

        public MainWindow()
        {
            InitializeComponent();
            WorkloadDomainsListBox.ItemsSource = _domains;
            StepsListBox.ItemsSource = _steps;
            Loaded += MainWindow_Loaded;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            WhenTerminalReady(() =>
            {
                var repoRoot = FindRepoRoot();
                if (repoRoot is null)
                {
                    StatusTextBlock.Text = $"Could not locate {ModuleManifestFileName} above this app's build output -- import the module manually in the console.";
                    return;
                }

                var manifestPath = Path.Combine(repoRoot, ModuleManifestFileName);
                SendToConsole($"Import-Module '{EscapeForSingleQuotedString(manifestPath)}' -Force");
            });
        }

        /// <summary>
        /// Walks up from this app's build output looking for the module manifest, so the console
        /// can auto-import the module regardless of Debug/Release or target framework folder depth.
        /// </summary>
        private static string? FindRepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                if (dir.GetFiles(ModuleManifestFileName).Length > 0)
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }
            return null;
        }

        private void WhenTerminalReady(Action action)
        {
            if (Term.ConPTYTerm is not null)
            {
                action();
                return;
            }

            var attempts = 0;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            timer.Tick += (_, _) =>
            {
                attempts++;
                if (Term.ConPTYTerm is not null)
                {
                    timer.Stop();
                    action();
                }
                else if (attempts > 50) // ~10 seconds
                {
                    timer.Stop();
                    StatusTextBlock.Text = "Embedded console did not start in time.";
                }
            };
            timer.Start();
        }

        private void SendToConsole(string commandLine)
        {
            if (Term.ConPTYTerm is null)
            {
                StatusTextBlock.Text = "Console isn't ready yet -- try again in a moment.";
                return;
            }
            Term.ConPTYTerm.WriteToTerm(commandLine + "\r");
        }

        private static string EscapeForSingleQuotedString(string value) => value.Replace("'", "''");

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var extractingBackup = ExtractBackupRadio.IsChecked == true;
            var dialog = new OpenFileDialog
            {
                Filter = extractingBackup ? "All files (*.*)|*.*" : "JSON files (*.json)|*.json|All files (*.*)|*.*",
                Title = extractingBackup ? "Select backup file" : "Select extracted-sddc-data.json"
            };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            FilePathTextBox.Text = dialog.FileName;

            if (extractingBackup)
            {
                // Extracting a backup file is not implemented yet -- selecting a file here does nothing further.
                return;
            }

            LoadExtractedData(dialog.FileName);
        }

        private void LoadExtractedData(string path)
        {
            _domains.Clear();
            _steps.Clear();
            StatusTextBlock.Text = string.Empty;

            try
            {
                using var stream = File.OpenRead(path);
                using var document = JsonDocument.Parse(stream);

                if (!document.RootElement.TryGetProperty("workloadDomains", out var domainsElement))
                {
                    StatusTextBlock.Text = "No 'workloadDomains' property found in the selected file.";
                    return;
                }

                foreach (var domain in domainsElement.EnumerateArray())
                {
                    var name = domain.TryGetProperty("domainName", out var nameProperty) ? nameProperty.GetString() : null;
                    var type = domain.TryGetProperty("domainType", out var typeProperty) ? typeProperty.GetString() : null;
                    if (name is not null)
                    {
                        _domains.Add(new WorkloadDomainViewModel(name, type ?? "UNKNOWN"));
                    }
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                StatusTextBlock.Text = $"Failed to load extracted SDDC data: {ex.Message}";
                return;
            }

            SendToConsole($"$extractedSDDCDataFile = '{EscapeForSingleQuotedString(path)}'");
        }

        private void WorkloadDomainsListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _steps.Clear();
            if (WorkloadDomainsListBox.SelectedItem is not WorkloadDomainViewModel domain)
            {
                return;
            }

            if (string.Equals(domain.DomainType, "MANAGEMENT", StringComparison.OrdinalIgnoreCase))
            {
                _steps.Add(new StepViewModel("New-PrepareManagementHostNetworking -extractedSDDCDataFile $extractedSDDCDataFile -mtu 8900"));
                _steps.Add(new StepViewModel("Add-VMKernelsToManagementHosts -extractedSDDCDataFile $extractedSDDCDataFile"));
            }
        }

        private void RunStep_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement { Tag: StepViewModel step })
            {
                return;
            }

            step.Status = StepStatus.Running;
            SendToConsole(step.CommandLine);
        }
    }
}
