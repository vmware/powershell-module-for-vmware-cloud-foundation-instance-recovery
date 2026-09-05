using System.ComponentModel;
using System.Windows.Media;

namespace InstanceRecoveryOrchestrator
{
    public enum StepStatus
    {
        Pending,
        Running
    }

    /// <summary>
    /// Status is set to Running as soon as its command line is sent to the console. There is no
    /// automatic Done/Failed detection yet -- ConPTY has no clean "child process finished this
    /// command" signal, so that's left as a known gap rather than guessed at with a heuristic.
    /// </summary>
    public sealed class StepViewModel : INotifyPropertyChanged
    {
        private StepStatus _status = StepStatus.Pending;

        public StepViewModel(string commandLine)
        {
            CommandLine = commandLine;
        }

        public string CommandLine { get; }

        public StepStatus Status
        {
            get => _status;
            set
            {
                if (_status == value)
                {
                    return;
                }
                _status = value;
                OnPropertyChanged(nameof(Status));
                OnPropertyChanged(nameof(StatusColor));
            }
        }

        public Brush StatusColor => Status switch
        {
            StepStatus.Running => Brushes.DodgerBlue,
            _ => Brushes.LightGray
        };

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
