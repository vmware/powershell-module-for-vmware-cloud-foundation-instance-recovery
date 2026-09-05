using ConPty;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using VtNetCore.VirtualTerminal;
using VtNetCore.XTermParser;

namespace VtNetCoreSpike
{
    /// <summary>
    /// Minimal custom-drawn terminal surface over VtNetCore's screen-buffer model.
    /// Not a general-purpose terminal control — just enough fidelity (color, bold/underline,
    /// cursor-key/function-key input) to compare against EasyWindowsTerminalControl for the
    /// same test-render.ps1 script.
    /// </summary>
    public sealed class TerminalRenderer : FrameworkElement
    {
        private const double FontSize = 14;
        private static readonly Typeface MonoTypeface = new(new FontFamily("Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        private readonly VirtualTerminalController _controller = new();
        private readonly DataConsumer _consumer;
        private readonly PseudoConsoleSession _session = new();
        private double _charWidth = 8;
        private double _charHeight = 16;

        public TerminalRenderer()
        {
            _consumer = new DataConsumer(_controller);
            _controller.SendData += (_, e) => _session.Write(e.Data);

            Focusable = true;
            FocusVisualStyle = null;
            SnapsToDevicePixels = true;

            MeasureFont();

            Loaded += (_, _) => StartSession();
            SizeChanged += (_, _) => ResizeToBounds();
            Unloaded += (_, _) => _session.Dispose();
        }

        private void MeasureFont()
        {
            var probe = new FormattedText("M", CultureInfo.InvariantCulture, FlowDirection.LeftToRight, MonoTypeface, FontSize, Brushes.White, 1.0);
            _charWidth = probe.WidthIncludingTrailingWhitespace;
            _charHeight = probe.Height;
        }

        private (int columns, int rows) CurrentGridSize()
        {
            var columns = Math.Max(1, (int)(ActualWidth / _charWidth));
            var rows = Math.Max(1, (int)(ActualHeight / _charHeight));
            return (columns, rows);
        }

        private void StartSession()
        {
            var (columns, rows) = CurrentGridSize();
            _controller.ResizeView(columns, rows);
            _session.Start("pwsh.exe -NoLogo -NoExit", columns, rows);
            _session.Exited += (_, _) => Dispatcher.BeginInvoke(InvalidateVisual);

            var readThread = new Thread(PumpOutput) { IsBackground = true };
            readThread.Start();

            Keyboard.Focus(this);
        }

        private void PumpOutput()
        {
            var buffer = new byte[4096];
            try
            {
                int read;
                while ((read = _session.ConsoleOutStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    var chunk = new byte[read];
                    Array.Copy(buffer, chunk, read);
                    _consumer.Push(chunk);
                    Dispatcher.BeginInvoke(DispatcherPriority.Render, InvalidateVisual);
                }
            }
            catch (ObjectDisposedException)
            {
                // Session torn down (window closed) while a read was in flight — expected.
            }
        }

        private void ResizeToBounds()
        {
            var (columns, rows) = CurrentGridSize();
            _controller.ResizeView(columns, rows);
            _session.Resize(columns, rows);
        }

        protected override void OnRender(DrawingContext dc)
        {
            dc.DrawRectangle(Brushes.Black, null, new Rect(0, 0, ActualWidth, ActualHeight));

            if (_controller.VisibleRows == 0)
            {
                return;
            }

            var rows = _controller.GetPageSpans(0, _controller.VisibleRows, _controller.VisibleColumns);
            for (var rowIndex = 0; rowIndex < rows.Count; rowIndex++)
            {
                double x = 0;
                var y = rowIndex * _charHeight;

                foreach (var span in rows[rowIndex].Spans)
                {
                    if (string.IsNullOrEmpty(span.Text))
                    {
                        continue;
                    }

                    var width = span.Text.Length * _charWidth;

                    if (!string.IsNullOrEmpty(span.BackgroundColor))
                    {
                        dc.DrawRectangle(new SolidColorBrush(ParseColor(span.BackgroundColor, Colors.Black)), null, new Rect(x, y, width, _charHeight));
                    }

                    if (!span.Hidden)
                    {
                        var typeface = new Typeface(
                            MonoTypeface.FontFamily,
                            span.Italic ? FontStyles.Italic : FontStyles.Normal,
                            span.Bold ? FontWeights.Bold : FontWeights.Normal,
                            FontStretches.Normal);
                        var text = new FormattedText(
                            span.Text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                            typeface, FontSize, new SolidColorBrush(ParseColor(span.ForgroundColor, Colors.LightGray)), 1.0);
                        if (span.Underline)
                        {
                            text.SetTextDecorations(TextDecorations.Underline);
                        }
                        dc.DrawText(text, new Point(x, y));
                    }

                    x += width;
                }
            }
        }

        private static Color ParseColor(string? value, Color fallback)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }
            try
            {
                return (Color)ColorConverter.ConvertFromString(value);
            }
            catch (FormatException)
            {
                return fallback;
            }
        }

        protected override void OnPreviewTextInput(TextCompositionEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.Text))
            {
                _session.Write(e.Text);
                e.Handled = true;
            }
            base.OnPreviewTextInput(e);
        }

        protected override void OnPreviewKeyDown(KeyEventArgs e)
        {
            var control = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
            var shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);

            // Ctrl+C has no entry in VtNetCore's key table (it's a signal, not a key sequence) —
            // forward it as raw ETX so Write-Progress loops / prompts can be interrupted like a real console.
            if (control && e.Key == Key.C)
            {
                _session.Write(new byte[] { 0x03 });
                e.Handled = true;
                return;
            }

            var sequence = KeyboardTranslations.GetKeySequence(
                e.Key.ToString(), control, shift, _controller.CursorState.ApplicationCursorKeysMode);
            if (sequence != null)
            {
                _session.Write(sequence);
                e.Handled = true;
            }

            base.OnPreviewKeyDown(e);
        }

        protected override void OnMouseDown(MouseButtonEventArgs e)
        {
            Keyboard.Focus(this);
            base.OnMouseDown(e);
        }
    }
}
