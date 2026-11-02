using System;
using System.ComponentModel;
using System.Windows;
using DaddyWatch.Services;
using DaddyWatch.ViewModels;

namespace DaddyWatch
{
    public partial class MainWindow : Window
    {
        private SystemTrayService? _trayService;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                _trayService = new SystemTrayService(this);
                _trayService.Initialize();
                _trayService.TrayDoubleClicked += OnTrayDoubleClicked;
            }
            catch
            {
                // Non-fatal if system tray cannot be registered in certain restricted sandbox environments
            }
        }

        private void OnTrayDoubleClicked()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        protected override void OnStateChanged(EventArgs e)
        {
            base.OnStateChanged(e);
            // If minimized, window stays accessible via system tray
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            _trayService?.Dispose();
        }
    }
}
