using System;
using System.Collections.Concurrent;
using Microsoft.Toolkit.Uwp.Notifications;

namespace DaddyWatch.Services
{
    public class NotificationService
    {
        public bool IsToastEnabled { get; set; } = true;
        public bool IsAudioAlertEnabled { get; set; } = true;

        private readonly ConcurrentDictionary<string, DateTime> _alertHistory = new();
        private readonly TimeSpan _throttleDuration = TimeSpan.FromMinutes(2);

        public void TriggerThreatAlert(string ip, string processName, int pid, string feedDetails)
        {
            if (!IsToastEnabled) return;

            var now = DateTime.UtcNow;
            if (_alertHistory.TryGetValue(ip, out var lastAlerted))
            {
                if (now - lastAlerted < _throttleDuration)
                    return; // Throttled
            }

            _alertHistory[ip] = now;

            try
            {
                new ToastContentBuilder()
                    .AddText("🚨 DaddyWatch: Active Threat Detected!")
                    .AddText($"Remote IP: {ip}")
                    .AddText($"Process: {processName} (PID: {pid})")
                    .AddText($"Threat: {feedDetails}")
                    .Show();

                if (IsAudioAlertEnabled)
                {
                    System.Media.SystemSounds.Exclamation.Play();
                }
            }
            catch
            {
                // Toasts can throw if notification permissions are restricted
            }
        }
    }
}
