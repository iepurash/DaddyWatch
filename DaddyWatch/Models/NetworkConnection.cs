using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace DaddyWatch.Models
{
    public partial class NetworkConnection : ObservableObject
    {
        [ObservableProperty]
        private string protocol = "TCP";

        [ObservableProperty]
        private string localAddress = "";

        [ObservableProperty]
        private int localPort;

        [ObservableProperty]
        private string remoteAddress = "";

        [ObservableProperty]
        private int remotePort;

        [ObservableProperty]
        private string state = "";

        [ObservableProperty]
        private int processId;

        [ObservableProperty]
        private string processName = "Unknown";

        [ObservableProperty]
        private string processPath = "";

        [ObservableProperty]
        private string resolvedHostname = "";

        [ObservableProperty]
        private ThreatLevel threat = ThreatLevel.Unknown;

        [ObservableProperty]
        private string threatDetails = "";

        [ObservableProperty]
        private DateTime timestamp = DateTime.Now;

        [ObservableProperty]
        private bool isNew;

        // GeoLocation & Country Flag
        [ObservableProperty]
        private string countryCode = "??";

        [ObservableProperty]
        private string countryName = "Unknown";

        [ObservableProperty]
        private string flagEmoji = "🌐";

        [ObservableProperty]
        private string city = "";

        [ObservableProperty]
        private double latitude;

        [ObservableProperty]
        private double longitude;

        public string Key => $"{Protocol}_{LocalAddress}:{LocalPort}_{RemoteAddress}:{RemotePort}";

        public string DisplayRemoteEndpoint => string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" 
            ? "—" 
            : $"{RemoteAddress}:{RemotePort}";

        public string DisplayLocalEndpoint => $"{LocalAddress}:{LocalPort}";
    }
}
