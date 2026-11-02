using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace DaddyWatch.Models
{
    public partial class ThreatFeed : ObservableObject
    {
        [ObservableProperty]
        private string name = "";

        [ObservableProperty]
        private string url = "";

        [ObservableProperty]
        private bool isMalicious = true;

        [ObservableProperty]
        private bool isEnabled = true;

        [ObservableProperty]
        private int entryCount;

        [ObservableProperty]
        private string status = "Not Loaded";

        [ObservableProperty]
        private DateTime? lastUpdated;

        public string Category => IsMalicious ? "Threat Blocklist" : "Trusted Allowlist";
    }
}
