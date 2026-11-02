using System;
using System.Collections.Generic;

namespace DaddyWatch.Models
{
    public class DnsInspectResult
    {
        public string Target { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string CanonicalName { get; set; } = "";
        public List<string> ResolvedIps { get; set; } = new();
        public ThreatLevel Threat { get; set; } = ThreatLevel.Unknown;
        public string ThreatDetails { get; set; } = "";
        public string Status { get; set; } = "OK";
        public long ResponseTimeMs { get; set; }

        public string IpsFormatted => ResolvedIps.Count > 0 ? string.Join(", ", ResolvedIps) : "None";
        public string TimeFormatted => Timestamp.ToString("HH:mm:ss");
    }
}
