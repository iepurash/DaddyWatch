using System;

namespace DaddyWatch.Models
{
    public class ThreatLogEntry
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string TimeFormatted => Timestamp.ToString("HH:mm:ss");
        public string DateFormatted => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
        public string Severity { get; set; } = "INFO"; // CRITICAL, WARNING, INFO, SUCCESS
        public string RemoteEndpoint { get; set; } = "";
        public string ProcessInfo { get; set; } = "";
        public string Message { get; set; } = "";
        public string ActionTaken { get; set; } = "";
    }
}
