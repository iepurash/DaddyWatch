using System;

namespace DaddyWatch.Models
{
    public class BlockedFirewallRule
    {
        public string RuleName { get; set; } = "";
        public string RemoteIp { get; set; } = "";
        public string Direction { get; set; } = "Outbound";
        public DateTime DateCreated { get; set; } = DateTime.Now;
    }
}
