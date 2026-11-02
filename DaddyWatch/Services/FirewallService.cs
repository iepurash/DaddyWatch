using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class FirewallService
    {
        private const string RulePrefix = "DaddyWatch_Block_";
        private readonly List<BlockedFirewallRule> _blockedRules = new();

        public IReadOnlyList<BlockedFirewallRule> BlockedRules => _blockedRules;

        public async Task<(bool Success, string Message)> BlockIpAsync(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "127.0.0.1" || ip == "0.0.0.0")
                return (false, "Cannot block loopback or wildcards.");

            string cleanIp = ip.Trim();
            string ruleNameOut = $"{RulePrefix}{cleanIp}_OUT";
            string ruleNameIn = $"{RulePrefix}{cleanIp}_IN";

            try
            {
                // Run netsh to add outbound and inbound blocking rules
                string cmdOut = $"advfirewall firewall add rule name=\"{ruleNameOut}\" dir=out action=block remoteip={cleanIp} enable=yes";
                string cmdIn = $"advfirewall firewall add rule name=\"{ruleNameIn}\" dir=in action=block remoteip={cleanIp} enable=yes";

                await RunNetshCommandAsync(cmdOut);
                await RunNetshCommandAsync(cmdIn);

                lock (_blockedRules)
                {
                    if (!_blockedRules.Exists(r => r.RemoteIp == cleanIp))
                    {
                        _blockedRules.Add(new BlockedFirewallRule
                        {
                            RuleName = ruleNameOut,
                            RemoteIp = cleanIp,
                            Direction = "Bi-directional",
                            DateCreated = DateTime.Now
                        });
                    }
                }

                return (true, $"Blocked {cleanIp} in Windows Firewall (Inbound & Outbound).");
            }
            catch (Exception ex)
            {
                return (false, $"Failed to configure firewall: {ex.Message}");
            }
        }

        public async Task<(bool Success, string Message)> UnblockIpAsync(string ip)
        {
            string cleanIp = ip.Trim();
            string ruleNameOut = $"{RulePrefix}{cleanIp}_OUT";
            string ruleNameIn = $"{RulePrefix}{cleanIp}_IN";

            try
            {
                await RunNetshCommandAsync($"advfirewall firewall delete rule name=\"{ruleNameOut}\"");
                await RunNetshCommandAsync($"advfirewall firewall delete rule name=\"{ruleNameIn}\"");

                lock (_blockedRules)
                {
                    _blockedRules.RemoveAll(r => r.RemoteIp == cleanIp);
                }

                return (true, $"Removed firewall rules for {cleanIp}.");
            }
            catch (Exception ex)
            {
                return (false, $"Error unblocking: {ex.Message}");
            }
        }

        public bool TerminateProcess(int pid, out string message)
        {
            if (pid <= 4)
            {
                message = "Protected Windows system process cannot be terminated.";
                return false;
            }

            try
            {
                using var proc = Process.GetProcessById(pid);
                string procName = proc.ProcessName;
                proc.Kill(true); // Kill process tree
                message = $"Terminated process '{procName}' (PID {pid}).";
                return true;
            }
            catch (Exception ex)
            {
                message = $"Failed to terminate PID {pid}: {ex.Message}";
                return false;
            }
        }

        private static async Task<string> RunNetshCommandAsync(string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi);
            if (process == null) throw new InvalidOperationException("Could not launch netsh.exe");

            string output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            return output;
        }
    }
}
