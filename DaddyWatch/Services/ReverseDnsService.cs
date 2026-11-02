using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class ReverseDnsService
    {
        private static readonly ConcurrentDictionary<string, string> HostnameCache = new();
        private static readonly SemaphoreSlim DnsSemaphore = new(3, 3);
        private const int TimeoutMs = 1500;

        public ConcurrentQueue<DnsInspectResult> RecentQueries { get; } = new();

        public async Task<string> ResolveHostnameAsync(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "0.0.0.0" || ip == "*" || ip == "::")
                return "";

            if (HostnameCache.TryGetValue(ip, out var cached))
                return cached;

            // Wait for semaphore slot to avoid thread pool exhaustion
            bool acquired = await DnsSemaphore.WaitAsync(500);
            if (!acquired) return "";

            try
            {
                using var cts = new CancellationTokenSource(TimeoutMs);
                var dnsTask = Dns.GetHostEntryAsync(ip);

                var completed = await Task.WhenAny(dnsTask, Task.Delay(TimeoutMs, cts.Token));
                if (completed == dnsTask && !dnsTask.IsFaulted)
                {
                    var entry = await dnsTask;
                    string hostname = entry.HostName ?? "";
                    HostnameCache[ip] = hostname;

                    RecordQuery(ip, hostname, new[] { ip });
                    return hostname;
                }
                else
                {
                    // Timed out or failed: cache negative to prevent repeated lag
                    HostnameCache[ip] = "";
                    return "";
                }
            }
            catch
            {
                HostnameCache[ip] = "";
                return "";
            }
            finally
            {
                DnsSemaphore.Release();
            }
        }

        public async Task<DnsInspectResult> InspectTargetAsync(string target)
        {
            var sw = Stopwatch.StartNew();
            var result = new DnsInspectResult
            {
                Target = target,
                Timestamp = DateTime.Now
            };

            if (string.IsNullOrWhiteSpace(target))
            {
                result.Status = "Empty query";
                return result;
            }

            string clean = target.Trim();

            try
            {
                if (IPAddress.TryParse(clean, out var ipAddress))
                {
                    // Reverse PTR lookup
                    var entry = await Dns.GetHostEntryAsync(ipAddress);
                    sw.Stop();
                    result.CanonicalName = entry.HostName ?? "";
                    result.ResolvedIps = entry.AddressList.Select(a => a.ToString()).ToList();
                    result.ResponseTimeMs = sw.ElapsedMilliseconds;
                    result.Status = "Resolved (PTR)";
                }
                else
                {
                    // Forward A/AAAA lookup
                    var entry = await Dns.GetHostEntryAsync(clean);
                    sw.Stop();
                    result.CanonicalName = entry.HostName ?? clean;
                    result.ResolvedIps = entry.AddressList.Select(a => a.ToString()).ToList();
                    result.ResponseTimeMs = sw.ElapsedMilliseconds;
                    result.Status = "Resolved (A/AAAA)";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                result.ResponseTimeMs = sw.ElapsedMilliseconds;
                result.Status = $"Lookup Failed: {ex.Message}";
            }

            RecordQuery(result.Target, result.CanonicalName, result.ResolvedIps);
            return result;
        }

        private void RecordQuery(string target, string hostname, IEnumerable<string> ips)
        {
            var item = new DnsInspectResult
            {
                Target = target,
                CanonicalName = hostname,
                ResolvedIps = ips.ToList(),
                Timestamp = DateTime.Now,
                Status = "Cached"
            };

            RecentQueries.Enqueue(item);
            while (RecentQueries.Count > 100)
            {
                RecentQueries.TryDequeue(out _);
            }
        }
    }
}
