using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class ThreatIntelligenceService
    {
        private static readonly HttpClient HttpClientInstance = new()
        {
            Timeout = TimeSpan.FromSeconds(25)
        };

        static ThreatIntelligenceService()
        {
            HttpClientInstance.DefaultRequestHeaders.Add("User-Agent", "DaddyWatch-Security-Suite/2026.1 (Windows NT 10.0; Win64; x64)");
        }

        // Exact IP Lookups: IP -> Feed Name
        private readonly ConcurrentDictionary<string, string> _maliciousIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _trustedIps = new(StringComparer.OrdinalIgnoreCase);

        // CIDR Matchers for subnet ranges (Optimized with Binary Search Intervals)
        private readonly CidrMatcher _maliciousCidrs = new();
        private readonly CidrMatcher _trustedCidrs = new();

        // Domain Matchers (Subdomains & Wildcards)
        private readonly DomainMatcher _maliciousDomains = new();
        private readonly DomainMatcher _trustedDomains = new();

        public int MaliciousCount => _maliciousIps.Count + _maliciousCidrs.Count + _maliciousDomains.Count;
        public int TrustedCount => _trustedIps.Count + _trustedCidrs.Count + _trustedDomains.Count;

        private readonly string _cacheDirectory;
        private readonly string _cacheFilePath;

        public List<ThreatFeed> DefaultFeeds { get; } = new();

        public ThreatIntelligenceService()
        {
            _cacheDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DaddyWatch");
            _cacheFilePath = Path.Combine(_cacheDirectory, "intel_cache.json");

            InitializeDefaultFeeds();
            InitializeBuiltInTrusted();
        }

        private void InitializeBuiltInTrusted()
        {
            // Authoritative Public DNS Resolvers
            var trustedDns = new[]
            {
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
                "94.140.14.14", "94.140.15.15"
            };
            foreach (var ip in trustedDns)
            {
                _trustedIps[ip] = "Authoritative Anycast DNS";
            }

            // Core Trusted Infrastructure Domains
            var trustedDomains = new[]
            {
                "*.microsoft.com", "*.windowsupdate.com", "*.windows.com", "*.live.com",
                "*.azure.com", "*.msftncsi.com", "*.msftconnecttest.com", "*.office.com",
                "*.google.com", "*.googleapis.com", "*.gstatic.com", "*.1e100.net",
                "*.github.com", "*.githubusercontent.com", "*.cloudflare.com", "*.fastly.net",
                "*.apple.com", "*.icloud.com", "*.digicert.com", "*.sectigo.com",
                "*.amazontrust.com", "*.aws.amazon.com", "*.akamai.net", "*.akamaiedge.net"
            };
            foreach (var dom in trustedDomains)
            {
                _trustedDomains.Add(dom, "Verified Core Enterprise Infrastructure");
            }
        }

        private void InitializeDefaultFeeds()
        {
            // === THREAT FEEDS (IPs & DOMAINS) ===
            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "Data-Shield Critical Threat List",
                Url = "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/prod_critical_data-shield_ipv4_blocklist.txt",
                IsMalicious = true,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "IPsum Level 3 Threat Feed",
                Url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                IsMalicious = true,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "FireHOL Level 2 Aggregated Blacklist",
                Url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                IsMalicious = true,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "Romain Marcoux Outgoing Attacks",
                Url = "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-40k.txt",
                IsMalicious = true,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "URLhaus Malware Hostfile (Domains/IPs)",
                Url = "https://urlhaus.abuse.ch/downloads/hostfile/",
                IsMalicious = true,
                IsEnabled = true
            });

            // === TRUSTED ALLOWLISTS (IPs, CIDRs, DOMAINS) ===
            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "Cloudflare Global Edge Ranges",
                Url = "https://www.cloudflare.com/ips-v4",
                IsMalicious = false,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "Google Core Services IP Ranges",
                Url = "https://www.gstatic.com/ipranges/goog.txt",
                IsMalicious = false,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "GitHub Official Infrastructure (Meta API)",
                Url = "https://api.github.com/meta",
                IsMalicious = false,
                IsEnabled = true
            });

            DefaultFeeds.Add(new ThreatFeed
            {
                Name = "Fastly Global CDN IP Ranges",
                Url = "https://api.fastly.com/public-ip-list",
                IsMalicious = false,
                IsEnabled = true
            });
        }

        public async Task<bool> LoadCachedIntelligenceAsync()
        {
            if (!File.Exists(_cacheFilePath)) return false;

            try
            {
                var json = await File.ReadAllTextAsync(_cacheFilePath);
                var cache = JsonSerializer.Deserialize<CacheData>(json);
                if (cache == null) return false;

                _maliciousIps.Clear();
                _trustedIps.Clear();
                _maliciousCidrs.Clear();
                _trustedCidrs.Clear();
                _maliciousDomains.Clear();
                _trustedDomains.Clear();

                InitializeBuiltInTrusted();

                foreach (var item in cache.MaliciousIps) _maliciousIps[item.Key] = item.Value;
                foreach (var item in cache.TrustedIps) _trustedIps[item.Key] = item.Value;
                foreach (var cidr in cache.MaliciousCidrs) _maliciousCidrs.Add(cidr, "Cached");
                foreach (var cidr in cache.TrustedCidrs) _trustedCidrs.Add(cidr, "Cached");
                foreach (var dom in cache.MaliciousDomains) _maliciousDomains.Add(dom, "Cached");
                foreach (var dom in cache.TrustedDomains) _trustedDomains.Add(dom, "Cached");

                _maliciousCidrs.RebuildIndex();
                _trustedCidrs.RebuildIndex();

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task SaveCachedIntelligenceAsync()
        {
            try
            {
                if (!Directory.Exists(_cacheDirectory))
                    Directory.CreateDirectory(_cacheDirectory);

                var cache = new CacheData
                {
                    LastUpdated = DateTime.UtcNow,
                    MaliciousIps = _maliciousIps.ToDictionary(k => k.Key, v => v.Value),
                    TrustedIps = _trustedIps.ToDictionary(k => k.Key, v => v.Value),
                    MaliciousDomains = _maliciousDomains.GetAllExactDomains().Keys.ToList(),
                    TrustedDomains = _trustedDomains.GetAllExactDomains().Keys.ToList()
                };

                var json = JsonSerializer.Serialize(cache, new JsonSerializerOptions { WriteIndented = false });
                await File.WriteAllTextAsync(_cacheFilePath, json);
            }
            catch
            {
                // Cache write failure non-fatal
            }
        }

        public async Task<int> RefreshFeedsAsync(IEnumerable<ThreatFeed> feeds, Action<string, string> onProgress)
        {
            _maliciousIps.Clear();
            _trustedIps.Clear();
            _maliciousCidrs.Clear();
            _trustedCidrs.Clear();
            _maliciousDomains.Clear();
            _trustedDomains.Clear();

            InitializeBuiltInTrusted();

            var enabledFeeds = feeds.Where(f => f.IsEnabled).ToList();
            var tasks = enabledFeeds.Select(feed => ProcessFeedAsync(feed, onProgress)).ToList();

            await Task.WhenAll(tasks);

            _maliciousCidrs.RebuildIndex();
            _trustedCidrs.RebuildIndex();

            await SaveCachedIntelligenceAsync();

            return MaliciousCount + TrustedCount;
        }

        public async Task ProcessFeedAsync(ThreatFeed feed, Action<string, string> onProgress)
        {
            feed.Status = "Loading...";
            onProgress(feed.Name, "Connecting to source...");

            try
            {
                string rawData;
                if (feed.Url.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
                {
                    string localPath = feed.Url.Replace("file:///", "");
                    rawData = await File.ReadAllTextAsync(localPath);
                }
                else
                {
                    rawData = await HttpClientInstance.GetStringAsync(feed.Url);
                }

                feed.Status = "Parsing...";

                int count = ParseIntelligenceData(rawData, feed.Name, feed.IsMalicious);
                feed.EntryCount = count;
                feed.Status = "Active";
                feed.LastUpdated = DateTime.Now;

                onProgress(feed.Name, $"Successfully loaded {count:N0} entries.");
            }
            catch (Exception ex)
            {
                feed.Status = "Error";
                onProgress(feed.Name, $"Failed: {ex.Message}");
            }
        }

        public int ImportLocalFile(string filePath, bool isMalicious, out string feedName)
        {
            feedName = Path.GetFileName(filePath);
            string content = File.ReadAllText(filePath);

            int count = ParseIntelligenceData(content, feedName, isMalicious);
            _maliciousCidrs.RebuildIndex();
            _trustedCidrs.RebuildIndex();

            return count;
        }

        public int ParseIntelligenceData(string text, string feedName, bool isMalicious)
        {
            if (string.IsNullOrWhiteSpace(text)) return 0;

            string trimmed = text.Trim();
            // Check if JSON
            if (trimmed.StartsWith("{") || trimmed.StartsWith("["))
            {
                return ParseJsonData(trimmed, feedName, isMalicious);
            }

            return ParsePlainTextData(trimmed, feedName, isMalicious);
        }

        private int ParseJsonData(string json, string feedName, bool isMalicious)
        {
            int added = 0;
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.ValueKind == JsonValueKind.Array)
                {
                    foreach (var elem in root.EnumerateArray())
                    {
                        if (elem.ValueKind == JsonValueKind.String)
                        {
                            if (IngestToken(elem.GetString() ?? "", feedName, isMalicious))
                                added++;
                        }
                    }
                }
                else if (root.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in root.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in prop.Value.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.String)
                                {
                                    if (IngestToken(item.GetString() ?? "", feedName, isMalicious))
                                        added++;
                                }
                            }
                        }
                        else if (prop.Value.ValueKind == JsonValueKind.String)
                        {
                            if (IngestToken(prop.Name, feedName, isMalicious)) added++;
                            if (IngestToken(prop.Value.GetString() ?? "", feedName, isMalicious)) added++;
                        }
                    }
                }
            }
            catch
            {
                // Fallback to plain text regex if JSON structure is irregular
                return ParsePlainTextData(json, feedName, isMalicious);
            }

            return added;
        }

        private int ParsePlainTextData(string text, string feedName, bool isMalicious)
        {
            int added = 0;
            var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith(';') || line.StartsWith("//"))
                    continue;

                // Strip trailing comments (e.g., "1.2.3.4 # comment")
                int commentIdx = line.IndexOf('#');
                if (commentIdx > 0) line = line[..commentIdx].Trim();

                // Tokenize whitespace (handles "127.0.0.1 badsite.com", "0.0.0.0 badsite.com", or "1.2.3.4\t3")
                var tokens = line.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length == 0) continue;

                if (tokens.Length >= 2 && (tokens[0] == "127.0.0.1" || tokens[0] == "0.0.0.0"))
                {
                    // Hosts file entry: target is tokens[1]
                    if (IngestToken(tokens[1], feedName, isMalicious)) added++;
                }
                else
                {
                    // Primary token
                    if (IngestToken(tokens[0], feedName, isMalicious)) added++;
                }
            }

            return added;
        }

        private bool IngestToken(string token, string feedName, bool isMalicious)
        {
            string clean = token.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(clean) || clean == "localhost" || clean == "broadcasthost") return false;

            // 1. CIDR
            if (clean.Contains('/') && Regex.IsMatch(clean, @"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"))
            {
                if (isMalicious)
                    _maliciousCidrs.Add(clean, feedName);
                else
                    _trustedCidrs.Add(clean, feedName);
                return true;
            }

            // 2. IPv4
            if (IPAddress.TryParse(clean, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (isMalicious)
                    _maliciousIps[clean] = feedName;
                else
                    _trustedIps[clean] = feedName;
                return true;
            }

            // 3. Domain Name
            if (clean.Contains('.') && !clean.Contains('/') && !clean.Contains(':') && clean.Length > 3)
            {
                if (isMalicious)
                    _maliciousDomains.Add(clean, feedName);
                else
                    _trustedDomains.Add(clean, feedName);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Comprehensive multi-layer evaluation: Checks IP, CIDRs, Hostname, and Subdomains
        /// </summary>
        public (ThreatLevel Level, string Details) EvaluateConnection(string ip, string hostname)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "*" || ip == "0.0.0.0" || ip == "::")
                return (ThreatLevel.Unknown, "Listening Socket / No Remote Peer");

            if (IsPrivateOrLoopback(ip))
                return (ThreatLevel.Local, "Internal / Localhost Loopback");

            // --- 1. MALICIOUS IP CHECK ---
            if (_maliciousIps.TryGetValue(ip, out var malIpFeed))
                return (ThreatLevel.Malicious, $"Flagged IP by {malIpFeed}");

            if (_maliciousCidrs.Matches(ip, out var malCidr, out var malCidrFeed))
                return (ThreatLevel.Malicious, $"Subnet {malCidr} in {malCidrFeed}");

            // --- 2. MALICIOUS DOMAIN CHECK ---
            if (!string.IsNullOrWhiteSpace(hostname))
            {
                if (_maliciousDomains.Matches(hostname, out var malDomainRule, out var malDomFeed))
                    return (ThreatLevel.Malicious, $"Malicious Domain '{malDomainRule}' ({malDomFeed})");
            }

            // --- 3. TRUSTED DOMAIN CHECK ---
            if (!string.IsNullOrWhiteSpace(hostname))
            {
                if (_trustedDomains.Matches(hostname, out var safeDomainRule, out var safeDomFeed))
                    return (ThreatLevel.Trusted, $"Verified Service Domain: {safeDomainRule} ({safeDomFeed})");
            }

            // --- 4. TRUSTED IP CHECK ---
            if (_trustedIps.TryGetValue(ip, out var safeIpFeed))
                return (ThreatLevel.Trusted, $"Verified Infrastructure: {safeIpFeed}");

            if (_trustedCidrs.Matches(ip, out var safeCidr, out var safeCidrFeed))
                return (ThreatLevel.Trusted, $"Trusted Subnet: {safeCidr} ({safeCidrFeed})");

            return (ThreatLevel.Unknown, "Uncataloged External Address");
        }

        public (ThreatLevel Level, string Details) EvaluateDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return (ThreatLevel.Unknown, "No domain specified");

            if (_maliciousDomains.Matches(domain, out var malRule, out var malFeed))
                return (ThreatLevel.Malicious, $"Flagged Domain '{malRule}' in {malFeed}");

            if (_trustedDomains.Matches(domain, out var safeRule, out var safeFeed))
                return (ThreatLevel.Trusted, $"Verified Domain '{safeRule}' ({safeFeed})");

            return (ThreatLevel.Unknown, "Uncataloged Domain");
        }

        public static bool IsPrivateOrLoopback(string ipString)
        {
            if (ipString == "127.0.0.1" || ipString == "::1" || ipString == "localhost")
                return true;

            if (!IPAddress.TryParse(ipString, out var ip)) return false;

            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                // 10.0.0.0/8
                if (bytes[0] == 10) return true;
                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                // 127.0.0.0/8
                if (bytes[0] == 127) return true;
                // 169.254.0.0/16 (Link Local)
                if (bytes[0] == 169 && bytes[1] == 254) return true;
                // 0.0.0.0
                if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) return true;
            }

            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
        }

        private class CacheData
        {
            public DateTime LastUpdated { get; set; }
            public Dictionary<string, string> MaliciousIps { get; set; } = new();
            public Dictionary<string, string> TrustedIps { get; set; } = new();
            public List<string> MaliciousCidrs { get; set; } = new();
            public List<string> TrustedCidrs { get; set; } = new();
            public List<string> MaliciousDomains { get; set; } = new();
            public List<string> TrustedDomains { get; set; } = new();
        }
    }
}
