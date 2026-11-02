using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class GeoIpService
    {
        private static readonly HttpClient Http = new()
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private static readonly ConcurrentDictionary<string, GeoLocation> Cache = new();
        private static readonly SemaphoreSlim ApiSemaphore = new(2, 2);
        private readonly string _cachePath;

        public GeoLocation LocalNodeLocation { get; private set; } = new()
        {
            CountryCode = "US",
            CountryName = "Local Station",
            FlagEmoji = "📍",
            City = "Host Machine",
            Latitude = 38.9072,
            Longitude = -77.0369,
            IsLocal = true
        };

        public GeoIpService()
        {
            string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DaddyWatch");
            _cachePath = Path.Combine(appData, "geoip_cache.json");

            LoadCache();
            _ = ResolveLocalPublicIpAsync();
        }

        private async Task ResolveLocalPublicIpAsync()
        {
            try
            {
                // Find approximate host coordinates for globe home node
                string json = await Http.GetStringAsync("https://ipapi.co/json/");
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("latitude", out var lat) && root.TryGetProperty("longitude", out var lon))
                {
                    string cc = root.TryGetProperty("country_code", out var c) ? c.GetString() ?? "US" : "US";
                    string cn = root.TryGetProperty("country_name", out var n) ? n.GetString() ?? "Local Host" : "Local Host";
                    string city = root.TryGetProperty("city", out var ct) ? ct.GetString() ?? "Home" : "Home";

                    LocalNodeLocation = new GeoLocation
                    {
                        CountryCode = cc,
                        CountryName = cn,
                        FlagEmoji = "📍",
                        City = city,
                        Latitude = lat.GetDouble(),
                        Longitude = lon.GetDouble(),
                        IsLocal = true
                    };
                }
            }
            catch
            {
                // Fallback to default coordinates
            }
        }

        private void LoadCache()
        {
            if (!File.Exists(_cachePath)) return;
            try
            {
                string json = File.ReadAllText(_cachePath);
                var items = JsonSerializer.Deserialize<Dictionary<string, GeoLocation>>(json);
                if (items != null)
                {
                    foreach (var kvp in items) Cache[kvp.Key] = kvp.Value;
                }
            }
            catch
            {
                // Non-fatal
            }
        }

        public async Task SaveCacheAsync()
        {
            try
            {
                string dir = Path.GetDirectoryName(_cachePath)!;
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                string json = JsonSerializer.Serialize(Cache, new JsonSerializerOptions { WriteIndented = false });
                await File.WriteAllTextAsync(_cachePath, json);
            }
            catch
            {
                // Non-fatal
            }
        }

        public GeoLocation GetLocationImmediate(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "*" || ip == "0.0.0.0" || ip == "::")
            {
                return new GeoLocation { CountryCode = "LO", FlagEmoji = "💻", CountryName = "Listening", IsLocal = true };
            }

            if (ThreatIntelligenceService.IsPrivateOrLoopback(ip))
            {
                return new GeoLocation { CountryCode = "LO", FlagEmoji = "🏠", CountryName = "Local Network", IsLocal = true };
            }

            if (Cache.TryGetValue(ip, out var cached))
                return cached;

            // Offline heuristics for well known ranges
            var heuristic = GetOfflineHeuristicLocation(ip);
            if (heuristic != null)
            {
                Cache[ip] = heuristic;
                return heuristic;
            }

            // Return pending placeholder and trigger background fetch
            var pending = new GeoLocation { CountryCode = "??", FlagEmoji = "🌐", CountryName = "Resolving...", Latitude = 0, Longitude = 0 };
            _ = FetchGeoAsync(ip);
            return pending;
        }

        public async Task<GeoLocation> GetLocationAsync(string ip)
        {
            var loc = GetLocationImmediate(ip);
            if (loc.CountryCode != "??") return loc;

            return await FetchGeoAsync(ip);
        }

        private async Task<GeoLocation> FetchGeoAsync(string ip)
        {
            if (Cache.TryGetValue(ip, out var existing) && existing.CountryCode != "??")
                return existing;

            bool acquired = await ApiSemaphore.WaitAsync(200);
            if (!acquired) return GetOfflineHeuristicLocation(ip) ?? new GeoLocation();

            try
            {
                string url = $"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon";
                string json = await Http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("status", out var s) && s.GetString() == "success")
                {
                    string cc = root.GetProperty("countryCode").GetString() ?? "??";
                    string cn = root.GetProperty("country").GetString() ?? "Unknown";
                    string city = root.TryGetProperty("city", out var ct) ? ct.GetString() ?? "" : "";
                    double lat = root.GetProperty("lat").GetDouble();
                    double lon = root.GetProperty("lon").GetDouble();

                    var geo = new GeoLocation
                    {
                        CountryCode = cc,
                        CountryName = cn,
                        FlagEmoji = GeoLocation.CountryCodeToFlagEmoji(cc),
                        City = city,
                        Latitude = lat,
                        Longitude = lon
                    };

                    Cache[ip] = geo;
                    return geo;
                }
            }
            catch
            {
                // Fallback to offline approximation
            }
            finally
            {
                ApiSemaphore.Release();
            }

            var fallback = GetOfflineHeuristicLocation(ip) ?? new GeoLocation
            {
                CountryCode = "US",
                CountryName = "External Network",
                FlagEmoji = "🌐",
                Latitude = 37.0902,
                Longitude = -95.7129
            };
            Cache[ip] = fallback;
            return fallback;
        }

        private static GeoLocation? GetOfflineHeuristicLocation(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return null;

            byte[] b = addr.GetAddressBytes();

            // Cloudflare / Anycast
            if (b[0] == 1 && b[1] == 1 && b[2] == 1)
                return new GeoLocation { CountryCode = "US", CountryName = "Cloudflare Edge", FlagEmoji = "🇺🇸", Latitude = 37.7749, Longitude = -122.4194 };

            // Google Public DNS / Services
            if (b[0] == 8 && b[1] == 8)
                return new GeoLocation { CountryCode = "US", CountryName = "Google Infrastructure", FlagEmoji = "🇺🇸", Latitude = 37.4220, Longitude = -122.0841 };

            // Quad9
            if (b[0] == 9 && b[1] == 9 && b[2] == 9)
                return new GeoLocation { CountryCode = "CH", CountryName = "Quad9 Anycast", FlagEmoji = "🇨🇭", Latitude = 47.3769, Longitude = 8.5417 };

            // Microsoft Azure
            if (b[0] == 20 || b[0] == 40 || (b[0] == 13 && b[1] >= 64 && b[1] <= 107))
                return new GeoLocation { CountryCode = "US", CountryName = "Microsoft Azure", FlagEmoji = "🇺🇸", Latitude = 47.6062, Longitude = -122.3321 };

            // AWS
            if (b[0] == 3 || (b[0] == 52 && b[1] <= 95) || (b[0] == 54 && b[1] <= 240))
                return new GeoLocation { CountryCode = "US", CountryName = "Amazon AWS Cloud", FlagEmoji = "🇺🇸", Latitude = 38.9072, Longitude = -77.0369 };

            // European major blocks (RIPE 185.0.0.0/8, 193.0.0.0/8, 194.0.0.0/8, 195.0.0.0/8)
            if (b[0] == 185 || b[0] == 193 || b[0] == 194 || b[0] == 195)
                return new GeoLocation { CountryCode = "EU", CountryName = "European Region", FlagEmoji = "🇪🇺", Latitude = 50.8503, Longitude = 4.3517 };

            // Asia Pacific blocks (APNIC 103.0.0.0/8, 114.0.0.0/8, 118.0.0.0/8)
            if (b[0] == 103 || b[0] == 114 || b[0] == 118)
                return new GeoLocation { CountryCode = "JP", CountryName = "Asia Pacific", FlagEmoji = "🇯🇵", Latitude = 35.6762, Longitude = 139.6503 };

            return null;
        }
    }
}
