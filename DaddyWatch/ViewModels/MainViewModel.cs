using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DaddyWatch.Models;
using DaddyWatch.Services;

namespace DaddyWatch.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private static readonly System.Windows.Media.SolidColorBrush BrushGreen = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#30D158"));
        private static readonly System.Windows.Media.SolidColorBrush BrushRed = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF453A"));
        private static readonly System.Windows.Media.SolidColorBrush BrushYellow = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FFD60A"));
        private static readonly System.Windows.Media.SolidColorBrush BrushGray = new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#8B949E"));

        private readonly NativeNetworkService _networkService = new();
        private readonly ThreatIntelligenceService _intelService = new();
        private readonly FirewallService _firewallService = new();
        private readonly ReverseDnsService _dnsService = new();
        private readonly NotificationService _notificationService = new();
        private readonly GeoIpService _geoIpService = new();
        private readonly GeoBlockService _geoBlockService = new();

        private readonly DispatcherTimer _scanTimer;
        private readonly Dictionary<string, NetworkConnection> _connectionsByKey = new();

        public ObservableCollection<NetworkConnection> Connections { get; } = new();
        public ICollectionView FilteredConnections { get; }

        public ObservableCollection<ThreatFeed> Feeds { get; } = new();
        public ObservableCollection<ThreatLogEntry> ThreatLogs { get; } = new();
        public ObservableCollection<BlockedFirewallRule> BlockedRules { get; } = new();
        public ObservableCollection<DnsInspectResult> DnsHistory { get; } = new();
        public ObservableCollection<CountryBlockItem> GeoBlockCountries { get; } = new();

        public GeoLocation LocalLocation => _geoIpService.LocalNodeLocation;

        [ObservableProperty]
        private int selectedTabIndex = 0;

        [ObservableProperty]
        private bool isScanning;

        [ObservableProperty]
        private string statusMessage = "Ready";

        [ObservableProperty]
        private string networkHealthStatus = "INITIALIZING";

        [ObservableProperty]
        private System.Windows.Media.SolidColorBrush networkHealthBrush = BrushGray;

        [ObservableProperty]
        private int totalThreatsFound;

        [ObservableProperty]
        private int maliciousDbCount;

        [ObservableProperty]
        private int trustedDbCount;

        [ObservableProperty]
        private int activeConnectionsCount;

        [ObservableProperty]
        private string searchQuery = "";

        [ObservableProperty]
        private string activeFilter = "ALL"; // ALL, THREATS, UNTRUSTED, TRUSTED, LISTENING

        [ObservableProperty]
        private string customFeedUrl = "";

        [ObservableProperty]
        private bool isCustomFeedMalicious = true;

        [ObservableProperty]
        private bool enableToasts = true;

        [ObservableProperty]
        private bool enableAudioAlerts = true;

        [ObservableProperty]
        private bool isCompilingFeeds;

        [ObservableProperty]
        private NetworkConnection? selectedConnection;

        // DNS & Domain Inspector properties
        [ObservableProperty]
        private string dnsInspectTarget = "";

        [ObservableProperty]
        private DnsInspectResult? currentDnsResult;

        [ObservableProperty]
        private bool isDnsInspecting;

        public MainViewModel()
        {
            FilteredConnections = CollectionViewSource.GetDefaultView(Connections);
            FilteredConnections.Filter = FilterConnectionItem;

            foreach (var feed in _intelService.DefaultFeeds)
            {
                Feeds.Add(feed);
            }

            SyncGeoBlockCountries();

            _scanTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _scanTimer.Tick += async (s, e) => await ScanNetworkTickAsync();

            _ = InitializeAsync();
        }

        private void SyncGeoBlockCountries()
        {
            GeoBlockCountries.Clear();
            foreach (var c in _geoBlockService.AllCountries)
            {
                GeoBlockCountries.Add(c);
            }
        }

        private async Task InitializeAsync()
        {
            Log("INFO", "DaddyWatch Engine starting...", "System");

            // Attempt to load cache
            bool loaded = await _intelService.LoadCachedIntelligenceAsync();
            if (loaded)
            {
                UpdateDatabaseCounters();
                Log("SUCCESS", $"Loaded intelligence cache ({MaliciousDbCount:N0} Threats, {TrustedDbCount:N0} Safe).", "Engine");
            }
            else
            {
                Log("INFO", "No local cache found. Compiling default feeds in background...", "Engine");
                _ = RefreshFeedsCommand.ExecuteAsync(null);
            }

            StartScanning();
        }

        partial void OnSearchQueryChanged(string value)
        {
            FilteredConnections.Refresh();
        }

        partial void OnActiveFilterChanged(string value)
        {
            FilteredConnections.Refresh();
        }

        partial void OnEnableToastsChanged(bool value)
        {
            _notificationService.IsToastEnabled = value;
        }

        partial void OnEnableAudioAlertsChanged(bool value)
        {
            _notificationService.IsAudioAlertEnabled = value;
        }

        private bool FilterConnectionItem(object obj)
        {
            if (obj is not NetworkConnection conn) return false;

            // 1. Filter by category
            if (ActiveFilter == "THREATS" && conn.Threat != ThreatLevel.Malicious) return false;
            if (ActiveFilter == "UNTRUSTED" && conn.Threat != ThreatLevel.Unknown && conn.Threat != ThreatLevel.Suspicious) return false;
            if (ActiveFilter == "TRUSTED" && conn.Threat != ThreatLevel.Trusted) return false;
            if (ActiveFilter == "LISTENING" && conn.State != "LISTENING") return false;

            // 2. Filter by search query
            if (string.IsNullOrWhiteSpace(SearchQuery)) return true;

            string q = SearchQuery.Trim().ToLowerInvariant();
            return conn.RemoteAddress.ToLowerInvariant().Contains(q) ||
                   conn.LocalAddress.ToLowerInvariant().Contains(q) ||
                   conn.ProcessName.ToLowerInvariant().Contains(q) ||
                   conn.ProcessId.ToString().Contains(q) ||
                   conn.ResolvedHostname.ToLowerInvariant().Contains(q) ||
                   conn.CountryName.ToLowerInvariant().Contains(q) ||
                   conn.CountryCode.ToLowerInvariant().Contains(q) ||
                   conn.LocalPort.ToString().Contains(q) ||
                   conn.RemotePort.ToString().Contains(q) ||
                   conn.ThreatDetails.ToLowerInvariant().Contains(q);
        }

        [RelayCommand]
        public void SetFilter(string filter)
        {
            ActiveFilter = filter;
        }

        [RelayCommand]
        public void ToggleScan()
        {
            if (IsScanning)
            {
                StopScanning();
            }
            else
            {
                StartScanning();
            }
        }

        private void StartScanning()
        {
            IsScanning = true;
            _scanTimer.Start();
            NetworkHealthStatus = "MONITORING ACTIVE";
            NetworkHealthBrush = BrushGreen;
            Log("INFO", "Network monitor scanner started.", "Monitor");
        }

        private void StopScanning()
        {
            IsScanning = false;
            _scanTimer.Stop();
            NetworkHealthStatus = "SCANNER PAUSED";
            NetworkHealthBrush = BrushGray;
            Log("INFO", "Network monitor scanner paused.", "Monitor");
        }

        private async Task ScanNetworkTickAsync()
        {
            if (!IsScanning) return;

            var rawList = await Task.Run(() => _networkService.GetActiveConnections(includeUdp: true));
            var currentKeys = new HashSet<string>();

            bool hasMaliciousNow = false;

            foreach (var item in rawList)
            {
                currentKeys.Add(item.Key);

                // GeoIP Resolution
                var geo = _geoIpService.GetLocationImmediate(item.RemoteAddress);
                item.CountryCode = geo.CountryCode;
                item.CountryName = geo.CountryName;
                item.FlagEmoji = geo.FlagEmoji;
                item.City = geo.City;
                item.Latitude = geo.Latitude;
                item.Longitude = geo.Longitude;

                if (_connectionsByKey.TryGetValue(item.Key, out var existing))
                {
                    // Existing socket: evaluate with hostname if present
                    var (level, details) = _intelService.EvaluateConnection(item.RemoteAddress, existing.ResolvedHostname);

                    // Check GeoBlocking rule
                    if (_geoBlockService.IsCountryBlocked(existing.CountryCode))
                    {
                        level = ThreatLevel.Malicious;
                        details = $"🚨 GEOBLOCKED: Traffic from {existing.FlagEmoji} {existing.CountryName} is disallowed";
                    }

                    existing.State = item.State;
                    existing.Threat = level;
                    existing.ThreatDetails = details;
                    existing.ProcessId = item.ProcessId;
                    existing.ProcessName = item.ProcessName;
                    existing.ProcessPath = item.ProcessPath;
                    existing.CountryCode = item.CountryCode;
                    existing.CountryName = item.CountryName;
                    existing.FlagEmoji = item.FlagEmoji;
                    existing.Latitude = item.Latitude;
                    existing.Longitude = item.Longitude;

                    if (level == ThreatLevel.Malicious)
                    {
                        hasMaliciousNow = true;
                    }
                }
                else
                {
                    // New Connection observed
                    var (level, details) = _intelService.EvaluateConnection(item.RemoteAddress, "");

                    // Check GeoBlocking rule
                    if (_geoBlockService.IsCountryBlocked(item.CountryCode))
                    {
                        level = ThreatLevel.Malicious;
                        details = $"🚨 GEOBLOCKED: Traffic from {item.FlagEmoji} {item.CountryName} is disallowed";
                    }

                    item.Threat = level;
                    item.ThreatDetails = details;

                    if (level == ThreatLevel.Malicious)
                    {
                        hasMaliciousNow = true;
                        TotalThreatsFound++;
                        _notificationService.TriggerThreatAlert(item.RemoteAddress, item.ProcessName, item.ProcessId, details);
                        Log("CRITICAL", $"Malicious traffic detected! IP: {item.RemoteAddress}:{item.RemotePort} ({item.CountryName}) by {item.ProcessName}", item.ProcessName, item.RemoteAddress);
                    }

                    _connectionsByKey[item.Key] = item;
                    Connections.Add(item);

                    // Trigger async reverse DNS lookup for public IPs
                    if (!ThreatIntelligenceService.IsPrivateOrLoopback(item.RemoteAddress) && item.RemoteAddress != "*")
                    {
                        _ = ResolveDnsAsync(item);
                    }
                }
            }

            // Remove closed connections
            var staleKeys = _connectionsByKey.Keys.Where(k => !currentKeys.Contains(k)).ToList();
            foreach (var staleKey in staleKeys)
            {
                var conn = _connectionsByKey[staleKey];
                _connectionsByKey.Remove(staleKey);
                Connections.Remove(conn);
            }

            ActiveConnectionsCount = Connections.Count;

            // Update Header Status Banner
            if (hasMaliciousNow)
            {
                NetworkHealthStatus = "CRITICAL THREAT ACTIVE";
                NetworkHealthBrush = BrushRed;
            }
            else if (Connections.Any(c => c.Threat == ThreatLevel.Suspicious))
            {
                NetworkHealthStatus = "POTENTIAL SUSPICIOUS TRAFFIC";
                NetworkHealthBrush = BrushYellow;
            }
            else
            {
                NetworkHealthStatus = "ALL CONNECTIONS SECURE";
                NetworkHealthBrush = BrushGreen;
            }
        }

        private async Task ResolveDnsAsync(NetworkConnection conn)
        {
            string host = await _dnsService.ResolveHostnameAsync(conn.RemoteAddress);
            if (!string.IsNullOrEmpty(host))
            {
                conn.ResolvedHostname = host;

                // Re-evaluate with newly discovered domain
                var (level, details) = _intelService.EvaluateConnection(conn.RemoteAddress, host);

                if (_geoBlockService.IsCountryBlocked(conn.CountryCode))
                {
                    level = ThreatLevel.Malicious;
                    details = $"🚨 GEOBLOCKED: Traffic from {conn.FlagEmoji} {conn.CountryName} is disallowed";
                }

                conn.Threat = level;
                conn.ThreatDetails = details;

                if (level == ThreatLevel.Malicious)
                {
                    TotalThreatsFound++;
                    _notificationService.TriggerThreatAlert(conn.RemoteAddress, conn.ProcessName, conn.ProcessId, details);
                    Log("CRITICAL", $"Flagged by domain rule! {host} ({conn.RemoteAddress}) by {conn.ProcessName}", conn.ProcessName, conn.RemoteAddress);
                }
            }
        }

        [RelayCommand]
        public void InspectDnsFromConnection()
        {
            if (SelectedConnection == null) return;
            string target = !string.IsNullOrWhiteSpace(SelectedConnection.ResolvedHostname)
                ? SelectedConnection.ResolvedHostname
                : SelectedConnection.RemoteAddress;

            if (string.IsNullOrWhiteSpace(target) || target == "*" || target == "0.0.0.0")
            {
                MessageBox.Show("Selected socket does not have an active external IP or domain to inspect.", "DNS Inspector", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            DnsInspectTarget = target;
            SelectedTabIndex = 1; // Switch to Tab 1: Domain & DNS Inspector
            _ = InspectDomainCommand.ExecuteAsync(null);
        }

        [RelayCommand]
        public void BlockSelectedCountry()
        {
            if (SelectedConnection == null || string.IsNullOrWhiteSpace(SelectedConnection.CountryCode) || SelectedConnection.CountryCode == "??" || SelectedConnection.CountryCode == "LO")
            {
                MessageBox.Show("Cannot geoblock this endpoint (local, wildcard, or unclassified country).", "GeoBlocker", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string code = SelectedConnection.CountryCode;
            string name = SelectedConnection.CountryName;
            string flag = SelectedConnection.FlagEmoji;

            var result = MessageBox.Show(
                $"Are you sure you want to GEOBLOCK all network traffic to/from {flag} {name} ({code})?\nAny active and future connections to this country will be flagged and dropped.",
                "Confirm Country GeoBlock",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                _geoBlockService.SetCountryBlocked(code, true);
                SyncGeoBlockCountries();
                Log("WARNING", $"GeoBlocked entire country: {flag} {name} ({code})", "GeoBlocker");
                MessageBox.Show($"Country {flag} {name} ({code}) is now GeoBlocked.", "GeoBlock Active", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        [RelayCommand]
        public void ToggleCountryBlock(CountryBlockItem item)
        {
            if (item == null) return;
            _geoBlockService.SetCountryBlocked(item.CountryCode, item.IsBlocked);
            Log("INFO", $"GeoBlock rule for {item.FlagEmoji} {item.CountryName}: {(item.IsBlocked ? "BLOCKED" : "ALLOWED")}", "GeoBlocker");
        }

        [RelayCommand]
        public async Task EmergencyLockdownAsync()
        {
            var confirm = MessageBox.Show(
                "⚠️ EMERGENCY SYSTEM LOCKDOWN\n\nThis will immediately terminate all non-system external connections and register Windows Firewall drop rules for all active remote endpoints.\n\nAre you sure you want to isolate the machine now?",
                "EMERGENCY NETWORK LOCKDOWN",
                MessageBoxButton.YesNo,
                MessageBoxImage.Stop);

            if (confirm != MessageBoxResult.Yes) return;

            Log("CRITICAL", "EMERGENCY LOCKDOWN INITIATED! Isolating all external endpoints...", "DefenseEngine");

            int count = 0;
            foreach (var conn in Connections.ToList())
            {
                if (conn.Threat != ThreatLevel.Local && !string.IsNullOrEmpty(conn.RemoteAddress) && conn.RemoteAddress != "*")
                {
                    _ = _firewallService.BlockIpAsync(conn.RemoteAddress);
                    if (conn.ProcessId > 4)
                    {
                        _firewallService.TerminateProcess(conn.ProcessId, out _);
                    }
                    count++;
                }
            }

            SyncBlockedRules();
            MessageBox.Show($"Lockdown active: Isolated {count} remote endpoints in Windows Firewall.", "System Isolated", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        [RelayCommand]
        public async Task RefreshFeedsAsync()
        {
            if (IsCompilingFeeds) return;
            IsCompilingFeeds = true;
            StatusMessage = "Compiling intelligence feeds...";

            Log("INFO", "Beginning parallel threat intelligence compilation...", "Feeds");

            int total = await _intelService.RefreshFeedsAsync(Feeds, (name, msg) =>
            {
                Log("INFO", $"[{name}] {msg}", "FeedManager");
            });

            UpdateDatabaseCounters();
            IsCompilingFeeds = false;
            StatusMessage = $"Compilation complete. {total:N0} records active.";
            Log("SUCCESS", $"Feed database synchronized. Total records: {total:N0}", "Feeds");
        }

        private void UpdateDatabaseCounters()
        {
            MaliciousDbCount = _intelService.MaliciousCount;
            TrustedDbCount = _intelService.TrustedCount;
        }

        [RelayCommand]
        public void AddCustomFeed()
        {
            if (string.IsNullOrWhiteSpace(CustomFeedUrl)) return;

            string url = CustomFeedUrl.Trim();
            var newFeed = new ThreatFeed
            {
                Name = $"Custom Feed ({Feeds.Count + 1})",
                Url = url,
                IsMalicious = IsCustomFeedMalicious,
                IsEnabled = true
            };

            Feeds.Add(newFeed);
            CustomFeedUrl = "";
            Log("INFO", $"Added custom feed: {url}", "Feeds");
            _ = RefreshFeedsCommand.ExecuteAsync(null);
        }

        [RelayCommand]
        public void ImportFile()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import Threat or Allowlist File (TXT or JSON)",
                Filter = "Supported Files (*.txt;*.json)|*.txt;*.json|Text Files (*.txt)|*.txt|JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                CheckFileExists = true
            };

            if (dlg.ShowDialog() == true)
            {
                try
                {
                    string path = dlg.FileName;
                    int count = _intelService.ImportLocalFile(path, IsCustomFeedMalicious, out string feedName);

                    var newFeed = new ThreatFeed
                    {
                        Name = $"File: {feedName}",
                        Url = $"file:///{path.Replace('\\', '/')}",
                        IsMalicious = IsCustomFeedMalicious,
                        IsEnabled = true,
                        EntryCount = count,
                        Status = "Active",
                        LastUpdated = DateTime.Now
                    };

                    Feeds.Add(newFeed);
                    UpdateDatabaseCounters();
                    _ = _intelService.SaveCachedIntelligenceAsync();

                    string category = IsCustomFeedMalicious ? "Malicious Threat Feed" : "Trusted Allowlist";
                    Log("SUCCESS", $"Imported {count:N0} entries from '{feedName}' as {category}.", "FileImport");
                    MessageBox.Show($"Successfully imported {count:N0} IPs/domains from:\n{feedName}\nAdded as {category}.", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    Log("WARNING", $"File import failed: {ex.Message}", "FileImport");
                    MessageBox.Show($"Failed to parse file: {ex.Message}", "Import Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        [RelayCommand]
        public async Task InspectDomainAsync()
        {
            if (string.IsNullOrWhiteSpace(DnsInspectTarget)) return;

            IsDnsInspecting = true;
            try
            {
                string target = DnsInspectTarget.Trim();
                var result = await _dnsService.InspectTargetAsync(target);

                var (domLevel, domDetails) = _intelService.EvaluateDomain(result.CanonicalName);
                ThreatLevel highestLevel = domLevel;
                string combinedDetails = domDetails;

                foreach (var ip in result.ResolvedIps)
                {
                    var (ipLevel, ipDetails) = _intelService.EvaluateConnection(ip, result.CanonicalName);
                    if (ipLevel == ThreatLevel.Malicious)
                    {
                        highestLevel = ThreatLevel.Malicious;
                        combinedDetails = ipDetails;
                        break;
                    }
                    if (ipLevel == ThreatLevel.Trusted && highestLevel != ThreatLevel.Malicious)
                    {
                        highestLevel = ThreatLevel.Trusted;
                        combinedDetails = ipDetails;
                    }
                }

                result.Threat = highestLevel;
                result.ThreatDetails = combinedDetails;
                CurrentDnsResult = result;

                DnsHistory.Insert(0, result);
                if (DnsHistory.Count > 100) DnsHistory.RemoveAt(DnsHistory.Count - 1);

                Log("INFO", $"DNS Inspection: {target} -> {result.IpsFormatted} [{highestLevel}]", "DnsInspector");
            }
            finally
            {
                IsDnsInspecting = false;
            }
        }

        [RelayCommand]
        public async Task BlockAllDnsIpsAsync()
        {
            if (CurrentDnsResult == null || CurrentDnsResult.ResolvedIps.Count == 0)
            {
                MessageBox.Show("No resolved IP addresses to block.", "Block DNS IPs", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            int blocked = 0;
            foreach (var ip in CurrentDnsResult.ResolvedIps)
            {
                var (success, _) = await _firewallService.BlockIpAsync(ip);
                if (success) blocked++;
            }

            SyncBlockedRules();
            MessageBox.Show($"Blocked {blocked} resolved IP(s) in Windows Firewall for {CurrentDnsResult.Target}.", "Firewall Rules Added", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        [RelayCommand]
        public async Task BlockSelectedIpAsync()
        {
            if (SelectedConnection == null || string.IsNullOrEmpty(SelectedConnection.RemoteAddress)) return;

            string ip = SelectedConnection.RemoteAddress;
            var (success, msg) = await _firewallService.BlockIpAsync(ip);

            if (success)
            {
                Log("SUCCESS", msg, SelectedConnection.ProcessName, ip);
                SyncBlockedRules();
                MessageBox.Show(msg, "Windows Firewall Block", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                Log("WARNING", msg, SelectedConnection.ProcessName, ip);
                MessageBox.Show(msg, "Firewall Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        [RelayCommand]
        public async Task UnblockIpAsync(string ip)
        {
            var (success, msg) = await _firewallService.UnblockIpAsync(ip);
            Log(success ? "SUCCESS" : "WARNING", msg, "Firewall", ip);
            SyncBlockedRules();
        }

        private void SyncBlockedRules()
        {
            BlockedRules.Clear();
            foreach (var rule in _firewallService.BlockedRules)
            {
                BlockedRules.Add(rule);
            }
        }

        [RelayCommand]
        public void TerminateSelectedProcess()
        {
            if (SelectedConnection == null) return;

            int pid = SelectedConnection.ProcessId;
            string name = SelectedConnection.ProcessName;

            var result = MessageBox.Show(
                $"Are you sure you want to terminate process '{name}' (PID: {pid})?\nThis will close all sockets and stop the executable immediately.",
                "Confirm Process Termination",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                bool killed = _firewallService.TerminateProcess(pid, out string message);
                Log(killed ? "SUCCESS" : "WARNING", message, name);
                MessageBox.Show(message, "Process Status", MessageBoxButton.OK, killed ? MessageBoxImage.Information : MessageBoxImage.Error);
            }
        }

        private static (bool IsValid, string CleanIp, string Error) GetValidPublicIp(NetworkConnection? conn)
        {
            if (conn == null) return (false, "", "No connection selected.");
            string ip = conn.RemoteAddress?.Trim() ?? "";

            if (string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "::")
            {
                return (false, "", "This connection is a local listening socket (* or 0.0.0.0) waiting for inbound connections, with no external remote IP.");
            }

            if (ThreatIntelligenceService.IsPrivateOrLoopback(ip))
            {
                return (false, ip, $"'{ip}' is a local private network or loopback address. VirusTotal and AbuseIPDB only analyze public internet IP addresses.");
            }

            if (!IPAddress.TryParse(ip, out _))
            {
                return (false, ip, $"'{ip}' is not a valid IP address.");
            }

            return (true, ip, "");
        }

        [RelayCommand]
        public void OpenVirusTotal()
        {
            var (isValid, cleanIp, error) = GetValidPublicIp(SelectedConnection);
            if (!isValid)
            {
                if (!string.IsNullOrEmpty(SelectedConnection?.ResolvedHostname))
                {
                    OpenVirusTotalDomain();
                    return;
                }

                MessageBox.Show(error, "VirusTotal Lookup", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            OpenBrowser($"https://www.virustotal.com/gui/ip-address/{cleanIp}");
        }

        [RelayCommand]
        public void OpenVirusTotalDomain()
        {
            if (SelectedConnection == null || string.IsNullOrWhiteSpace(SelectedConnection.ResolvedHostname))
            {
                MessageBox.Show("No resolved domain/hostname is available for this connection.", "Domain Lookup", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string domain = SelectedConnection.ResolvedHostname.Trim();
            OpenBrowser($"https://www.virustotal.com/gui/domain/{domain}");
        }

        [RelayCommand]
        public void OpenAbuseIpDb()
        {
            var (isValid, cleanIp, error) = GetValidPublicIp(SelectedConnection);
            if (!isValid)
            {
                MessageBox.Show(error, "AbuseIPDB Lookup", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            OpenBrowser($"https://www.abuseipdb.com/check/{cleanIp}");
        }

        [RelayCommand]
        public void OpenIpInfo()
        {
            var (isValid, cleanIp, error) = GetValidPublicIp(SelectedConnection);
            if (!isValid)
            {
                MessageBox.Show(error, "IPInfo Lookup", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            OpenBrowser($"https://ipinfo.io/{cleanIp}");
        }

        [RelayCommand]
        public void OpenFileLocation()
        {
            if (SelectedConnection == null || string.IsNullOrEmpty(SelectedConnection.ProcessPath))
            {
                MessageBox.Show("Executable path is not accessible for this system process.", "Open Location", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                Process.Start("explorer.exe", $"/select,\"{SelectedConnection.ProcessPath}\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open location: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        public void CopySelectedIp()
        {
            if (SelectedConnection != null && !string.IsNullOrEmpty(SelectedConnection.RemoteAddress))
            {
                Clipboard.SetText(SelectedConnection.RemoteAddress);
            }
        }

        [RelayCommand]
        public void CopyHostname()
        {
            if (SelectedConnection != null && !string.IsNullOrEmpty(SelectedConnection.ResolvedHostname))
            {
                Clipboard.SetText(SelectedConnection.ResolvedHostname);
            }
        }

        [RelayCommand]
        public void CopyAllDetails()
        {
            if (SelectedConnection != null)
            {
                string info = $"Process: {SelectedConnection.ProcessName} (PID {SelectedConnection.ProcessId})\n" +
                              $"Country: {SelectedConnection.FlagEmoji} {SelectedConnection.CountryName} ({SelectedConnection.CountryCode})\n" +
                              $"Protocol: {SelectedConnection.Protocol}\n" +
                              $"Local: {SelectedConnection.DisplayLocalEndpoint}\n" +
                              $"Remote: {SelectedConnection.DisplayRemoteEndpoint}\n" +
                              $"Hostname: {SelectedConnection.ResolvedHostname}\n" +
                              $"State: {SelectedConnection.State}\n" +
                              $"Threat: {SelectedConnection.Threat} ({SelectedConnection.ThreatDetails})\n" +
                              $"Path: {SelectedConnection.ProcessPath}";
                Clipboard.SetText(info);
            }
        }

        [RelayCommand]
        public void ClearLogs()
        {
            ThreatLogs.Clear();
        }

        [RelayCommand]
        public void ExportLogsToCsv()
        {
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"DaddyWatch_Audit_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                var sb = new StringBuilder();
                sb.AppendLine("Timestamp,Severity,RemoteEndpoint,Country,Process,Message");

                foreach (var log in ThreatLogs)
                {
                    sb.AppendLine($"\"{log.DateFormatted}\",\"{log.Severity}\",\"{log.RemoteEndpoint}\",\"{log.ProcessInfo}\",\"{log.Message.Replace("\"", "\"\"")}\"");
                }

                File.WriteAllText(path, sb.ToString());
                MessageBox.Show($"Audit logs exported successfully to:\n{path}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Log(string severity, string message, string process = "", string endpoint = "")
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                ThreatLogs.Insert(0, new ThreatLogEntry
                {
                    Timestamp = DateTime.Now,
                    Severity = severity,
                    Message = message,
                    ProcessInfo = process,
                    RemoteEndpoint = endpoint
                });

                if (ThreatLogs.Count > 1000)
                {
                    ThreatLogs.RemoveAt(ThreatLogs.Count - 1);
                }
            });
        }

        private static void OpenBrowser(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open web browser: {ex.Message}", "Browser Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
