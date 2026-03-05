using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace DaddyBlocker
{
    public partial class MainWindow : Window
    {
        private string settingsFile = "settings.txt";
        private Dictionary<string, string> countries = new Dictionary<string, string> {
            {"Afghanistan", "af"}, {"Albania", "al"}, {"Algeria", "dz"}, {"Belarus", "by"}, {"Brazil", "br"}, {"Bulgaria", "bg"}, {"Cambodia", "kh"}, {"China", "cn"}, {"Colombia", "co"}, {"Egypt", "eg"}, {"India", "in"}, {"Indonesia", "id"}, {"Iran", "ir"}, {"Iraq", "iq"}, {"Israel", "il"}, {"Kazakhstan", "kz"}, {"Libya", "ly"}, {"Malaysia", "my"}, {"Mexico", "mx"}, {"Morocco", "ma"}, {"N. Korea", "kp"}, {"Nigeria", "ng"}, {"Pakistan", "pk"}, {"Philippines", "ph"}, {"Romania", "ro"}, {"Russia", "ru"}, {"Serbia", "rs"}, {"Syria", "sy"}, {"Thailand", "th"}, {"Turkey", "tr"}, {"Ukraine", "ua"}, {"UAE", "ae"}, {"Uzbekistan", "uz"}, {"Vietnam", "vn"}, {"Yemen", "ye"}
        };

        public MainWindow()
        {
            InitializeComponent();
            foreach (var country in countries.Keys.OrderBy(k => k)) CountryListBox.Items.Add(country);
            LoadSettings();
        }

        private void Log(string? msg)
        {
            if (string.IsNullOrEmpty(msg)) return;
            Dispatcher.Invoke(() => { LogBox.AppendText($"[{DateTime.Now:HH:mm}] {msg}\n"); LogBox.ScrollToEnd(); });
        }

        private void AddFeed_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag != null)
            {
                string tag = btn.Tag.ToString()!;
                if (!CustomIPBox.Text.Contains(tag)) { CustomIPBox.AppendText(tag + Environment.NewLine); Log($"Added: {btn.Content}"); }
            }
        }

        private void AddAllFeeds_Click(object sender, RoutedEventArgs e)
        {
            string[] feeds = { "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-aa.txt", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" };
            foreach (var f in feeds) if (!CustomIPBox.Text.Contains(f)) CustomIPBox.AppendText(f + Environment.NewLine);
            Log("All high-threat feeds subscribed!");
        }

        private void LightPreset_Click(object sender, RoutedEventArgs e)
        {
            CustomIPBox.Clear(); CountryListBox.UnselectAll();
            CustomIPBox.AppendText("https://feodotracker.abuse.ch/downloads/ipblocklist.txt" + Environment.NewLine);
            CustomIPBox.AppendText("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" + Environment.NewLine);
            Log("LIGHT PRESET Loaded.");
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var lines = CountryListBox.SelectedItems.Cast<string>().ToList();
                lines.Add("---CUSTOM---"); lines.Add(CustomIPBox.Text);
                File.WriteAllLines(settingsFile, lines); Log("Setup Saved!");
            }
            catch { Log("Error saving settings."); }
        }

        private void LoadSettings()
        {
            if (File.Exists(settingsFile))
            {
                var allLines = File.ReadAllLines(settingsFile); bool inCustom = false;
                foreach (var line in allLines)
                {
                    if (line == "---CUSTOM---") { inCustom = true; continue; }
                    if (!inCustom && CountryListBox.Items.Contains(line)) CountryListBox.SelectedItems.Add(line);
                    else if (inCustom) CustomIPBox.AppendText(line + Environment.NewLine);
                }
            }
        }

        private void Preset_Click(object sender, RoutedEventArgs e)
        {
            CountryListBox.UnselectAll();
            if (sender is Button btn)
            {
                if (btn.Name == "BtnGaming")
                {
                    if (!CustomIPBox.Text.Contains("#WHITELIST_GAMING")) CustomIPBox.AppendText("#WHITELIST_GAMING" + Environment.NewLine);
                    Log("GAMING PRO Mode.");
                }
                else if (btn.Name == "BtnDefault") Select(new[] { "China", "Russia", "N. Korea", "Iran", "Belarus" });
            }
        }

        private void Select(string[] names) { foreach (var n in names) if (CountryListBox.Items.Contains(n)) CountryListBox.SelectedItems.Add(n); }

        private async void Activate_Click(object sender, RoutedEventArgs e)
        {
            Log("Daddy is calibrating (Bypassing Length Limits)...");
            StatusLabel.Text = "Status: PREPARING...";

            var customLines = CustomIPBox.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var urls = customLines.Where(l => l.StartsWith("http")).ToList();
            var codes = CountryListBox.SelectedItems.Cast<string>().Where(n => countries.ContainsKey(n)).Select(n => countries[n]);
            foreach (var c in codes) urls.Add($"http://www.ipdeny.com/ipblocks/data/countries/{c}.zone");

            // 1. High-Speed Parallel Fetch
            var rawData = new ConcurrentBag<string>();
            using (var client = new HttpClient())
            {
                await Task.WhenAll(urls.Select(async url => {
                    try { rawData.Add(await client.GetStringAsync(url)); } catch { }
                }));
            }

            // 2. Save to Temporary File to avoid "Argument Too Long" error
            string tempFile = Path.Combine(Path.GetTempPath(), "daddy_ips.txt");
            File.WriteAllText(tempFile, string.Join("\n", rawData));

            bool whGaming = customLines.Any(l => l.Contains("#WHITELIST_GAMING"));
            bool whComms = customLines.Any(l => l.Contains("#WHITELIST_COMMS"));

            // 3. PowerShell Logic reading from the file
            string psScript = $@"
                $tempFile = '{tempFile.Replace("\\", "\\\\")}'
                $regex = '^\s*\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}(/\d{{1,2}})?\s*$'
                
                # Load and Clean
                $allIPs = Get-Content $tempFile | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ -match $regex }} | Select-Object -Unique

                $safe = @('8.8.8.8', '1.1.1.1')
                if ('{whGaming}' -eq 'True') {{ $safe += @('162.254.192.0/21', '155.133.224.0/19', '185.25.180.0/22', '185.25.182.0/23') }}
                if ('{whComms}' -eq 'True') {{ $safe += @('162.158.0.0/15', '104.16.0.0/12', '13.107.64.0/18') }}

                $final = $allIPs | Where-Object {{ 
                    $ip = $_; $isSafe = $false;
                    foreach($s in $safe) {{ if ($ip.StartsWith($s)) {{ $isSafe = $true; break }} }}
                    -not $isSafe
                }}

                Remove-NetFirewallRule -DisplayName 'DADDY_SHIELD' -ErrorAction SilentlyContinue
                if ($final.Count -gt 0) {{
                    for ($i=0; $i -lt $final.Count; $i+=5000) {{
                        $chunk = $final[$i..([Math]::Min($i + 4999, $final.Count - 1))]
                        New-NetFirewallRule -DisplayName 'DADDY_SHIELD' -Direction Inbound -Action Block -RemoteAddress $chunk
                        New-NetFirewallRule -DisplayName 'DADDY_SHIELD' -Direction Outbound -Action Block -RemoteAddress $chunk
                    }}
                    Write-Output ""SUCCESS: $($final.Count) ranges active.""
                }}
                Remove-Item $tempFile -ErrorAction SilentlyContinue";

            await Task.Run(() => {
                ProcessStartInfo psi = new ProcessStartInfo("powershell.exe", $"-ExecutionPolicy Bypass -Command \"{psScript}\"")
                {
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using (Process? p = Process.Start(psi))
                {
                    while (p != null && !p.StandardOutput.EndOfStream) Log(p.StandardOutput.ReadLine());
                    p?.WaitForExit();
                }
            });

            StatusLabel.Text = "Status: DADDY ACTIVE"; Log("--- Shield Deployed! ---");
        }

        private void StopShield_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(new ProcessStartInfo("powershell.exe", "Remove-NetFirewallRule -DisplayName 'DADDY_SHIELD'") { Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden });
            Log("Shield Reset."); StatusLabel.Text = "Status: Standby";
        }
    }
}