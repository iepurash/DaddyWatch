using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class GeoBlockService
    {
        private readonly HashSet<string> _blockedCodes = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _settingsPath;

        public List<CountryBlockItem> AllCountries { get; } = new();

        public GeoBlockService()
        {
            string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DaddyWatch");
            _settingsPath = Path.Combine(appData, "geoblock_settings.json");

            InitializeCountryCatalog();
            LoadSettings();
        }

        private void InitializeCountryCatalog()
        {
            var presets = new (string Code, string Name)[]
            {
                ("RU", "Russia"),
                ("CN", "China"),
                ("KP", "North Korea"),
                ("IR", "Iran"),
                ("BY", "Belarus"),
                ("SY", "Syria"),
                ("US", "United States"),
                ("DE", "Germany"),
                ("GB", "United Kingdom"),
                ("RO", "Romania"),
                ("FR", "France"),
                ("NL", "Netherlands"),
                ("CH", "Switzerland"),
                ("CA", "Canada"),
                ("JP", "Japan"),
                ("IN", "India"),
                ("BR", "Brazil"),
                ("UA", "Ukraine"),
                ("PL", "Poland"),
                ("IT", "Italy"),
                ("ES", "Spain"),
                ("AU", "Australia"),
                ("SG", "Singapore"),
                ("KR", "South Korea"),
                ("IL", "Israel"),
                ("TR", "Turkey"),
                ("HK", "Hong Kong")
            };

            foreach (var (code, name) in presets)
            {
                AllCountries.Add(new CountryBlockItem
                {
                    CountryCode = code,
                    CountryName = name,
                    FlagEmoji = GeoLocation.CountryCodeToFlagEmoji(code),
                    IsBlocked = false
                });
            }
        }

        public bool IsCountryBlocked(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode) || countryCode == "??" || countryCode == "LO")
                return false;

            lock (_blockedCodes)
            {
                return _blockedCodes.Contains(countryCode);
            }
        }

        public void SetCountryBlocked(string countryCode, bool blocked)
        {
            if (string.IsNullOrEmpty(countryCode)) return;

            lock (_blockedCodes)
            {
                if (blocked) _blockedCodes.Add(countryCode);
                else _blockedCodes.Remove(countryCode);
            }

            var item = AllCountries.FirstOrDefault(c => c.CountryCode.Equals(countryCode, StringComparison.OrdinalIgnoreCase));
            if (item != null) item.IsBlocked = blocked;

            SaveSettings();
        }

        private void LoadSettings()
        {
            if (!File.Exists(_settingsPath)) return;
            try
            {
                string json = File.ReadAllText(_settingsPath);
                var list = JsonSerializer.Deserialize<List<string>>(json);
                if (list != null)
                {
                    lock (_blockedCodes)
                    {
                        _blockedCodes.Clear();
                        foreach (var code in list) _blockedCodes.Add(code);
                    }

                    foreach (var item in AllCountries)
                    {
                        item.IsBlocked = _blockedCodes.Contains(item.CountryCode);
                    }
                }
            }
            catch
            {
                // Non-fatal
            }
        }

        public void SaveSettings()
        {
            try
            {
                string dir = Path.GetDirectoryName(_settingsPath)!;
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                lock (_blockedCodes)
                {
                    string json = JsonSerializer.Serialize(_blockedCodes.ToList(), new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_settingsPath, json);
                }
            }
            catch
            {
                // Non-fatal
            }
        }
    }
}
