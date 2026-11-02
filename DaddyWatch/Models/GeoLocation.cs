using System;

namespace DaddyWatch.Models
{
    public class GeoLocation
    {
        public string CountryCode { get; set; } = "??";
        public string CountryName { get; set; } = "Unknown";
        public string FlagEmoji { get; set; } = "🌐";
        public string City { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public bool IsLocal { get; set; }

        public static string CountryCodeToFlagEmoji(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode) || countryCode.Length != 2)
                return "🌐";

            countryCode = countryCode.ToUpperInvariant();
            if (countryCode == "LO" || countryCode == "LC") return "🏠";

            try
            {
                int firstChar = char.ConvertToUtf32(countryCode, 0) + 0x1F1A5;
                int secondChar = char.ConvertToUtf32(countryCode, 1) + 0x1F1A5;
                return char.ConvertFromUtf32(firstChar) + char.ConvertFromUtf32(secondChar);
            }
            catch
            {
                return "🌐";
            }
        }
    }
}
