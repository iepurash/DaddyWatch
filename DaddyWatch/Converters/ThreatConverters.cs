using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DaddyWatch.Models;

namespace DaddyWatch.Converters
{
    public class ThreatLevelToBrushConverter : IValueConverter
    {
        private static readonly SolidColorBrush MaliciousBrush = new((Color)ColorConverter.ConvertFromString("#FF453A"));
        private static readonly SolidColorBrush SuspiciousBrush = new((Color)ColorConverter.ConvertFromString("#FFD60A"));
        private static readonly SolidColorBrush TrustedBrush = new((Color)ColorConverter.ConvertFromString("#30D158"));
        private static readonly SolidColorBrush LocalBrush = new((Color)ColorConverter.ConvertFromString("#38BDF8"));
        private static readonly SolidColorBrush UnknownBrush = new((Color)ColorConverter.ConvertFromString("#8B949E"));

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ThreatLevel level)
            {
                return level switch
                {
                    ThreatLevel.Malicious => MaliciousBrush,
                    ThreatLevel.Suspicious => SuspiciousBrush,
                    ThreatLevel.Trusted => TrustedBrush,
                    ThreatLevel.Local => LocalBrush,
                    _ => UnknownBrush
                };
            }
            return UnknownBrush;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class ThreatLevelToBackgroundConverter : IValueConverter
    {
        private static readonly SolidColorBrush MaliciousBg = new((Color)ColorConverter.ConvertFromString("#2E1014"));
        private static readonly SolidColorBrush SuspiciousBg = new((Color)ColorConverter.ConvertFromString("#2A240A"));
        private static readonly SolidColorBrush TrustedBg = new((Color)ColorConverter.ConvertFromString("#0F291E"));
        private static readonly SolidColorBrush LocalBg = new((Color)ColorConverter.ConvertFromString("#0C2136"));
        private static readonly SolidColorBrush UnknownBg = new((Color)ColorConverter.ConvertFromString("#1C2128"));

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ThreatLevel level)
            {
                return level switch
                {
                    ThreatLevel.Malicious => MaliciousBg,
                    ThreatLevel.Suspicious => SuspiciousBg,
                    ThreatLevel.Trusted => TrustedBg,
                    ThreatLevel.Local => LocalBg,
                    _ => UnknownBg
                };
            }
            return UnknownBg;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class StateToBrushConverter : IValueConverter
    {
        private static readonly SolidColorBrush Green = new((Color)ColorConverter.ConvertFromString("#30D158"));
        private static readonly SolidColorBrush Orange = new((Color)ColorConverter.ConvertFromString("#FF9F0A"));
        private static readonly SolidColorBrush Gray = new((Color)ColorConverter.ConvertFromString("#8B949E"));

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string state = (value as string)?.ToUpperInvariant() ?? "";
            return state switch
            {
                "ESTABLISHED" => Green,
                "LISTENING" => Orange,
                _ => Gray
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
