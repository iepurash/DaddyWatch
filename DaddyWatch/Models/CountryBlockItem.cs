using CommunityToolkit.Mvvm.ComponentModel;

namespace DaddyWatch.Models
{
    public partial class CountryBlockItem : ObservableObject
    {
        public string CountryCode { get; set; } = "";
        public string CountryName { get; set; } = "";
        public string FlagEmoji { get; set; } = "🌐";

        [ObservableProperty]
        private bool isBlocked;
    }
}
