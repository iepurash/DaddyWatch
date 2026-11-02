using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace DaddyWatch.Services
{
    public class SystemTrayService : IDisposable
    {
        private const int WM_USER = 0x0400;
        public const int WM_TRAYICON = WM_USER + 100;

        private const uint NIM_ADD = 0x00000000;
        private const uint NIM_MODIFY = 0x00000001;
        private const uint NIM_DELETE = 0x00000002;

        private const uint NIF_MESSAGE = 0x00000001;
        private const uint NIF_ICON = 0x00000002;
        private const uint NIF_TIP = 0x00000004;

        private const int WM_LBUTTONDBLCLK = 0x0203;
        private const int WM_RBUTTONUP = 0x0205;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct NOTIFYICONDATA
        {
            public int cbSize;
            public IntPtr hWnd;
            public int uID;
            public uint uFlags;
            public int uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szTip;
            public int dwState;
            public int dwStateMask;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szInfo;
            public int uTimeoutOrVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string szInfoTitle;
            public int dwInfoFlags;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern bool Shell_NotifyIcon(uint dwMessage, ref NOTIFYICONDATA lpData);

        [DllImport("user32.dll")]
        private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

        private IntPtr _hwnd;
        private HwndSource? _hwndSource;
        private bool _isCreated;
        private readonly Window _parentWindow;

        public event Action? TrayDoubleClicked;

        public SystemTrayService(Window parentWindow)
        {
            _parentWindow = parentWindow;
        }

        public void Initialize()
        {
            var helper = new WindowInteropHelper(_parentWindow);
            _hwnd = helper.Handle;

            _hwndSource = HwndSource.FromHwnd(_hwnd);
            _hwndSource?.AddHook(WndProc);

            // Use standard shield / application icon
            IntPtr hIcon = LoadIcon(IntPtr.Zero, new IntPtr(32518)); // IDI_SHIELD = 32518

            var nid = new NOTIFYICONDATA
            {
                cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
                hWnd = _hwnd,
                uID = 1001,
                uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage = WM_TRAYICON,
                hIcon = hIcon,
                szTip = "DaddyWatch 2026 - Endpoint Protection"
            };

            _isCreated = Shell_NotifyIcon(NIM_ADD, ref nid);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_TRAYICON)
            {
                int mouseEvent = lParam.ToInt32();
                if (mouseEvent == WM_LBUTTONDBLCLK || mouseEvent == WM_RBUTTONUP)
                {
                    TrayDoubleClicked?.Invoke();
                    handled = true;
                }
            }
            return IntPtr.Zero;
        }

        public void Dispose()
        {
            if (_isCreated && _hwnd != IntPtr.Zero)
            {
                var nid = new NOTIFYICONDATA
                {
                    cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
                    hWnd = _hwnd,
                    uID = 1001
                };
                Shell_NotifyIcon(NIM_DELETE, ref nid);
                _isCreated = false;
            }

            _hwndSource?.RemoveHook(WndProc);
        }
    }
}
