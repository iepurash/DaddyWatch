using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DaddyWatch.Models;

namespace DaddyWatch.Services
{
    public class NativeNetworkService
    {
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            UDP_TABLE_CLASS tableClass,
            uint reserved = 0);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        // Process Cache: PID -> (Name, Path, LastChecked)
        private static readonly ConcurrentDictionary<int, (string Name, string Path, DateTime Checked)> ProcessCache = new();

        public static (string Name, string Path) GetProcessInfo(int pid)
        {
            if (pid <= 0) return ("[System Idle Process]", "");
            if (pid == 4) return ("System", "C:\\Windows\\System32\\ntoskrnl.exe");

            var now = DateTime.UtcNow;
            if (ProcessCache.TryGetValue(pid, out var cached) && (now - cached.Checked).TotalSeconds < 30)
            {
                return (cached.Name, cached.Path);
            }

            try
            {
                using var proc = Process.GetProcessById(pid);
                string name = proc.ProcessName;
                string path = "";
                try
                {
                    path = proc.MainModule?.FileName ?? "";
                }
                catch
                {
                    // Access denied for system / elevated processes
                }

                if (!string.IsNullOrEmpty(path))
                {
                    name = Path.GetFileName(path);
                }
                else
                {
                    name = $"{proc.ProcessName}.exe";
                }

                var entry = (name, path, now);
                ProcessCache[pid] = entry;
                return (name, path);
            }
            catch
            {
                var fallback = ($"PID {pid}", "");
                ProcessCache[pid] = (fallback.Item1, fallback.Item2, now);
                return fallback;
            }
        }

        public List<NetworkConnection> GetActiveConnections(bool includeUdp = true)
        {
            var connections = new List<NetworkConnection>();

            try
            {
                GetTcpConnections(connections);
                if (includeUdp)
                {
                    GetUdpEndpoints(connections);
                }
            }
            catch
            {
                // Fallback to standard .NET IPGlobalProperties if native table fails
                GetFallbackConnections(connections);
            }

            return connections;
        }

        private void GetTcpConnections(List<NetworkConnection> list)
        {
            int bufferSize = 0;
            // Get required buffer size
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0) return;

                int rowCount = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4); // skip row count uint32

                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localIp = new IPAddress(row.dwLocalAddr).ToString();
                    var remoteIp = new IPAddress(row.dwRemoteAddr).ToString();
                    int localPort = PortToHostOrder(row.dwLocalPort);
                    int remotePort = PortToHostOrder(row.dwRemotePort);
                    int pid = (int)row.dwOwningPid;
                    var (procName, procPath) = GetProcessInfo(pid);

                    list.Add(new NetworkConnection
                    {
                        Protocol = "TCP",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        State = DecodeTcpState(row.dwState),
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        Timestamp = DateTime.Now
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }

        private void GetUdpEndpoints(List<NetworkConnection> list)
        {
            int bufferSize = 0;
            uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                if (ret != 0) return;

                int rowCount = Marshal.ReadInt32(udpTablePtr);
                IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localIp = new IPAddress(row.dwLocalAddr).ToString();
                    int localPort = PortToHostOrder(row.dwLocalPort);
                    int pid = (int)row.dwOwningPid;
                    var (procName, procPath) = GetProcessInfo(pid);

                    list.Add(new NetworkConnection
                    {
                        Protocol = "UDP",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "LISTENING",
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        Timestamp = DateTime.Now
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
        }

        private void GetFallbackConnections(List<NetworkConnection> list)
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            foreach (var c in connections)
            {
                list.Add(new NetworkConnection
                {
                    Protocol = "TCP",
                    LocalAddress = c.LocalEndPoint.Address.ToString(),
                    LocalPort = c.LocalEndPoint.Port,
                    RemoteAddress = c.RemoteEndPoint.Address.ToString(),
                    RemotePort = c.RemoteEndPoint.Port,
                    State = c.State.ToString().ToUpperInvariant(),
                    ProcessId = 0,
                    ProcessName = "System / Unspecified",
                    Timestamp = DateTime.Now
                });
            }
        }

        private static int PortToHostOrder(uint port)
        {
            return ((int)(port & 0xFF) << 8) | ((int)(port >> 8) & 0xFF);
        }

        private static string DecodeTcpState(uint state) => state switch
        {
            1 => "CLOSED",
            2 => "LISTENING",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT_1",
            7 => "FIN_WAIT_2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN"
        };
    }
}
