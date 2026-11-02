using System;
using System.Collections.Generic;
using System.Net;

namespace DaddyWatch.Services
{
    public struct CidrInterval : IComparable<CidrInterval>
    {
        public uint StartIp { get; }
        public uint EndIp { get; }
        public string OriginalCidr { get; }
        public string SourceFeed { get; }

        public CidrInterval(uint start, uint end, string cidr, string source)
        {
            StartIp = start;
            EndIp = end;
            OriginalCidr = cidr;
            SourceFeed = source;
        }

        public int CompareTo(CidrInterval other)
        {
            int cmp = StartIp.CompareTo(other.StartIp);
            return cmp != 0 ? cmp : other.EndIp.CompareTo(EndIp); // broader intervals first
        }
    }

    public class CidrMatcher
    {
        private readonly List<CidrInterval> _intervals = new();
        private CidrInterval[] _sortedIntervals = Array.Empty<CidrInterval>();
        private readonly object _lock = new();
        private bool _isDirty = false;

        public void Add(string cidr, string source = "")
        {
            var parts = cidr.Trim().Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip)) return;
            if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32) return;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;

            uint netmask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            uint ipUint = IpToUint(ip);
            uint start = ipUint & netmask;
            uint end = start | ~netmask;

            lock (_lock)
            {
                _intervals.Add(new CidrInterval(start, end, cidr, source));
                _isDirty = true;
            }
        }

        public void RebuildIndex()
        {
            lock (_lock)
            {
                if (!_isDirty) return;
                var copy = new List<CidrInterval>(_intervals);
                copy.Sort();
                _sortedIntervals = copy.ToArray();
                _isDirty = false;
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _intervals.Clear();
                _sortedIntervals = Array.Empty<CidrInterval>();
                _isDirty = false;
            }
        }

        public int Count
        {
            get
            {
                lock (_lock) return _intervals.Count;
            }
        }

        /// <summary>
        /// High-speed binary search lookup: O(log N) instead of O(N)
        /// </summary>
        public bool Matches(string ipString, out string matchedCidr, out string source)
        {
            matchedCidr = "";
            source = "";

            if (!IPAddress.TryParse(ipString, out var ip)) return false;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

            uint ipUint = IpToUint(ip);

            CidrInterval[] intervals;
            lock (_lock)
            {
                if (_isDirty) RebuildIndex();
                intervals = _sortedIntervals;
            }

            if (intervals.Length == 0) return false;

            // Binary search to find candidate intervals
            int low = 0;
            int high = intervals.Length - 1;
            int bestIndex = -1;

            while (low <= high)
            {
                int mid = (low + high) / 2;
                if (intervals[mid].StartIp <= ipUint)
                {
                    bestIndex = mid;
                    low = mid + 1; // look for closest start
                }
                else
                {
                    high = mid - 1;
                }
            }

            // Check candidate and backward search for overlapping wider ranges
            if (bestIndex != -1)
            {
                for (int i = bestIndex; i >= 0; i--)
                {
                    if (intervals[i].StartIp <= ipUint && ipUint <= intervals[i].EndIp)
                    {
                        matchedCidr = intervals[i].OriginalCidr;
                        source = intervals[i].SourceFeed;
                        return true;
                    }
                    // Optimization: if the gap between StartIp and ipUint exceeds max subnet size (e.g. /8 = 16M), stop
                    if (ipUint - intervals[i].StartIp > 0x01000000) break;
                }
            }

            return false;
        }

        public static uint IpToUint(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return 0;
            return ((uint)bytes[0] << 24) |
                   ((uint)bytes[1] << 16) |
                   ((uint)bytes[2] << 8) |
                   (uint)bytes[3];
        }
    }
}
