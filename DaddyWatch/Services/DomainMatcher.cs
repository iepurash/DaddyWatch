using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace DaddyWatch.Services
{
    public class DomainMatcher
    {
        private readonly ConcurrentDictionary<string, string> _exactDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _wildcardSuffixes = new(StringComparer.OrdinalIgnoreCase);

        public int Count => _exactDomains.Count + _wildcardSuffixes.Count;

        public void Add(string domain, string source = "")
        {
            if (string.IsNullOrWhiteSpace(domain)) return;

            string clean = domain.Trim().ToLowerInvariant().TrimEnd('.');
            if (clean.StartsWith("*."))
            {
                clean = clean[2..];
                _wildcardSuffixes[clean] = source;
            }
            else
            {
                _exactDomains[clean] = source;
            }
        }

        public void Clear()
        {
            _exactDomains.Clear();
            _wildcardSuffixes.Clear();
        }

        public bool Matches(string domain, out string matchedRule, out string source)
        {
            matchedRule = "";
            source = "";

            if (string.IsNullOrWhiteSpace(domain)) return false;

            string clean = domain.Trim().ToLowerInvariant().TrimEnd('.');

            // 1. Direct exact match
            if (_exactDomains.TryGetValue(clean, out var feed))
            {
                matchedRule = clean;
                source = feed;
                return true;
            }

            // 2. Direct wildcard suffix match
            if (_wildcardSuffixes.TryGetValue(clean, out var wildFeed))
            {
                matchedRule = $"*.{clean}";
                source = wildFeed;
                return true;
            }

            // 3. Subdomain hierarchy walk: a.b.c.com -> b.c.com -> c.com
            int dotIndex = clean.IndexOf('.');
            while (dotIndex > 0 && dotIndex < clean.Length - 1)
            {
                string parentDomain = clean[(dotIndex + 1)..];

                // Check parent domain in wildcards or exact list
                if (_wildcardSuffixes.TryGetValue(parentDomain, out var parentWildFeed))
                {
                    matchedRule = $"*.{parentDomain}";
                    source = parentWildFeed;
                    return true;
                }

                if (_exactDomains.TryGetValue(parentDomain, out var parentExactFeed))
                {
                    matchedRule = parentDomain;
                    source = parentExactFeed;
                    return true;
                }

                dotIndex = clean.IndexOf('.', dotIndex + 1);
            }

            return false;
        }

        public Dictionary<string, string> GetAllExactDomains() => new(_exactDomains);
        public Dictionary<string, string> GetAllWildcards() => new(_wildcardSuffixes);
    }
}
