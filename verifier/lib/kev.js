'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/kev.js
//
// CISA Known Exploited Vulnerabilities advisory.
//
// Real feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// Field names were inspected on the real JSON before coding (see docs/SETUP.md):
//   top level: title, catalogVersion, dateReleased, count, vulnerabilities[]
//   entry:     cveID, vendorProject, product, vulnerabilityName, dateAdded,
//              shortDescription, requiredAction, dueDate,
//              knownRansomwareCampaignUse, notes, cwes
//
// We filter vendorProject === "Microsoft" and dateAdded >= the policy's
// last-change date, cache the feed locally, and keep working offline.
//
// ADVISORY ONLY: nothing here maps a CVE to an OS build, and nothing changes
// the policy automatically.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const { readJson, writeJsonAtomic } = require('./store');

const CACHE_MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6 hours
const MAX_ENTRIES = 60;

class KevAdvisory {
  constructor({ cacheFile, url, fetchImpl = fetch, now = () => Date.now() }) {
    this.cacheFile = cacheFile;
    this.url = url;
    this.fetchImpl = fetchImpl;
    this.now = now;
  }

  async loadFeed() {
    const cached = readJson(this.cacheFile, null);
    const cachedAt = cached && cached.fetchedAt ? Date.parse(cached.fetchedAt) : 0;
    const isFresh = cachedAt && this.now() - cachedAt < CACHE_MAX_AGE_MS;

    if (isFresh) {
      return { feed: cached, stale: false, error: null };
    }

    try {
      const res = await this.fetchImpl(this.url, { signal: AbortSignal.timeout(15000) });
      if (!res.ok) throw new Error(`KEV feed returned HTTP ${res.status}`);
      const json = await res.json();
      if (!Array.isArray(json.vulnerabilities)) throw new Error('KEV feed has no vulnerabilities array');
      const feed = {
        fetchedAt: new Date(this.now()).toISOString(),
        catalogVersion: json.catalogVersion || null,
        dateReleased: json.dateReleased || null,
        count: json.count || json.vulnerabilities.length,
        vulnerabilities: json.vulnerabilities,
      };
      writeJsonAtomic(this.cacheFile, feed);
      return { feed, stale: false, error: null };
    } catch (err) {
      if (cached) {
        // Offline: keep serving the cache, and say so on the dashboard.
        return { feed: cached, stale: true, error: err.message };
      }
      throw new Error(`KEV feed unavailable and no local cache exists: ${err.message}`);
    }
  }

  /** Microsoft KEV entries added on/after `sinceIso` (usually policy.updatedAt). */
  async advisory({ sinceIso }) {
    const { feed, stale, error } = await this.loadFeed();
    const sinceDate = sinceIso ? String(sinceIso).slice(0, 10) : null;

    const microsoft = feed.vulnerabilities.filter((v) => v.vendorProject === 'Microsoft');
    const entries = microsoft
      .filter((v) => (sinceDate ? String(v.dateAdded) >= sinceDate : true))
      .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
      .slice(0, MAX_ENTRIES)
      .map((v) => ({
        cveID: v.cveID,
        vulnerabilityName: v.vulnerabilityName,
        product: v.product,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        ransomware: String(v.knownRansomwareCampaignUse).toLowerCase() === 'known',
      }));

    return {
      advisoryOnly: true,
      source: 'CISA KEV',
      sourceUrl: this.url,
      fetchedAt: feed.fetchedAt,
      catalogVersion: feed.catalogVersion,
      dateReleased: feed.dateReleased,
      stale,
      error,
      since: sinceDate,
      microsoftTotal: microsoft.length,
      entries,
      cachePresent: fs.existsSync(this.cacheFile),
    };
  }
}

/**
 * The `since` date for one advisory window.
 *   policy -> when the policy last changed (the default)
 *   30d/90d -> a rolling window counted back from `now`
 * Anything else falls back to the policy window, never to "show everything".
 */
function windowSince(window, policyUpdatedAt, now) {
  if (window === '30d' || window === '90d') {
    const days = window === '30d' ? 30 : 90;
    return new Date(now - days * 24 * 60 * 60 * 1000).toISOString();
  }
  return policyUpdatedAt;
}

module.exports = { KevAdvisory, CACHE_MAX_AGE_MS, windowSince };
