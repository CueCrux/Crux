// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// Unified Shell Console v2 — service worker (ExecPlan unified-shell-console-2026-07-03, M5).
// No-build, vanilla service worker. It gives the console an installable, offline-
// capable app shell WITHOUT ever caching the daemon control plane.
//
// Two jobs, kept deliberately small:
//   1. Precache a fixed, EXACT app-shell set (the shell HTML + its JS modules +
//      icon + manifest) and serve it cache-first with a background refresh
//      (stale-while-revalidate), so a reload works offline.
//   2. NEVER cache /v1/* — the daemon's live control plane. This is a compliance
//      invariant, not an optimisation (see the fetch handler).
'use strict';

// Cache revision. This MUST match the SW_REV constant embedded in shell.html: a
// console.rs marker test AND smoke.cjs assert the two are byte-equal. There is no
// build step to inject a content hash, so the discipline is manual — bump BOTH
// this line and shell.html's copy whenever any app-shell asset changes, and the
// old cache is dropped on the next activate.
const SW_REV = 'ushell-v2-r8';
const CACHE_NAME = 'crux-console-v2::' + SW_REV;

// The EXACT app-shell precache set. Cache-first with background refresh. Keep this
// list in lock-step with the smoke's APP_SHELL assertion — it is the single source
// of truth for what the console caches. NOTE: no /v1/* path appears here, by design.
const APP_SHELL = [
  '/console',
  '/console-v2/api.js',
  '/console-v2/pages.js',
  '/console-v2/render.js',
  '/console-v2/icon.svg',
  '/console-v2/manifest.webmanifest'
];

function isAppShell(pathname) { return APP_SHELL.indexOf(pathname) >= 0; }

// ---- Install: precache the app shell, then take over ASAP. ----------------
self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function (cache) { return cache.addAll(APP_SHELL); })
      .then(function () { return self.skipWaiting(); })
  );
});

// ---- Activate: drop stale console caches, then claim open clients. --------
self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.map(function (key) {
          // Only ever delete OUR versioned caches; leave anything else alone.
          if (key.indexOf('crux-console-v2::') === 0 && key !== CACHE_NAME) {
            return caches.delete(key);
          }
          return null;
        }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

// ---- Fetch handler --------------------------------------------------------
// COMPLIANCE INVARIANT — the daemon control plane (/v1/*) is NEVER cached and
// NEVER served from cache. Receipts, gates, work-state, and version must always
// reflect the live daemon: a stale receipt or gate decision is both a correctness
// bug and an audit-trail (Art. 12) violation. Any request whose path starts with
// /v1/ is handed straight to the network (no Cache match, no Cache.put) by
// returning early WITHOUT calling event.respondWith. Non-GET requests (mutations)
// are bypassed the same way — the console never caches a POST/PUT/DELETE.
self.addEventListener('fetch', function (event) {
  var req = event.request;
  if (req.method !== 'GET') { return; }   // never cache mutations

  var url;
  try { url = new URL(req.url); } catch (e) { return; }
  if (url.origin !== self.location.origin) { return; }   // never touch cross-origin

  // Network-only passthrough for the live control plane — never cached.
  if (url.pathname.startsWith('/v1/')) { return; }

  // Only the app shell is cached. Any other same-origin GET is left to the
  // network (browser default), so nothing outside APP_SHELL ever enters the cache.
  if (!isAppShell(url.pathname)) { return; }

  // Stale-while-revalidate: serve the cached shell immediately (or fall back to
  // the network on a cold cache) and refresh the entry in the background.
  event.respondWith(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.match(req).then(function (cached) {
        var network = fetch(req).then(function (resp) {
          // Only refresh with a good, same-origin ("basic") response; never the
          // control plane (already bypassed above).
          if (resp && resp.ok && resp.type === 'basic' && isAppShell(url.pathname)) {
            cache.put(req, resp.clone());
          }
          return resp;
        }).catch(function () { return cached; });
        return cached || network;
      });
    })
  );
});
