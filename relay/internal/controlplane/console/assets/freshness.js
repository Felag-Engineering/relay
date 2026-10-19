// freshness.js — advances the words a page uses for its own age (00-foundations.md,
// "How old a page is"; Fleet is the one screen that carries it).
//
// The server renders "rendered 40s ago" inside a <time data-rendered-age> and
// that text is complete with scripts off. This file only keeps it true as the
// tab ages: past five minutes it adds ", Refresh to re-read" and marks the
// element data-stale so CSS can draw it heavier. It is not a refresh: it makes
// no request, reads no data, never navigates or reloads, and touches no
// storage. The one timer rewrites text and nothing else.
//
// Two of the three rules stream.js states hold here:
//
//  1. NO innerHTML, ever. The only write is textContent.
//  3. NO configuration in the script. The age at render is read from the
//     element's own data-age attribute.
//
// DEVIATION, RECORDED: rule 2 (no display copy) is relaxed for this file only.
// The words "rendered", "s / min / hr / day(s) ago" and ", Refresh to re-read"
// live here as well as in Go, because the relative text has to advance with no
// round trip. Go's renderedAgo is the authority; this file mirrors it, and
// TestAssets_FreshnessAdvancesUnderADOM feeds this file Go's own table and
// fails if the two differ.
//
// Age is the server's data-age plus time elapsed on THIS browser's clock since
// the script loaded. The browser's clock is never compared with the page's
// datetime, so a skewed client clock cannot make a fresh page read old.
//
// No aria-live is added: text rewritten every few seconds in a live region
// would be read aloud continuously.
(function () {
  "use strict";

  var el = document.querySelector("time[data-rendered-age]");
  if (!el) {
    return;
  }

  var tickMs = 5000;
  var staleAfterMs = 5 * 60 * 1000;
  var baseMs = Number(el.getAttribute("data-age")) * 1000;
  if (!(baseMs >= 0)) {
    baseMs = 0;
  }
  var loaded = Date.now();

  function words(ms) {
    var s = Math.floor(ms / 1000);
    var text;
    if (s < 1) {
      text = "rendered just now";
    } else if (s < 60) {
      text = "rendered " + s + "s ago";
    } else if (s < 3600) {
      text = "rendered " + Math.floor(s / 60) + " min ago";
    } else if (s < 86400) {
      text = "rendered " + Math.floor(s / 3600) + " hr ago";
    } else {
      var d = Math.floor(s / 86400);
      text = "rendered " + d + (d === 1 ? " day" : " days") + " ago";
    }
    return ms >= staleAfterMs ? text + ", Refresh to re-read" : text;
  }

  function update() {
    var ms = baseMs + Math.max(0, Date.now() - loaded);
    var text = words(ms);
    if (el.textContent !== text) {
      el.textContent = text;
    }
    // A page only ever gets older, so the mark is never removed.
    if (ms >= staleAfterMs) {
      el.setAttribute("data-stale", "yes");
    }
    window.setTimeout(update, tickMs);
  }

  // The server's text is right at load; the first tick is scheduled, not run.
  window.setTimeout(update, tickMs);
})();
