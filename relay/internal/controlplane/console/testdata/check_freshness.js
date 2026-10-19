// check_freshness.js — assets/freshness.js, driven.
//
// Argument: a JSON file of {ageMs, text, stale} rows produced by Go's
// renderedAgo, so the script is held to Go's words rather than to a second
// hand-written copy.
"use strict";

const fs = require("fs");
const path = require("path");
const dom = require("./dom.js");
const script = path.join(__dirname, "..", "assets", "freshness.js");

const rows = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

let clock = 1000000;
Date.now = () => clock;
global.fetch = () => { throw new Error("freshness.js made a request"); };
global.XMLHttpRequest = function () { throw new Error("freshness.js made a request"); };

// load runs the script fresh against one <time> and returns what a test needs.
function load(dataAge, initialText) {
  delete require.cache[require.resolve(script)];
  const el = dom.makeElement("t", {
    "data-age": dataAge,
    datetime: "2026-08-25 12:00:00Z",
    title: "2026-08-25 12:00:00Z",
  });
  el.textContent = initialText;
  const writes = [];
  const calls = [];
  const setAttribute = el.setAttribute;
  el.setAttribute = function (name, value) {
    calls.push(name);
    setAttribute.call(el, name, value);
  };
  let text = initialText;
  Object.defineProperty(el, "textContent", {
    get() { return text; },
    set(v) { writes.push(v); text = v; },
  });
  const world = dom.install({}, { "time[data-rendered-age]": el });
  const start = clock;
  require(script);
  return { el, world, start, writes, calls };
}

function untouched(f) {
  dom.check(f.world.reloaded === 0, "the script reloaded the page");
  dom.check(f.world.navigatedTo === null, "the script navigated");
  dom.check(f.world.opened.length === 0, "the script opened a stream");
  dom.check(f.el.getAttribute("datetime") === "2026-08-25 12:00:00Z", "datetime changed");
  dom.check(f.el.getAttribute("title") === "2026-08-25 12:00:00Z", "title changed");
  dom.check(f.el.getAttribute("data-age") !== null, "data-age was removed");
  for (const name of f.calls) {
    dom.check(name === "data-stale", "the script set attribute " + name);
  }
  dom.check(!("aria-live" in f.el.attrs) && !("role" in f.el.attrs), "the script added a live region");
}

// --- the server's text stands until the first tick; one fixed timer ---------
const f = load("0", "rendered just now");
dom.check(f.writes.length === 0, "the script rewrote the text at load");
dom.check(f.world.timers.length === 1 && f.world.timers[0].ms === 5000, "want exactly one 5000 ms timer");

// --- ascending ages, each through one tick; data-stale is never removed -----
const ascending = rows.filter((r) => r.ageMs >= 0).sort((a, b) => a.ageMs - b.ageMs);
for (const r of ascending) {
  clock = f.start + r.ageMs;
  f.world.runTimers();
  dom.check(f.el.textContent === r.text, "at " + r.ageMs + " ms the script says " + JSON.stringify(f.el.textContent) + ", Go says " + JSON.stringify(r.text));
  dom.check((f.el.getAttribute("data-stale") === "yes") === r.stale, "at " + r.ageMs + " ms data-stale disagrees with Go");
  dom.check(f.world.timers.length === 1 && f.world.timers[0].ms === 5000, "the next tick is not a single 5000 ms timer");
}
untouched(f);

// --- the age at render is honoured ------------------------------------------
const g = load("60", "rendered 1 min ago");
g.world.runTimers();
dom.check(g.el.textContent === "rendered 1 min ago", "data-age=60 was not honoured: " + g.el.textContent);
const h = load("300", "rendered 5 min ago, Refresh to re-read");
h.world.runTimers();
dom.check(h.el.getAttribute("data-stale") === "yes", "an already old page was not marked");
untouched(g);
untouched(h);

// --- a clock moved backwards never yields a negative age (fresh load) -------
for (const r of rows.filter((r) => r.ageMs < 0)) {
  const b = load("0", "rendered just now");
  clock = b.start + r.ageMs;
  b.world.runTimers();
  dom.check(b.el.textContent === "rendered just now" && b.el.getAttribute("data-stale") === null, "a backwards clock aged the page");
  untouched(b);
}
// --- no element on the page: nothing scheduled, nothing thrown ---------------
delete require.cache[require.resolve(script)];
const none = dom.install({}, {});
require(script);
dom.check(none.timers.length === 0, "the script scheduled a timer with no element");

console.log("OK");
