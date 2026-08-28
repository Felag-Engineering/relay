// check_dayone.js — assets/stream.js + assets/dayone.js, driven.
//
// #422 lifted the transport out of dayone.js into the shell. Nothing in Go can
// see that day one still works afterwards, and "the file still contains the
// word maxAttempts" does not prove it does. This drives the real files.
"use strict";

const path = require("path");
const dom = require("./dom.js");
const assets = path.join(__dirname, "..", "assets");

const panel = dom.makeElement("dayone-watch", {
  "data-events": "/console/events?kinds=enrollment",
  "data-last-event-id": "e-1",
});
const list = dom.makeList();
const empty = { hidden: false };
const template = dom.makeTemplate();

const world = dom.install(
  {
    "dayone-watch": panel,
    "dayone-attempts": list,
    "dayone-empty": empty,
    "dayone-attempt-row": template,
  },
  {}
);

require(path.join(assets, "stream.js"));
require(path.join(assets, "dayone.js"));

dom.check(world.opened.length === 1, "dayone.js did not open a stream");
dom.check(
  world.opened[0] === "/console/events?kinds=enrollment&last_event_id=e-1",
  "day one did not resume from the newest rendered attempt: " + world.opened[0]
);

// --- a rejection is prepended, with the SERVER's words --------------------
world.emit(
  "enrollment",
  "e-2",
  JSON.stringify({ outcome: "rejected", reason: "no such token", token_id: "tok-1", source: "203.0.113.1", at: "now" })
);
dom.check(list.rows.length === 1, "a rejection was not prepended");
dom.check(empty.hidden === true, "the empty-list note was not hidden once an attempt arrived");
const row = list.rows[0];
dom.check(row.written[".areason"] === "no such token", "the refusal reason was not written into the row");
dom.check(row.written[".atok code"] === "tok-1", "the token id was not written into the row");

// --- an acceptance navigates, which is spec 10's "without a reload" -------
world.emit("enrollment", "e-3", JSON.stringify({ outcome: "accepted" }));
dom.check(world.navigatedTo === "/console/", "an accepted enrollment did not move to the fleet view");

// --- a gap reloads the region rather than splicing ------------------------
world.emit("gap", "", JSON.stringify({ text: "the watch fell behind" }));
dom.check(panel.getAttribute("data-live") === "gap", "a gap did not put the panel in its gap state");
dom.check(world.timers.length > 0, "a gap did not schedule the reload");

// --- day one hard-depends on stream.js, and degrades HONESTLY without it --
// Re-require the handler alone, with no RelayLive: it must return silently and
// open nothing, leaving the server-rendered "not connected" state standing.
delete require.cache[require.resolve(path.join(assets, "dayone.js"))];
const before = world.opened.length;
const saved = global.window.RelayLive;
delete global.window.RelayLive;
require(path.join(assets, "dayone.js"));
global.window.RelayLive = saved;
dom.check(world.opened.length === before, "dayone.js opened a stream with no shared transport loaded");

console.log("OK  stream.js + dayone.js: resume, prepend a rejection, navigate on acceptance, reload on gap");
