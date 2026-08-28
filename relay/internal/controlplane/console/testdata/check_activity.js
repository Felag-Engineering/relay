// check_activity.js — assets/stream.js + assets/activity.js, driven.
//
// The properties here are the ones no Go test can see and no text search
// proves: that the two files actually WIRE UP, that the resume point moves in
// the transport rather than in the handler (a free variable there would throw
// a ReferenceError under "use strict" and silently stop resuming across
// reconnects), and that the live lane counts without ever building a row.
"use strict";

const path = require("path");
const dom = require("./dom.js");
const assets = path.join(__dirname, "..", "assets");

const counter = { textContent: "0" };
const region = dom.makeElement("live", {
  "data-events": "/console/events?kinds=job",
  "data-last-event-id": "evt-1",
}, { "#live-new-count": counter });

// One dispatch row on the page, and one row for a Job that is not.
const onScreen = dom.makeElement("row", {});
const feed = {
  querySelector(selector) {
    return selector === '.ev[data-job-id="job-here"]' ? onScreen : null;
  },
};

const world = dom.install({}, { "[data-live-region]": region, ".feed": feed });

require(path.join(assets, "stream.js"));
require(path.join(assets, "activity.js"));

// --- the transport connects, and it resumes -------------------------------
dom.check(world.opened.length === 1, "activity.js did not open a stream");
dom.check(
  world.opened[0] === "/console/events?kinds=job&last_event_id=evt-1",
  "the resume point was not carried into the stream URL: " + world.opened[0]
);

// --- a Job already on screen is flipped IN PLACE --------------------------
world.emit("job", "evt-2", JSON.stringify({ job_id: "job-here", transition: "completed" }));
dom.check(
  onScreen.getAttribute("data-jobstate") === "completed",
  "a completing Job on screen was not marked completed in place"
);
dom.check(counter.textContent === "0", "a Job already on screen was counted as a new event");
dom.check(
  region.getAttribute("data-queued") === null,
  "a Job already on screen marked the region as having queued events"
);

// --- a Job that is NOT on screen queues, never splices ---------------------
world.emit("job", "evt-3", JSON.stringify({ job_id: "job-elsewhere", transition: "created" }));
dom.check(counter.textContent === "1", "an off-page Job did not increment the queue counter");
dom.check(region.getAttribute("data-queued") === "yes", "the region was not marked as queued");
dom.check(feed.rows === undefined, "activity.js added something to the feed — it must never render a row");

// --- a malformed payload is survivable, not fatal -------------------------
world.emit("job", "evt-4", "not json at all");
dom.check(counter.textContent === "1", "a malformed frame was counted");

// --- THE RESUME POINT MOVES, AND IT MOVES IN stream.js --------------------
//
// This is the regression that is otherwise invisible in both directions. If
// activity.js assigned lastEventID itself it would be a free variable, and
// under "use strict" that throws INSIDE the handler — the live region stops
// resuming and goes on looking healthy. If stream.js stops writing
// e.lastEventId back, the region reconnects to the ORIGINAL resume point and
// replays every event since the page was rendered, forever.
//
// Only a reconnect can tell either of those apart from working code, so drive
// one: the newest delivered event was evt-4, and that is where the next
// connection must pick up.
world.reconnect();
dom.check(world.opened.length === 2, "the transport did not reconnect after an error");
dom.check(
  world.opened[1] === "/console/events?kinds=job&last_event_id=evt-4",
  "the reconnect did not resume from the newest delivered event: " + world.opened[1]
);
dom.check(
  region.getAttribute("data-live") === "down" || region.getAttribute("data-live") === "on",
  "the region did not report its connection state during the reconnect"
);

console.log("OK  stream.js + activity.js: connect, resume across a reconnect, flip in place, queue off-page, render nothing");
