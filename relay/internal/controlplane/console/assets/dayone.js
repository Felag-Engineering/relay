// dayone.js — the live half of the Console's day-one screen (spec 10, and the
// SSE conventions in spec 11).
//
// It loads beside stream.js, which owns the transport: connecting, resuming,
// backing off, and the five states of a live region. This file is only day
// one's handler. When it was written it held a copy of all of that, and #422
// would have shipped a second copy — so the transport moved to the shell
// (spec 11 line 113, "Build it once") and this file kept the three rules it
// enforces:
//
//  1. NO innerHTML, ever. Rows are built by cloning the <template> the server
//     rendered and setting textContent. A token id derives from a credential a
//     caller supplied and a source is a remote address; the server-rendered
//     rows are escaped by html/template, and the live ones must have the same
//     safety property, not a weaker one.
//  2. NO display copy. Every word on this screen is chosen in Go — the states
//     of the watch panel are sibling elements selected by a data-live
//     attribute, and a rejection's reason arrives already humanised on the
//     stream. This file sets attributes and moves text the server produced.
//  3. NO configuration. The endpoint and the resume point are read from data-
//     attributes, because no inline script means no server-injected variables.
//
// DEVIATION, RECORDED: spec 11 line 113 also says incoming events for a region
// a user is reading queue behind an explicit control. This file still PREPENDS
// rejections immediately. That is now a deliberate per-screen choice rather
// than a copy nobody could see: the control exists in the shell and Activity
// uses it, and on day one there is by definition nothing being read yet — the
// screen's whole job is the first attempt arriving.
//
// DEPENDENCY, RECORDED: this screen now needs TWO files to load. If stream.js
// 404s or fails to parse, window.RelayLive is undefined, this file returns
// immediately, and the panel sits at the data-live="down" the SERVER rendered —
// "The live watch is not connected." — with no reconnect behind it. That state
// is honest rather than misleading, which is why it is a note and not a
// guard: the screen degrades to saying it is not watching, which is true.
// TestDayOne_ScriptIsActuallyServed fetches both files so a typo in p.Scripts
// cannot ship that state to a whole fleet with every Go test green.
(function () {
  "use strict";

  var panel = document.getElementById("dayone-watch");
  if (!panel || !window.RelayLive) {
    return;
  }

  var list = document.getElementById("dayone-attempts");
  var empty = document.getElementById("dayone-empty");
  var rowTemplate = document.getElementById("dayone-attempt-row");

  // maxRows caps what the page holds; the seam's own retention caps what it
  // can ever send.
  var maxRows = 50;

  function setText(row, selector, value) {
    var el = row.querySelector(selector);
    if (el) {
      el.textContent = value || "";
    }
  }

  function addRejection(attempt) {
    if (!list || !rowTemplate) {
      return;
    }
    var row = rowTemplate.content.firstElementChild.cloneNode(true);
    setText(row, ".areason", attempt.reason);
    setText(row, ".atok code", attempt.token_id);
    setText(row, ".asrc", attempt.source);
    setText(row, ".awhen", attempt.at);
    list.insertBefore(row, list.firstChild);
    if (empty) {
      empty.hidden = true;
    }
    while (list.children.length > maxRows) {
      list.removeChild(list.lastElementChild);
    }
  }

  // The resume point is stream.js's, not this file's: it writes e.lastEventId
  // back before calling here, so this handler receives the parsed payload and
  // nothing else.
  function onEnrollment(attempt) {
    // The registry is written inside Enroll, before the daemon opens a
    // Tunnel, so by the time this arrives the fleet view has a Node and no
    // longer renders this screen. That is the "without a reload" criterion.
    if (attempt.outcome === "accepted") {
      window.location.assign("/console/");
      return;
    }
    addRejection(attempt);
  }

  window.RelayLive.region(panel, { enrollment: onEnrollment });
})();
