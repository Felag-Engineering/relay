// activity.js — the live half of the Console's Activity screen (spec 04, and
// the SSE conventions in spec 11).
//
// It loads beside stream.js, which owns the transport, the resume point and
// the five states of the live region. This file is only the handler.
//
// # It renders NOTHING, and that is the design
//
// Spec 04's fourth acceptance criterion is "live tail and historical query use
// the same renderer". The way to guarantee that is not discipline, it is to
// make a second renderer impossible: this file cannot build an Activity row,
// because the projection it receives carries only a Job id, a transition word
// and a timestamp — not the Selector, the Operation, the principal or the
// outcome counts a row is made of. So it does exactly two things:
//
//   1. a Job already on screen that FINISHES gets one data-jobstate attribute,
//      revealing a sentence the SERVER already rendered into the row. Nothing
//      moves, nothing reflows (foundations rule 6), and the outcome bar does
//      NOT repaint — repainting it would mean re-implementing NewOutcomeBar's
//      minority floor and grow quantisation in JavaScript, which is the second
//      renderer this whole arrangement exists to prevent.
//   2. anything else queues behind the explicit reload control.
//
// The three rules from stream.js hold here: no innerHTML, no display copy, no
// configuration.
(function () {
  "use strict";

  var live = document.querySelector("[data-live-region]");
  if (!live || !window.RelayLive) {
    return;
  }

  var feed = document.querySelector(".feed");

  function onJob(job) {
    if (!job || !job.job_id) {
      return;
    }

    // CSS.escape on a value that ultimately derives from a Job id this Relay
    // issued, but which ARRIVES OVER A NETWORK. A selector built from an
    // unescaped remote string is a selector a remote string can rewrite.
    var row = null;
    if (feed && window.CSS && typeof window.CSS.escape === "function") {
      row = feed.querySelector('.ev[data-job-id="' + window.CSS.escape(job.job_id) + '"]');
    }

    if (row && (job.transition === "completed" || job.transition === "cancelled")) {
      // IN PLACE. Nothing moves.
      row.setAttribute("data-jobstate", job.transition);
      return;
    }

    // A Job that is not on this page — a new one, or one the current filter
    // excludes — is counted, never spliced. The counter is deliberately
    // filter-blind, which the page says beside it in the server's own words.
    window.RelayLive.queue(live, 1);
  }

  window.RelayLive.region(live, { job: onJob });
})();
