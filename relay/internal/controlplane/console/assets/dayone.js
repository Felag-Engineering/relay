// dayone.js — the live half of the Console's day-one screen (spec 10, and the
// SSE conventions in spec 11).
//
// This is the Console's only client-side behaviour, and it is loaded as an
// external file from this origin because the content security policy admits
// `script-src 'self'` and nothing inline.
//
// Three rules this file must keep:
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
// DEVIATION, RECORDED: spec 11 line 113 says "live but stable" is enforced in
// the shell — incoming events for a region a user is reading queue behind an
// explicit control, built once. This file prepends rejections immediately.
// On day one there is arguably nothing being read yet, so the deviation is
// defensible; but this is the first live region in the product and #422 will
// inherit whatever shape it takes, so the queueing control belongs in the shell
// before a second screen copies this one.
(function () {
  "use strict";

  var panel = document.getElementById("dayone-watch");
  if (!panel || typeof EventSource === "undefined") {
    return;
  }

  var list = document.getElementById("dayone-attempts");
  var empty = document.getElementById("dayone-empty");
  var rowTemplate = document.getElementById("dayone-attempt-row");
  var endpoint = panel.getAttribute("data-events");
  var lastEventID = panel.getAttribute("data-last-event-id") || "";

  // maxRows caps what the page holds; the seam's own retention caps what it
  // can ever send.
  var maxRows = 50;

  // maxAttempts bounds the reconnect loop. It is not a network nicety: an SSE
  // response is ONE request, and a Console session's idle timeout is refreshed
  // per request — so a tab parked on this screen refreshes nothing and the
  // session can expire while the operator is actively watching. The reconnect
  // then follows a redirect to the sign-in page and fails as an ordinary
  // error, indistinguishable from a blip. Without a bound this backs off
  // forever against a login page; with one, the panel ends up in a state that
  // says so.
  var maxAttempts = 6;

  var attempts = 0;
  var source = null;

  function setState(state) {
    panel.setAttribute("data-live", state);
  }

  function streamURL() {
    if (!lastEventID) {
      return endpoint;
    }
    // The separator is computed, not assumed. data-events carries a query
    // string today (?kinds=enrollment) and the next screen's may not.
    var sep = endpoint.indexOf("?") < 0 ? "?" : "&";
    return endpoint + sep + "last_event_id=" + encodeURIComponent(lastEventID);
  }

  function backoff() {
    return Math.min(30000, 1000 * Math.pow(2, attempts)) + Math.floor(Math.random() * 1000);
  }

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

  function onEnrollment(e) {
    lastEventID = e.lastEventId || lastEventID;

    var attempt;
    try {
      attempt = JSON.parse(e.data);
    } catch (err) {
      return;
    }

    // The registry is written inside Enroll, before the daemon opens a
    // Tunnel, so by the time this arrives the fleet view has a Node and no
    // longer renders this screen. That is the "without a reload" criterion.
    if (attempt.outcome === "accepted") {
      window.location.assign("/console/");
      return;
    }
    addRejection(attempt);
  }

  // A gap means continuity that was not real. Reload the region rather than
  // splicing (spec 11): the server re-renders from the seam's retained
  // history, which is the only accurate view available.
  function onGap() {
    if (source) {
      source.close();
    }
    setState("gap");
    window.setTimeout(function () {
      window.location.reload();
    }, 1000);
  }

  function onError() {
    if (source) {
      source.close();
    }
    attempts++;
    if (attempts > maxAttempts) {
      setState("ended");
      return;
    }
    setState("down");
    window.setTimeout(connect, backoff());
  }

  function connect() {
    source = new EventSource(streamURL());
    source.onopen = function () {
      attempts = 0;
      setState("on");
    };
    source.addEventListener("enrollment", onEnrollment);
    source.addEventListener("gap", onGap);
    source.onerror = onError;
  }

  connect();
})();
