// stream.js — the Console shell's ONE live-region client (spec 11).
//
// It is loaded as an external file from this origin because the content
// security policy admits `script-src 'self'` and nothing inline.
//
// This file owns the TRANSPORT: connecting, resuming, backing off, and the
// five states a live region can be in. Screens own their HANDLERS. That split
// exists because day one (#427) shipped the transport inside its own screen
// file and Activity (#422) was about to inherit a copy of it — two copies of a
// reconnect loop is two backoff policies, and the second one is the one nobody
// looks at again (spec 11 line 113: "Build it once").
//
// Three rules this file must keep, inherited verbatim from dayone.js:
//
//  1. NO innerHTML, ever. Rows are built by cloning a <template> the server
//     rendered and setting textContent. A token id derives from a credential a
//     caller supplied and a source is a remote address; the server-rendered
//     rows are escaped by html/template, and the live ones must have the same
//     safety property, not a weaker one.
//  2. NO display copy. Every word on a live region is chosen in Go — the states
//     are sibling elements selected by a data-live attribute, and a rejection's
//     reason arrives already humanised on the stream. This file sets attributes
//     and moves text the server produced.
//  3. NO configuration. The endpoint and the resume point are read from data-
//     attributes, because no inline script means no server-injected variables.
(function () {
  "use strict";

  // maxAttempts bounds the reconnect loop. It is not a network nicety: an SSE
  // response is ONE request, and a Console session's idle timeout is refreshed
  // per request — so a tab parked on a live screen refreshes nothing and the
  // session can expire while the operator is actively watching. The reconnect
  // then follows a redirect to the sign-in page and fails as an ordinary
  // error, indistinguishable from a blip. Without a bound this backs off
  // forever against a login page; with one, the region ends up in a state that
  // says so.
  var maxAttempts = 6;

  // region wires one live region to the stream its data-events names.
  //
  // handlers maps an SSE event name to a function taking the parsed payload.
  // THE HANDLER NEVER SEES THE RAW EVENT and never touches the resume point:
  // this file writes e.lastEventId back BEFORE dispatching, because the resume
  // point is transport state. A screen file that tried to keep it would be
  // assigning a variable it does not have — under "use strict" that throws
  // inside the handler, and the region would silently stop resuming across
  // reconnects while continuing to look healthy.
  function region(el, handlers) {
    if (!el || typeof EventSource === "undefined") {
      return;
    }

    var endpoint = el.getAttribute("data-events");
    if (!endpoint) {
      return;
    }
    var lastEventID = el.getAttribute("data-last-event-id") || "";
    var attempts = 0;
    var source = null;

    function setState(state) {
      el.setAttribute("data-live", state);
    }

    function streamURL() {
      if (!lastEventID) {
        return endpoint;
      }
      // The separator is computed, not assumed. One region's data-events
      // carries a query string (?kinds=enrollment) and another's may not.
      var sep = endpoint.indexOf("?") < 0 ? "?" : "&";
      return endpoint + sep + "last_event_id=" + encodeURIComponent(lastEventID);
    }

    function backoff() {
      return Math.min(30000, 1000 * Math.pow(2, attempts)) + Math.floor(Math.random() * 1000);
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

    function dispatch(name, handler) {
      source.addEventListener(name, function (e) {
        lastEventID = e.lastEventId || lastEventID;
        var payload;
        try {
          payload = JSON.parse(e.data);
        } catch (err) {
          return;
        }
        handler(payload);
      });
    }

    function connect() {
      source = new EventSource(streamURL());
      source.onopen = function () {
        attempts = 0;
        setState("on");
      };
      for (var name in handlers) {
        if (Object.prototype.hasOwnProperty.call(handlers, name)) {
          dispatch(name, handlers[name]);
        }
      }
      source.addEventListener("gap", onGap);
      source.onerror = onError;
    }

    connect();
  }

  // queue is the explicit control spec 11 requires: incoming events for a
  // region someone is reading do not push in, they increment a counter that
  // has to be clicked. The count is a number written into an element the
  // server rendered; the words beside it are the server's.
  function queue(el, n) {
    if (!el) {
      return;
    }
    var counter = el.querySelector("#live-new-count");
    if (!counter) {
      return;
    }
    var current = parseInt(counter.textContent, 10);
    if (isNaN(current)) {
      current = 0;
    }
    counter.textContent = String(current + n);
    el.setAttribute("data-queued", "yes");
  }

  window.RelayLive = { region: region, queue: queue };
})();
