// dom.js — the smallest DOM the Console's asset files actually touch.
//
// This repository ships no JavaScript test runner and adding one is out of
// scope, so the properties of assets/*.js are asserted two ways: against the
// files' TEXT (dayone_test.go), and — here — against their BEHAVIOUR, by
// require()-ing the real files under node with a hand-written stub for the
// handful of DOM calls they make.
//
// It is deliberately not jsdom. A dependency-free stub is what lets these run
// in `make test-relay` on any box that happens to have node, and be skipped
// rather than fail where node is absent. It stubs only what the asset files
// use; anything they start using that is missing here throws, which is the
// failure mode we want.
"use strict";

function makeElement(id, attributes, children) {
  const attrs = Object.assign({}, attributes || {});
  return {
    id: id,
    attrs: attrs,
    children: children || {},
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null;
    },
    setAttribute(name, value) {
      attrs[name] = value;
    },
    querySelector(selector) {
      return this.children[selector] || null;
    },
  };
}

// makeList is the <ul> day one prepends rejection rows into.
function makeList() {
  const rows = [];
  return {
    rows: rows,
    children: rows,
    firstChild: null,
    insertBefore(row) {
      rows.unshift(row);
    },
    removeChild() {
      rows.pop();
    },
    get lastElementChild() {
      return rows[rows.length - 1];
    },
  };
}

// makeTemplate is the <template> day one clones rows from. The clone records
// what textContent was written into it, so a test can assert the row was
// built by setting text and never by assigning markup.
function makeTemplate() {
  return {
    content: {
      firstElementChild: {
        cloneNode() {
          const written = {};
          return {
            written: written,
            querySelector(selector) {
              return {
                set textContent(v) {
                  written[selector] = v;
                },
                get textContent() {
                  return written[selector] || "";
                },
              };
            },
          };
        },
      },
    },
  };
}

// install puts a global window/document/EventSource in place and returns the
// handle a test drives the fake stream through.
function install(elementsById, elementsBySelector) {
  const world = {
    opened: [],
    listeners: {},
    navigatedTo: null,
    reloaded: 0,
    timers: [],
  };

  global.window = {
    setTimeout(fn, ms) {
      world.timers.push({ fn: fn, ms: ms });
      return world.timers.length;
    },
    location: {
      assign(url) {
        world.navigatedTo = url;
      },
      reload() {
        world.reloaded++;
      },
    },
    // The real CSS.escape; a stub that returned its input unchanged would
    // let a test pass while the asset file had dropped the escaping.
    CSS: {
      escape(s) {
        return String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => "\\" + c);
      },
    },
  };

  global.document = {
    getElementById(id) {
      return elementsById[id] || null;
    },
    querySelector(selector) {
      return elementsBySelector[selector] || null;
    },
  };

  global.EventSource = function (url) {
    world.opened.push(url);
    world.closed = false;
    this.close = function () {
      world.closed = true;
    };
    this.addEventListener = function (name, fn) {
      (world.listeners[name] = world.listeners[name] || []).push(fn);
    };
    // onopen and onerror are ASSIGNED rather than registered, so they have to
    // be captured here — and onerror is the whole reconnect path, which is
    // where the resume point is actually load-bearing.
    Object.defineProperty(this, "onerror", {
      set(fn) {
        world.onerror = fn;
      },
    });
    Object.defineProperty(this, "onopen", {
      set(fn) {
        world.onopen = fn;
      },
    });
  };

  // emit delivers one server-sent event to every handler registered for it.
  world.emit = function (name, lastEventId, data) {
    const fns = world.listeners[name] || [];
    if (fns.length === 0) {
      throw new Error("nothing is listening for the event " + JSON.stringify(name));
    }
    for (const fn of fns) {
      fn({ lastEventId: lastEventId, data: data });
    }
  };

  // reconnect drives the real error path: the transport closes, backs off,
  // and re-opens. runTimers is separate because the backoff is scheduled, and
  // a test that called connect() directly would be testing its own idea of
  // the reconnect rather than the file's.
  world.reconnect = function () {
    if (typeof world.onerror !== "function") {
      throw new Error("nothing assigned an onerror handler, so there is no reconnect path to drive");
    }
    world.listeners = {};
    world.onerror();
    world.runTimers();
  };

  world.runTimers = function () {
    const due = world.timers.splice(0, world.timers.length);
    for (const t of due) {
      t.fn();
    }
  };

  return world;
}

function check(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

module.exports = { makeElement, makeList, makeTemplate, install, check };
