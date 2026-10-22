// check_accounts.js — assets/accounts.js, driven.
//
// What no Go test can see: that the script opens the linked page's content in
// the dialog, leaves modified clicks as links, falls back to following the
// link on every failure, never wedges its triggers, closes every way and
// returns focus to the control that opened it, and narrows the role panel.
//
// The stubs are built here rather than widened into dom.js: this script needs
// a small element tree, a dialog, a fetch and a parser. Every element refuses
// an innerHTML or outerHTML assignment, so any markup assignment fails the
// test. Node's own fetch is removed so the script's window.fetch is the only
// one that can be called.
"use strict";

const path = require("path");
const dom = require("./dom.js");

const scriptPath = path.join(__dirname, "..", "assets", "accounts.js");

const FOCUSABLE_TAGS = { input: true, select: true, textarea: true, button: true };

// matches implements exactly the selectors accounts.js uses; any other
// selector throws, so a script that starts using a new one fails here.
function matches(node, sel) {
  const a = node.attrs;
  switch (sel) {
    case "[data-modal-title]":
    case "[data-modal-body]":
    case "[data-modal-close]":
    case "[data-role-line]":
    case "[data-modal-trigger]":
      return sel.slice(1, -1) in a;
    case ".back":
      return a.class === "back";
    case ".rolepanel":
      return a.class === "rolepanel";
    case "main#content":
      return node.tag === "main" && a.id === "content";
    case "a[data-modal-trigger]":
      return node.tag === "a" && "data-modal-trigger" in a;
    case "input[type=radio][name=role]":
      return node.tag === "input" && a.type === "radio" && a.name === "role";
    case "input[type=radio][name=role]:checked":
      return node.tag === "input" && a.type === "radio" && a.name === "role" && node.checked === true;
    case "input:not([type=hidden]), select, textarea, button":
      return FOCUSABLE_TAGS[node.tag] === true && !(node.tag === "input" && a.type === "hidden");
    default:
      throw new Error("accounts.js used a selector the stub does not know: " + sel);
  }
}

function node(tag, attrs, kids) {
  const n = {
    tag: tag,
    attrs: Object.assign({}, attrs || {}),
    childNodes: [],
    parent: null,
    listeners: {},
    hidden: false,
    textContent: "",
    isConnected: true,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
    },
    addEventListener(name, fn) {
      (this.listeners[name] = this.listeners[name] || []).push(fn);
    },
    matches(sel) {
      return matches(this, sel);
    },
    closest(sel) {
      for (let c = this; c; c = c.parent) {
        if (matches(c, sel)) return c;
      }
      return null;
    },
    contains(other) {
      for (let c = other; c; c = c.parent) {
        if (c === this) return true;
      }
      return false;
    },
    querySelectorAll(sel) {
      const out = [];
      const walk = (parent) => {
        for (const c of parent.childNodes) {
          if (matches(c, sel)) out.push(c);
          walk(c);
        }
      };
      walk(this);
      return out;
    },
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] || null;
    },
    replaceChildren(...kids) {
      for (const c of this.childNodes) c.parent = null;
      this.childNodes = kids;
      for (const c of kids) c.parent = this;
    },
    remove() {
      if (!this.parent) return;
      this.parent.childNodes.splice(this.parent.childNodes.indexOf(this), 1);
      this.parent = null;
    },
    focus() {
      world.focused = this;
    },
    scrollIntoView() {
      world.scrolled.push(this);
    },
  };
  for (const prop of ["innerHTML", "outerHTML"]) {
    Object.defineProperty(n, prop, {
      set() {
        throw new Error("accounts.js assigned markup through " + prop);
      },
    });
  }
  n.replaceChildren(...(kids || []));
  return n;
}

let world = null;

// pageMain is the <main id="content"> a fetched page parses into: a Back link,
// the kind chip and one form, and a state section for the Enable link.
function pageMain(opts) {
  const o = opts || {};
  const radios = ["viewer", "operator", "admin"].map((r) => {
    const radio = node("input", { type: "radio", name: "role", value: r });
    radio.value = r;
    radio.checked = o.checked === r;
    return radio;
  });
  const lines = ["viewer", "operator", "admin"].map((r) => node("div", { class: "roleline", "data-role-line": r }));
  const panel = node("div", { class: "rolepanel" }, lines);
  const section = node("div", { id: "state" }, [node("input", { type: "password" }), node("button", {})]);
  const form = node("form", {}, [
    node("input", { type: "hidden" }),
    node("input", { type: "text" }),
    ...radios,
    panel,
    section,
  ]);
  for (const r of radios) r.form = form;
  world.byId.state = section;
  world.panel = panel;
  world.lines = lines;
  world.firstControl = form.childNodes[1];
  world.sectionControl = section.childNodes[0];
  return node("main", { id: "content" }, [
    node("p", { class: "back" }),
    node("p", { class: "accthead" }),
    form,
  ]);
}

// setup builds a fresh world and loads the real script into it.
function setup(opts) {
  const o = opts || {};
  delete global.fetch;
  delete global.DOMParser;
  require.cache[require.resolve(scriptPath)] && delete require.cache[require.resolve(scriptPath)];

  world = {
    focused: null,
    scrolled: [],
    byId: {},
    fetches: [],
    assigned: [],
    showModals: 0,
    timers: [],
    cleared: [],
    windowListeners: {},
    documentListeners: {},
    mainOpts: o.mainOpts,
    noMain: false,
    fetchImpl: null,
  };

  const title = node("h2", { "data-modal-title": "" });
  const body = node("div", { "data-modal-body": "" });
  const x = node("button", { type: "button", "data-modal-close": "" });
  const cancel = node("button", { type: "button", "data-modal-close": "" });
  const dlg = node("dialog", { id: "acctdlg" }, [
    node("div", {}, [node("div", {}, [title, x]), body, node("div", {}, [cancel])]),
  ]);
  dlg.open = false;
  if (!o.noShowModal) {
    dlg.showModal = function () {
      world.showModals++;
      this.open = true;
    };
  }
  dlg.close = function () {
    if (!this.open) return;
    this.open = false;
    for (const fn of this.listeners.close || []) fn({});
  };
  world.byId.acctdlg = dlg;
  world.dlg = dlg;
  world.title = title;
  world.body = body;
  world.x = x;
  world.cancel = cancel;

  const edit = node("a", { href: "/console/accounts/ana", "data-modal-trigger": "", "data-modal-title": "ana" });
  const enable = node("a", { href: "/console/accounts/retired-ci#state", "data-modal-trigger": "", "data-modal-title": "retired-ci" });
  const root = node("div", {}, [edit, enable, dlg]);
  world.edit = edit;
  world.enable = enable;

  global.document = {
    getElementById(id) {
      return world.byId[id] || null;
    },
    addEventListener(name, fn) {
      (world.documentListeners[name] = world.documentListeners[name] || []).push(fn);
    },
  };

  global.window = {
    location: {
      assign(url) {
        world.assigned.push(url);
      },
    },
    addEventListener(name, fn) {
      (world.windowListeners[name] = world.windowListeners[name] || []).push(fn);
    },
    setTimeout(fn, ms) {
      world.timers.push({ fn: fn, ms: ms });
      return world.timers.length;
    },
    clearTimeout(id) {
      world.cleared.push(id);
    },
    AbortController: function () {
      const listeners = [];
      this.signal = {
        aborted: false,
        addEventListener(name, fn) {
          listeners.push(fn);
        },
      };
      this.abort = () => {
        this.signal.aborted = true;
        for (const fn of listeners) fn();
      };
    },
    fetch(url, init) {
      world.fetches.push({ url: url, init: init });
      if (world.fetchImpl) return world.fetchImpl(url, init);
      return Promise.resolve(okResponse());
    },
  };
  if (!o.noDOMParser) {
    global.window.DOMParser = function () {
      this.parseFromString = function () {
        return {
          querySelector(sel) {
            if (sel !== "main#content") throw new Error("unexpected selector on the parsed page: " + sel);
            return world.noMain ? null : pageMain(world.mainOpts);
          },
        };
      };
    };
  }

  require(scriptPath);
  world.root = root;
  return world;
}

function okResponse() {
  return { ok: true, redirected: false, text: () => Promise.resolve("<html>") };
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

// click bubbles a click from target through its ancestors and then the
// document, as the browser does.
function click(target, extra) {
  const e = Object.assign(
    {
      target: target,
      button: 0,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
    },
    extra || {}
  );
  for (let n = target; n; n = n.parent) {
    for (const fn of n.listeners.click || []) fn(e);
  }
  for (const fn of world.documentListeners.click || []) fn(e);
  return e;
}

function pointerdown(target) {
  const e = { target: target };
  for (let n = target; n; n = n.parent) {
    for (const fn of n.listeners.pointerdown || []) fn(e);
  }
}

function change(target) {
  const e = { target: target };
  for (let n = target; n; n = n.parent) {
    for (const fn of n.listeners.change || []) fn(e);
  }
}

async function openEdit() {
  const e = click(world.edit);
  await flush();
  return e;
}

(async function () {
  // a. A plain click opens the page's content in the dialog.
  setup();
  let e = await openEdit();
  dom.check(e.defaultPrevented, "a plain click on an Edit trigger was not taken over");
  dom.check(world.fetches.length === 1, "opening fetched " + world.fetches.length + " times, want 1");
  const f = world.fetches[0];
  dom.check(f.url === "/console/accounts/ana", "fetched " + f.url + ", not the trigger's href");
  dom.check(!("method" in f.init) && !("body" in f.init), "the fetch is not a bare GET: " + JSON.stringify(f.init));
  dom.check(f.init.credentials === "same-origin", "the fetch does not carry same-origin credentials");
  dom.check(f.init.cache === "no-store", "the fetch is not no-store");
  dom.check(world.dlg.open && world.showModals === 1, "the dialog was not opened with showModal");
  dom.check(world.title.textContent === "ana", "the title is " + JSON.stringify(world.title.textContent));
  const kinds = world.body.childNodes.map((c) => c.attrs.class || c.tag);
  dom.check(
    kinds.length === 2 && kinds[0] === "accthead" && kinds[1] === "form",
    "the body holds " + JSON.stringify(kinds) + ", want the page's content without its Back link"
  );
  dom.check(world.focused === world.firstControl, "focus did not move to the first control in the body");
  dom.check(world.assigned.length === 0, "a successful open navigated");

  // b. Modified and non-primary clicks stay links.
  setup();
  e = click(world.edit, { ctrlKey: true });
  dom.check(!e.defaultPrevented, "a ctrl-click was taken over");
  e = click(world.edit, { button: 1 });
  dom.check(!e.defaultPrevented, "a middle-button click was taken over");
  e = click(world.edit, { metaKey: true });
  dom.check(!e.defaultPrevented, "a meta-click was taken over");
  await flush();
  dom.check(world.fetches.length === 0, "a modified click fetched");

  // c. Enable lands on the state section.
  setup();
  click(world.enable);
  await flush();
  dom.check(world.fetches[0].url === "/console/accounts/retired-ci", "the fragment was sent: " + world.fetches[0].url);
  dom.check(world.scrolled.indexOf(world.byId.state) >= 0, "the state section was not scrolled into view");
  dom.check(world.focused === world.sectionControl, "the state section's first control was not focused");

  // d. Every failure follows the link, fragment included.
  const failures = {
    "a rejected fetch": (w) => (w.fetchImpl = () => Promise.reject(new Error("offline"))),
    "a non-2xx response": (w) => (w.fetchImpl = () => Promise.resolve({ ok: false, redirected: false, text: () => Promise.resolve("") })),
    "a redirected response": (w) => (w.fetchImpl = () => Promise.resolve({ ok: true, redirected: true, text: () => Promise.resolve("") })),
    "a page with no content": (w) => (w.noMain = true),
  };
  for (const name of Object.keys(failures)) {
    setup();
    failures[name](world);
    click(world.enable);
    await flush();
    dom.check(
      world.assigned.length === 1 && world.assigned[0] === "/console/accounts/retired-ci#state",
      name + " did not fall back to the original href: " + JSON.stringify(world.assigned)
    );
    dom.check(world.showModals === 0 && !world.dlg.open, name + " still opened the dialog");
  }

  // d2. One open at a time, and a failed one releases the lock.
  setup();
  let rejectFirst;
  world.fetchImpl = () => new Promise((_, reject) => (rejectFirst = reject));
  click(world.edit);
  click(world.edit);
  await flush();
  dom.check(world.fetches.length === 1, "a second click while one was pending fetched again");
  rejectFirst(new Error("offline"));
  await flush();
  dom.check(world.assigned.length === 1, "the failed open did not fall back");
  world.fetchImpl = null;
  click(world.edit);
  await flush();
  dom.check(world.fetches.length === 2 && world.dlg.open, "the triggers stayed dead after a failed open");

  // d3. A fetch that never settles is aborted and falls back.
  setup();
  world.fetchImpl = (url, init) =>
    new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
  click(world.edit);
  await flush();
  dom.check(world.timers.length === 1 && world.timers[0].ms > 0, "no timeout was armed on the fetch");
  dom.check(world.assigned.length === 0, "fell back before the timeout");
  world.timers[0].fn();
  await flush();
  dom.check(world.assigned.length === 1, "a fetch that never settled did not fall back");
  dom.check(world.cleared.length === 1, "the timeout was not cleared");
  world.fetchImpl = null;
  click(world.edit);
  await flush();
  dom.check(world.dlg.open, "the triggers stayed dead after a timed-out open");

  // e. The close button and Cancel close and return focus.
  for (const which of ["x", "cancel"]) {
    setup();
    await openEdit();
    click(world[which]);
    dom.check(!world.dlg.open, "the " + which + " control did not close the dialog");
    dom.check(world.focused === world.edit, "focus did not return to the opener after " + which);
    dom.check(world.body.childNodes.length === 0, "the body kept its content after " + which);
    dom.check(world.title.textContent === "", "the title kept its text after " + which);
  }

  // f. Esc is the native close.
  setup();
  await openEdit();
  world.focused = null;
  world.dlg.close();
  dom.check(world.focused === world.edit, "focus did not return to the opener after Esc");

  // g. A backdrop click closes; a click inside does not.
  setup();
  await openEdit();
  pointerdown(world.body.childNodes[1]);
  click(world.body.childNodes[1]);
  dom.check(world.dlg.open, "a click inside the dialog closed it");
  // A drag that began inside the box and was released on the backdrop.
  pointerdown(world.body.childNodes[1]);
  click(world.dlg);
  dom.check(world.dlg.open, "a drag from inside the box released on the backdrop closed the dialog");
  click(world.dlg);
  dom.check(world.dlg.open, "a click with no press on the backdrop closed the dialog");
  pointerdown(world.dlg);
  click(world.dlg);
  dom.check(!world.dlg.open, "a press and release on the backdrop did not close the dialog");

  // h. The role panel narrows to the selected role.
  setup();
  await openEdit();
  const hidden = () => world.lines.map((l) => l.hidden === true);
  dom.check(hidden().every((h) => !h), "a form with no role selected narrowed the panel");
  const radios = world.body.querySelectorAll("input[type=radio][name=role]");
  change(radios[1]);
  dom.check(JSON.stringify(hidden()) === "[true,false,true]", "operator did not narrow to operator: " + JSON.stringify(hidden()));
  change(radios[2]);
  dom.check(JSON.stringify(hidden()) === "[true,true,false]", "admin did not narrow to admin: " + JSON.stringify(hidden()));
  setup({ mainOpts: { checked: "viewer" } });
  await openEdit();
  dom.check(JSON.stringify(hidden()) === "[false,true,true]", "a preselected role did not narrow on open: " + JSON.stringify(hidden()));

  // i. A page restored from the back/forward cache never shows the dialog.
  setup();
  await openEdit();
  const pageshow = world.windowListeners.pageshow[0];
  pageshow({ persisted: false });
  dom.check(world.dlg.open, "a pageshow that was not a restore closed the dialog");
  pageshow({ persisted: true });
  dom.check(!world.dlg.open && world.body.childNodes.length === 0, "a restored page kept the dialog open");

  // i2. Leaving the page closes the dialog, so a typed password is not
  // in a back/forward-cache snapshot.
  setup();
  await openEdit();
  world.windowListeners.pagehide[0]({ persisted: true });
  dom.check(!world.dlg.open && world.body.childNodes.length === 0, "pagehide left the dialog open");

  // i3. A failure after the dialog is open does not navigate away from it.
  setup();
  world.dlg.showModal = function () {
    this.open = true;
    throw new Error("after open");
  };
  // The throw surfaces as an unhandled rejection of the click's open(); that
  // is the point: it is reported, not turned into a navigation.
  const rejections = [];
  const onRejection = (err) => rejections.push(err);
  process.on("unhandledRejection", onRejection);
  await openEdit();
  await flush();
  process.removeListener("unhandledRejection", onRejection);
  dom.check(rejections.length === 1, "the throw after showModal was swallowed: " + rejections.length);
  dom.check(world.assigned.length === 0, "a throw after showModal followed the link");
  world.dlg.showModal = function () {
    this.open = true;
  };
  click(world.edit);
  await flush();
  dom.check(world.fetches.length === 2, "the triggers stayed dead after a throw past the fetch");

  // j. Without dialog support or a parser nothing is installed.
  for (const opts of [{ noShowModal: true }, { noDOMParser: true }]) {
    setup(opts);
    e = click(world.edit);
    await flush();
    dom.check(!e.defaultPrevented, "a link was taken over where the script cannot open a dialog: " + JSON.stringify(opts));
    dom.check(world.fetches.length === 0, "fetched where the script cannot open a dialog: " + JSON.stringify(opts));
  }

  console.log("OK accounts.js");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
