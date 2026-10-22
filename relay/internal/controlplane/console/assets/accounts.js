// accounts.js — the Accounts list's modals (11-console-shell.md, "Modals").
//
// New account, Edit and Enable are plain links to their own pages. With this
// file loaded they open that page's content in the list's <dialog> instead.
// The content is fetched with the same GET the link would make and lifted out
// of the response, so the modal holds the page's own forms and cannot drift
// from them. This file only opens and closes the dialog: every act is the
// page's own form submitting as an ordinary navigation, with its CSRF field,
// step-up and confirmation pages untouched. It reads no field value other
// than a checked role radio's, writes none, and authors no display copy.
//
// Anything that goes wrong (no dialog support, a failed or redirected fetch,
// a page without its content) falls back to following the link, so a modal is
// never the only way to an act.
(function () {
  "use strict";

  var FETCH_TIMEOUT_MS = 10000;
  var FOCUSABLE = "input:not([type=hidden]), select, textarea, button";

  var dlg = document.getElementById("acctdlg");
  if (
    !dlg ||
    typeof dlg.showModal !== "function" ||
    typeof window.fetch !== "function" ||
    typeof window.DOMParser !== "function"
  ) {
    return;
  }

  var title = dlg.querySelector("[data-modal-title]");
  var body = dlg.querySelector("[data-modal-body]");
  var closers = dlg.querySelectorAll("[data-modal-close]");
  if (!title || !body) {
    return;
  }

  var opener = null;
  var busy = false;

  function narrow(panel, role) {
    var lines = panel.querySelectorAll("[data-role-line]");
    for (var i = 0; i < lines.length; i++) {
      lines[i].hidden = lines[i].getAttribute("data-role-line") !== role;
    }
  }

  // The role panel describes the selected role and decides nothing; with no
  // role selected all of them stay visible.
  function narrowInjected() {
    var checked = body.querySelector("input[type=radio][name=role]:checked");
    if (!checked || !checked.form) {
      return;
    }
    var panel = checked.form.querySelector(".rolepanel");
    if (panel) {
      narrow(panel, checked.value);
    }
  }

  function focusIn(root) {
    var target = root.querySelector(FOCUSABLE);
    if (target) {
      target.focus();
    }
  }

  // fetchMain returns the linked page's <main>, or null when anything about
  // getting it went wrong. Only the fetch and the parse are guarded: a throw
  // after the dialog is open must not navigate away from it.
  async function fetchMain(path) {
    var timer = null;
    try {
      var init = {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "text/html" },
      };
      // A fetch that never settles must not leave the triggers dead.
      if (typeof window.AbortController === "function") {
        var controller = new window.AbortController();
        init.signal = controller.signal;
        timer = window.setTimeout(function () {
          controller.abort();
        }, FETCH_TIMEOUT_MS);
      }

      var res = await window.fetch(path, init);
      if (!res.ok || res.redirected) {
        return null;
      }
      var text = await res.text();
      var doc = new window.DOMParser().parseFromString(text, "text/html");
      return doc.querySelector("main#content");
    } catch (err) {
      return null;
    } finally {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    }
  }

  async function open(a) {
    if (busy) {
      return;
    }
    busy = true;
    try {
      var href = a.getAttribute("href");
      var hash = href.indexOf("#");
      var path = hash < 0 ? href : href.slice(0, hash);
      var section = hash < 0 ? "" : href.slice(hash + 1);

      var main = await fetchMain(path);
      if (!main) {
        window.location.assign(href);
        return;
      }
      var backs = main.querySelectorAll(".back");
      for (var i = 0; i < backs.length; i++) {
        backs[i].remove();
      }
      body.replaceChildren.apply(body, Array.prototype.slice.call(main.childNodes));
      title.textContent = a.getAttribute("data-modal-title");
      opener = a;
      narrowInjected();
      dlg.showModal();

      var el = section ? document.getElementById(section) : null;
      if (el && body.contains(el)) {
        el.scrollIntoView();
        focusIn(el);
      } else {
        focusIn(body);
      }
    } finally {
      busy = false;
    }
  }

  document.addEventListener("click", function (e) {
    var a = e.target && e.target.closest ? e.target.closest("a[data-modal-trigger]") : null;
    if (!a) {
      return;
    }
    // A modified click asks for a new tab or window: leave it a link.
    if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) {
      return;
    }
    e.preventDefault();
    open(a);
  });

  for (var i = 0; i < closers.length; i++) {
    closers[i].addEventListener("click", function () {
      dlg.close();
    });
  }

  // Only a click on the backdrop targets the dialog itself: the inner box
  // fills it. The press must also have started there, or a drag that began in
  // a field and was released outside would discard what was typed.
  var pressedBackdrop = false;
  dlg.addEventListener("pointerdown", function (e) {
    pressedBackdrop = e.target === dlg;
  });
  dlg.addEventListener("click", function (e) {
    var close = e.target === dlg && pressedBackdrop;
    pressedBackdrop = false;
    if (close) {
      dlg.close();
    }
  });

  // One handler for every way out (Esc, the close button, Cancel, the
  // backdrop, a restored page): nothing typed lingers and focus goes back to
  // the control that opened the dialog.
  dlg.addEventListener("close", function () {
    body.replaceChildren();
    title.textContent = "";
    var from = opener;
    opener = null;
    if (from && from.isConnected) {
      from.focus();
    }
  });

  // Closed on the way out as well as on the way back, so a typed step-up
  // password is not in a back/forward-cache snapshot.
  window.addEventListener("pagehide", function () {
    if (dlg.open) {
      dlg.close();
    }
  });
  window.addEventListener("pageshow", function (e) {
    if (e.persisted && dlg.open) {
      dlg.close();
    }
  });

  dlg.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.matches || !t.matches("input[type=radio][name=role]") || !t.form) {
      return;
    }
    var panel = t.form.querySelector(".rolepanel");
    if (panel) {
      narrow(panel, t.value);
    }
  });
})();
