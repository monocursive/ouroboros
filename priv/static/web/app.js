// Ouroboros web — the LiveSocket, the two chrome toggles, and nothing else.
//
// No bundler, no module graph: `phoenix.min.js` and `phoenix_live_view.min.js` are the
// prebuilt UMD bundles that ship inside the dependencies, copied here verbatim by the
// `web.assets` mix alias, and they publish `Phoenix` and `LiveView` as globals. This
// file is hand-written and stays small enough to read in one sitting.
(function () {
  "use strict";

  // ------------------------------------------------------------------------------------
  // Storage
  //
  // Every read and every write is guarded. `localStorage` is not merely empty in a private
  // window or a browser set to block site data — the accessor itself throws, and an
  // unguarded read here would take the LiveSocket down with it and leave a dead page. So
  // both halves fail to "no stored preference", which is the state a first visit is in.
  // ------------------------------------------------------------------------------------

  var THEME_KEY = "ouroboros:theme";
  var BELL_KEY = "ouroboros:notify";

  function stored(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  function store(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (error) {
      // A preference that cannot be written is a preference that lasts one page. The
      // control still works; it just will not be remembered, which is strictly better
      // than refusing to switch.
    }
  }

  // ------------------------------------------------------------------------------------
  // Theme
  //
  // The inline head script (`Ouroboros.Web.Layouts.theme_script/0`) has already stamped
  // the stored choice on `<html>` before this file was even fetched — that is what stops
  // the page flashing dark at somebody who chose light. Everything here is the *toggle*:
  // reading back what that script decided, and writing the next choice down.
  //
  // Dark is the default and it is deliberately not written to storage on load. An operator
  // who never touched the control has stated nothing, and an empty key says exactly that.
  // ------------------------------------------------------------------------------------

  var root = document.documentElement;

  function currentTheme() {
    return root.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function paintThemeButtons() {
    var light = currentTheme() === "light";
    var label = light ? "Switch to the dark theme" : "Switch to the light theme";
    var buttons = document.querySelectorAll("[data-ouro-theme]");

    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", light ? "true" : "false");
      buttons[i].setAttribute("aria-label", label);
      buttons[i].setAttribute("title", label);
    }
  }

  function toggleTheme() {
    var next = currentTheme() === "light" ? "dark" : "light";

    // Both themes are written down, dark included. Once a person has *chosen*, the choice
    // is a fact worth keeping — and an absent key would let a future default flip them
    // back to a theme they had already switched away from.
    root.setAttribute("data-theme", next);
    store(THEME_KEY, next);
    paintThemeButtons();
  }

  // ------------------------------------------------------------------------------------
  // Needs-you notifications
  //
  // Off by default and off on every load: enabling this is a person asking the browser for
  // a permission, and a page that restored "on" from storage would be claiming a channel
  // it has not re-checked. The stored value only says "this browser has said yes before",
  // which is what lets the button come back on without asking twice.
  //
  // The server (`Ouroboros.Web.Live.DeckLive`) pushes `needs-you` only for sessions that
  // have just *entered* the needs-you group; this side adds the two rules the server
  // cannot see — whether anybody is looking, and whether this key has already rung.
  // ------------------------------------------------------------------------------------

  var Notifications = window.Notification;

  // `Object.create(null)` rather than `{}`: the keys here are session ids and request ids,
  // and on an ordinary object `rung["constructor"]` and `rung["toString"]` are already
  // truthy — a session whose id happened to be one of those would silently never ring.
  var rung = Object.create(null);

  function bellOn() {
    return stored(BELL_KEY) === "on";
  }

  function paintBellButtons() {
    var on = bellOn();
    var blocked = Notifications && Notifications.permission === "denied";
    var buttons = document.querySelectorAll("[data-ouro-bell]");

    var label = !Notifications
      ? "This browser does not offer notifications"
      : blocked
        ? "Notifications are blocked for this site in your browser"
        : on
          ? "Stop notifying me when a session needs me"
          : "Notify me when a session needs me";

    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
      buttons[i].setAttribute("aria-label", label);
      buttons[i].setAttribute("title", label);

      if (blocked || !Notifications) {
        buttons[i].setAttribute("data-ouro-blocked", "");
      } else {
        buttons[i].removeAttribute("data-ouro-blocked");
      }
    }
  }

  function toggleBell() {
    // Degrade silently: a browser with no Notification API gets a control that says why it
    // cannot do anything, rather than a thrown error or a button that lies.
    if (!Notifications) {
      paintBellButtons();
      return;
    }

    if (bellOn()) {
      store(BELL_KEY, "off");
      paintBellButtons();
      return;
    }

    if (Notifications.permission === "granted") {
      store(BELL_KEY, "on");
      paintBellButtons();
      return;
    }

    // `requestPermission` is a promise in every current browser and took a callback in
    // older ones; both shapes are handled because neither costs anything.
    var answer = Notifications.requestPermission(function (result) {
      settle(result);
    });

    if (answer && typeof answer.then === "function") {
      answer.then(settle, function () {
        paintBellButtons();
      });
    }

    function settle(result) {
      store(BELL_KEY, result === "granted" ? "on" : "off");
      paintBellButtons();
    }
  }

  // One notification per session that has just started needing somebody, and only while
  // nobody is looking at the tab.
  function announce(sessions) {
    if (!Notifications || !bellOn()) return;
    if (Notifications.permission !== "granted") {
      // Permission was revoked under us. Stop claiming the bell is on.
      if (bellOn()) store(BELL_KEY, "off");
      paintBellButtons();
      return;
    }

    // The Page Visibility rule, and it is the whole reason this feature is tolerable: a
    // person reading the deck can already see the needs-you group grow, and an OS banner
    // for something on screen is noise.
    if (!document.hidden) return;

    for (var i = 0; i < sessions.length; i++) {
      var session = sessions[i];
      if (!session || !session.key || rung[session.key]) continue;

      // Remembered for the life of the page rather than for the life of the ask. The
      // server re-pushes everything currently pending after a reconnect, and a repair is
      // not a new request — so a key that has rung once never rings again here.
      rung[session.key] = true;

      try {
        // The tag is the *session*, not the ask. Two approvals landing on one session are
        // two things that must each be checked against `rung`, but one thing to tell
        // somebody about — and a same-tag notification replaces its predecessor rather
        // than stacking a second banner saying the same words.
        var note = new Notifications((session.title || "A session") + " needs you", {
          tag: session.group || session.key
        });

        // Focus the tab and get out of the way. Deliberately not a navigation: the deck
        // this notification came from may well already have the session open, and a page
        // load would tear down a live transcript to draw what was on screen anyway.
        note.onclick = function () {
          window.focus();
          this.close();
        };
      } catch (error) {
        // Some browsers throw on `new Notification` outside a service worker. Nothing
        // else on this page depends on it, so the loop keeps going.
      }
    }
  }

  // One delegated listener rather than a hook per button: these controls are static markup
  // with no server state behind them (see `Ouroboros.Web.Layouts`), so they survive every
  // LiveView patch and there is nothing to mount or destroy.
  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.closest) return;

    if (target.closest("[data-ouro-theme]")) {
      event.preventDefault();
      toggleTheme();
    } else if (target.closest("[data-ouro-bell]")) {
      event.preventDefault();
      toggleBell();
    }
  });

  // Command-search convention without taking a printable slash away from a field. The
  // shortcut is shown on the rail itself, and it applies only while focus is somewhere
  // that is not already editable. LiveView owns the query and the filtering; this tiny
  // browser-side half owns only the focus move, which should never require a round trip.
  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.altKey || event.ctrlKey || event.metaKey) return;

    var active = document.activeElement;
    var editable = active && active.matches && active.matches("input, textarea, select, [contenteditable='true']");
    if (editable) return;

    var search = document.querySelector(".ouro-rail-search input");
    if (!search) return;

    event.preventDefault();
    search.focus();
  });

  window.addEventListener("phx:needs-you", function (event) {
    var detail = event.detail || {};
    announce(detail.sessions || []);
  });

  window.addEventListener("phx:focus-invalid", function (event) {
    var detail = event.detail || {};
    var target = detail.selector && document.querySelector(detail.selector);
    if (target && target.focus) target.focus();
  });

  function paintChrome() {
    paintThemeButtons();
    paintBellButtons();
  }

  // A LiveView navigation between the deck, /new and /machines swaps the body without
  // reloading this file, so the fresh buttons arrive carrying the server's static
  // `aria-pressed="false"`. This is where they are told what is actually true.
  window.addEventListener("phx:page-loading-stop", paintChrome);

  paintChrome();

  var Socket = window.Phoenix && window.Phoenix.Socket;
  var LiveSocket = window.LiveView && window.LiveView.LiveSocket;

  if (!Socket || !LiveSocket) {
    // Nothing to wire. The page is server-rendered and stays correct without a socket;
    // it just will not update. Say so once rather than throwing on every navigation.
    //
    // The two toggles above are already live: they need no socket, and a page that could
    // not live-update is exactly the page a reader might still want in their own theme.
    console.error("ouroboros: phoenix assets did not load; the page will not live-update");
    return;
  }

  var meta = document.querySelector("meta[name='csrf-token']");
  var csrfToken = meta ? meta.getAttribute("content") : null;

  // The transcript grows from the bottom while a turn streams, and a pane that jumped to
  // the newest line while somebody was reading history would be unusable. So it follows
  // only while the reader is already at the bottom, and stops the moment they scroll up —
  // the terminal client's `follow` flag, in a browser.
  //
  // The connection pill needs no hook: LiveView writes `phx-connected` and the three
  // `phx-*-error` classes onto its own root, and the stylesheet reads them.
  var ScrollPin = {
    // Within this many pixels of the bottom still counts as "at the bottom", because a
    // reader who has not deliberately scrolled away should not be stranded by a rounding
    // error or a half-rendered image.
    slack: 48,

    atBottom: function () {
      var el = this.el;
      return el.scrollHeight - el.scrollTop - el.clientHeight <= this.slack;
    },

    mounted: function () {
      this.pinned = true;
      this.el.scrollTop = this.el.scrollHeight;

      this.onScroll = function () {
        this.pinned = this.atBottom();
      }.bind(this);

      this.el.addEventListener("scroll", this.onScroll, { passive: true });
    },

    updated: function () {
      if (this.pinned) {
        this.el.scrollTop = this.el.scrollHeight;
      }
    },

    destroyed: function () {
      this.el.removeEventListener("scroll", this.onScroll);
    }
  };

  // Enter sends, Shift-Enter is a new line, and the box grows a little as it fills.
  //
  // A textarea rather than an input because a message is not a search box, and Enter is
  // bound here rather than through `phx-keydown` because a round trip per keystroke to
  // decide whether a key was a newline would make typing feel like the network.
  //
  // The submit goes through the form so LiveView's own `phx-submit` path runs — including
  // `phx-disable-with`, which is the one-in-flight interlock a person can see. While that
  // class is on the form the key does nothing, so holding Enter cannot queue a second
  // send behind the first.
  var Composer = {
    // Tall enough for a paragraph, short enough that the transcript stays the page.
    maxHeight: 200,

    mounted: function () {
      this.onKeyDown = function (event) {
        if (event.key !== "Enter" || event.shiftKey || event.altKey || event.metaKey) return;
        // An IME composing a character sends Enter to commit it; that Enter is not a send.
        if (event.isComposing || event.keyCode === 229) return;

        var form = this.el.form;
        if (!form || form.classList.contains("phx-submit-loading")) return;
        if (this.el.value.trim() === "") return;

        event.preventDefault();

        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        }
      }.bind(this);

      this.onInput = function () {
        this.autosize();
        this.syncSend();
      }.bind(this);

      this.el.addEventListener("keydown", this.onKeyDown);
      this.el.addEventListener("input", this.onInput);
      this.autosize();
      this.syncSend();
    },
    // The server owns the draft, so a send that cleared it or a refusal that handed it
    // back both land here and the box has to follow.
    updated: function () {
      this.autosize();
      this.syncSend();
    },

    destroyed: function () {
      this.el.removeEventListener("keydown", this.onKeyDown);
      this.el.removeEventListener("input", this.onInput);
    },

    autosize: function () {
      var el = this.el;
      el.style.height = "auto";
      el.style.height = Math.min(el.scrollHeight, this.maxHeight) + "px";
    },

    syncSend: function () {
      var form = this.el.form;
      var button = form && form.querySelector("[data-ouro-send]");
      if (button) button.disabled = this.el.value.trim() === "";
    }
  };

  var Modal = {
    mounted: function () {
      this.previouslyFocused = document.activeElement;
      this.cancelEvent = this.el.getAttribute("data-cancel-event") || "session-action-cancel";
      this.onCancel = function (event) {
        event.preventDefault();
        this.pushEvent(this.cancelEvent, {});
      }.bind(this);

      this.el.addEventListener("cancel", this.onCancel);
      if (!this.el.open) this.el.showModal();

      var target = this.el.querySelector(
        "[autofocus], button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])"
      );
      if (target) target.focus();
    },

    destroyed: function () {
      this.el.removeEventListener("cancel", this.onCancel);
      if (this.previouslyFocused && this.previouslyFocused.isConnected) {
        this.previouslyFocused.focus();
      }
    }
  };

  var FocusInvalid = {
    mounted: function () {
      this.focusIfInvalid();
    },

    updated: function () {
      this.focusIfInvalid();
    },

    focusIfInvalid: function () {
      if (this.el.getAttribute("aria-invalid") === "true") this.el.focus();
    }
  };

  var liveSocket = new LiveSocket("/live", Socket, {
    params: { _csrf_token: csrfToken },
    hooks: { ScrollPin: ScrollPin, Composer: Composer, FocusInvalid: FocusInvalid, Modal: Modal }
  });

  // The socket is the only thing that can tell a viewer the daemon went away, so the
  // body carries its state and the stylesheet decides what that looks like.
  window.addEventListener("phx:page-loading-start", function () {
    document.body.classList.add("phx-loading");
  });
  window.addEventListener("phx:page-loading-stop", function () {
    document.body.classList.remove("phx-loading");
  });

  liveSocket.connect();

  // Deliberately exposed: `liveSocket.enableDebug()` in a browser console is how a
  // person debugging this surface sees what it is sending.
  window.liveSocket = liveSocket;
})();
