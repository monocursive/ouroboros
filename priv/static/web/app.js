// Ouroboros web — the LiveSocket, and nothing else.
//
// No bundler, no module graph: `phoenix.min.js` and `phoenix_live_view.min.js` are the
// prebuilt UMD bundles that ship inside the dependencies, copied here verbatim by the
// `web.assets` mix alias, and they publish `Phoenix` and `LiveView` as globals. This
// file is hand-written and stays small enough to read in one sitting.
(function () {
  "use strict";

  var Socket = window.Phoenix && window.Phoenix.Socket;
  var LiveSocket = window.LiveView && window.LiveView.LiveSocket;

  if (!Socket || !LiveSocket) {
    // Nothing to wire. The page is server-rendered and stays correct without a socket;
    // it just will not update. Say so once rather than throwing on every navigation.
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

      this.onInput = this.autosize.bind(this);

      this.el.addEventListener("keydown", this.onKeyDown);
      this.el.addEventListener("input", this.onInput);
      this.autosize();
    },

    // The server owns the draft, so a send that cleared it or a refusal that handed it
    // back both land here and the box has to follow.
    updated: function () {
      this.autosize();
    },

    destroyed: function () {
      this.el.removeEventListener("keydown", this.onKeyDown);
      this.el.removeEventListener("input", this.onInput);
    },

    autosize: function () {
      var el = this.el;
      el.style.height = "auto";
      el.style.height = Math.min(el.scrollHeight, this.maxHeight) + "px";
    }
  };

  var liveSocket = new LiveSocket("/live", Socket, {
    params: { _csrf_token: csrfToken },
    hooks: { ScrollPin: ScrollPin, Composer: Composer }
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
