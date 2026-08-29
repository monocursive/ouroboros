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

  var liveSocket = new LiveSocket("/live", Socket, {
    params: { _csrf_token: csrfToken },
    hooks: {}
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
