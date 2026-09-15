/* Image bytes travel only through authenticated, bounded attachment calls. */
(function () {
  "use strict";
  var MAX = 20 * 1024 * 1024, TOTAL = 64 * 1024 * 1024;
  // Survives LiveView navigation, but never a page reload. Only drafts with source
  // Files live here; completed sources are released. Admission bounds the whole cache.
  var drafts = new Map();
  function uuid() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
  }
  function storage(key, value) {
    try {
      if (value === undefined) return sessionStorage.getItem(key);
      sessionStorage.setItem(key, value);
    } catch (_) { /* An unavailable cache never takes the draft away. */ }
    return null;
  }
  function base64(bytes) {
    var parts = [];
    for (var i = 0; i < bytes.length; i += 8192)
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)));
    return btoa(parts.join(""));
  }
  async function digest(bytes) {
    if (!crypto.subtle) throw new Error("Image uploads require HTTPS or a localhost browser connection.");
    return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
  }
  function imageUrl(el, id, variant) {
    var query = new URLSearchParams();
    if (el.dataset.node) query.set("node", el.dataset.node);
    if (el.dataset.sessionId) query.set("session_id", el.dataset.sessionId);
    return "/attachments/" + encodeURIComponent(id) + "/" + variant + "?" + query;
  }
  function preview(url, name) {
    var dialog = document.createElement("dialog"), image = document.createElement("img");
    dialog.className = "ouro-image-preview";
    image.src = url; image.alt = name || "Attached image";
    var close = document.createElement("button");
    close.type = "button"; close.textContent = "Close image";
    close.onclick = function () { dialog.close(); };
    dialog.append(close, image); document.body.append(dialog);
    var focused = document.activeElement;
    dialog.addEventListener("close", function () {
      image.src = ""; dialog.remove(); if (focused && focused.isConnected) focused.focus();
    });
    dialog.showModal(); close.focus();
  }
  document.addEventListener("click", function (event) {
    var target = event.target.closest("[data-image-preview]");
    if (target) { event.preventDefault(); preview(target.dataset.imagePreview, target.textContent); }
  });

  window.OuroImageAttachments = {
    mounted: function () {
      this.form = this.el.closest("form");
      this.text = this.form.querySelector("textarea");
      this.picker = this.el.querySelector("[data-image-picker]");
      this.tray = this.el.querySelector(".ouro-image-tray");
      this.hint = this.el.querySelector("[role=status]");
      this.attach = this.el.querySelector("[data-attach]");
      this.attach.onclick = function () { this.picker.click(); }.bind(this);
      this.picker.onchange = function () { this.add(this.picker.files, "file_picker"); this.picker.value = ""; }.bind(this);
      this.onPaste = function (event) {
        if (this.el.dataset.locked === "true" || !this.enabled || event.target !== this.text || !event.clipboardData) return;
        var files = Array.from(event.clipboardData.items || []).filter(function (item) {
          return item.kind === "file" && item.type.startsWith("image/");
        }).map(function (item) { return item.getAsFile(); }).filter(Boolean);
        if (!files.length) files = Array.from(event.clipboardData.files || []).filter(function (file) { return file.type.startsWith("image/"); });
        if (!files.length) return;
        event.preventDefault();
        var text = event.clipboardData.getData("text/plain");
        if (text) {
          this.text.setRangeText(text, this.text.selectionStart, this.text.selectionEnd, "end");
          this.text.dispatchEvent(new Event("input", {bubbles: true}));
        }
        this.add(files, "clipboard");
      }.bind(this);
      this.onDrag = function (event) {
        if (this.enabled && Array.from(event.dataTransfer.types).includes("Files")) event.preventDefault();
      }.bind(this);
      this.onDrop = function (event) {
        if (!this.enabled || !event.dataTransfer.files.length) return;
        event.preventDefault(); this.add(event.dataTransfer.files, "drop");
      }.bind(this);
      this.onSubmit = function (event) {
        this.sync();
        if (this.batchError || this.entries.some(function (e) { return e.state !== "ready"; }) ||
            (this.entries.length && ((event.submitter && event.submitter.value === "steer") || this.text.value.startsWith("!")))) {
          event.preventDefault(); event.stopImmediatePropagation();
          if (!this.batchError) this.hint.textContent = "Finish or remove pending images, then Send or Queue the message.";
        }
      }.bind(this);
      this.lastEdit = Date.now();
      this.onInput = function () {this.lastEdit = Date.now(); this.sync();}.bind(this);
      this.form.addEventListener("paste", this.onPaste);
      this.form.addEventListener("dragover", this.onDrag);
      this.form.addEventListener("drop", this.onDrop);
      this.form.addEventListener("submit", this.onSubmit, true);
      this.text.addEventListener("input", this.onInput);
      this.handleEvent("draft-sent", function (event) {
        if (event.key !== this.key || !Array.isArray(event.images)) return;
        var ids = event.images.map(function (r) { return r.id; });
        if (!this.entries.some(function (e) { return ids.includes(e.id); })) return;
        this.entries = this.entries.filter(function (e) { return !ids.includes(e.id); });
        if (!this.el.dataset.sessionId && !this.entries.length) {
          drafts.delete(this.draft);
          try { sessionStorage.removeItem("ouroboros.images." + this.draft); } catch (_) {}
          this.draft = this.key + ":" + this.client + ":" + uuid();
          storage("ouroboros.images.active." + this.key, this.draft);
        }
        this.render();
      }.bind(this));
      this.load();
      this.touch = setInterval(function () {
        if (Date.now() - this.lastEdit < 90000 && this.entries.some(function (e) { return e.state === "ready"; }))
          this.rpc("touch_draft", {draft_id: this.draft}).catch(function () {});
      }.bind(this), 60000);
    },
    updated: function () {
      if (this.key !== this.el.dataset.draftKey) this.load();
      this.render();
    },
    reconnected: function () { this.recover(); },
    destroyed: function () {
      this.remember();
      this.dead = true; this.generation++; clearInterval(this.touch);
      this.form.removeEventListener("paste", this.onPaste);
      this.form.removeEventListener("dragover", this.onDrag);
      this.form.removeEventListener("drop", this.onDrop);
      this.form.removeEventListener("submit", this.onSubmit, true);
      this.text.removeEventListener("input", this.onInput);
    },
    load: function () {
      if (this.entries) this.remember();
      this.key = this.el.dataset.draftKey; this.generation = (this.generation || 0) + 1;
      this.client = storage("ouroboros.images.client") || uuid(); storage("ouroboros.images.client", this.client);
      this.draft = storage("ouroboros.images.active." + this.key) || this.key + ":" + this.client;
      this.entries = []; this.enabled = false; this.batchError = false;
      this.attach.disabled = true;
      var cached = drafts.get(this.draft);
      if (cached) { this.entries = cached.entries; this.batchError = cached.batchError; }
      else try { this.entries = JSON.parse(storage("ouroboros.images." + this.draft) || "[]").slice(0, 32); } catch (_) {}
      this.entries.forEach(function (e) { e.state = e.file ? "waiting" : e.id ? "checking" : "failed"; });
      this.render();
      var generation = this.generation;
      this.rpc("limits", {}).then(function (limits) {
        if (generation !== this.generation) return;
        this.enabled = limits.image_attachments_v1 === true;
        this.maxSource = Math.min(MAX, limits.max_source_bytes || MAX);
        this.chunk = Math.min(limits.chunk_bytes || 65536, 65536);
        this.attach.disabled = !this.enabled;
        this.hint.textContent = this.enabled ? "Paste, drop, or choose images · up to 20 MiB each. Uploads go to the selected runtime before Send; unused images expire after 24 hours." : "Image uploads are unavailable on this runtime.";
        if (this.enabled && this.maxSource < MAX) this.hint.textContent += " This connection limits source files to " + Math.floor(this.maxSource / 1024) + " KiB.";
        if (this.enabled) { this.recover(); this.pump(); }
      }.bind(this)).catch(function (error) { this.hint.textContent = error.message; }.bind(this));
    },
    rpc: function (operation, params) {
      return new Promise(function (resolve, reject) {
        var timer = setTimeout(function () { reject(new Error("Connection interrupted. Retry this image to check its upload.")); }, 18000);
        this.pushEvent("image-action", {key: this.key, operation: operation, params: params}, function (answer) {
          clearTimeout(timer); if (answer.error) reject(new Error(answer.error)); else resolve(answer.ok);
        });
      }.bind(this));
    },
    add: function (files, source) {
      if (!this.enabled || this.el.dataset.locked === "true") return;
      this.lastEdit = Date.now();
      var batch = Array.from(files);
      var total = this.entries.reduce(function (sum, e) { return sum + e.size; }, 0);
      var maxSource = this.maxSource || MAX;
      var cachedFiles = [];
      drafts.forEach(function (draft) { draft.entries.forEach(function (e) { if (e.file) cachedFiles.push(e.file); }); });
      var cacheFull = cachedFiles.length + batch.length > 64 || cachedFiles.concat(batch).reduce(function (n, f) {return n + f.size;}, 0) > TOTAL;
      var invalid = cacheFull || this.entries.length + batch.length > 32 || total + batch.reduce(function (n, f) {return n + f.size;}, 0) > TOTAL || batch.some(function (f) { return f.size > maxSource || f.size === 0; });
      if (invalid) {
        this.batchError = true;
        this.hint.textContent = cacheFull ? "Finish or remove images in other drafts before adding more. Unfinished sources are limited to 64 images and 64 MiB across this page." : "No images from this selection were added. Limit: 32 images, 20 MiB each, 64 MiB per message. Choose a smaller selection or dismiss this error.";
        var dismiss = document.createElement("button"); dismiss.type = "button"; dismiss.textContent = "Dismiss selection error";
        dismiss.onclick = function () {this.batchError = false; this.hint.textContent = "Selection error dismissed."; this.sync();}.bind(this);
        this.hint.append(dismiss); this.sync(); return;
      }
      batch.forEach(function (file) {
        this.entries.push({local: uuid(), attempt: uuid(), name: file.name, size: file.size, source: source, state: "waiting", file: file});
      }.bind(this));
      this.render(); this.pump();
    },
    current: function (e, generation) { return !this.dead && generation === this.generation && this.entries.includes(e); },
    retained: function (e, draft) { var cached = drafts.get(draft); return cached && cached.entries.includes(e); },
    pump: async function () {
      if (this.running || !this.enabled || this.dead) return;
      this.running = true; var generation = this.generation;
      try {
        for (var e of this.entries) {
          if (!this.current(e, generation)) break;
          if (e.state !== "waiting") continue;
          try { await this.upload(e, generation); }
          catch (error) { if (this.current(e, generation)) { e.state = "failed"; e.error = error.message; this.render(); } }
        }
      } finally { this.running = false; if (this.entries.some(function (e) { return e.state === "waiting"; })) this.pump(); }
    },
    upload: async function (e, generation) {
      if (!e.file) throw new Error("Choose this image again to retry its upload.");
      e.state = "uploading"; this.render();
      var bytes = new Uint8Array(await e.file.arrayBuffer());
      e.hash = await digest(bytes);
      if (!this.current(e, generation)) return;
      var draft = this.draft, key = this.key;
      var status = await this.rpc("begin", {client_id: this.client, draft_id: draft,
        client_attachment_id: e.local, attempt_id: e.attempt, byte_size: e.size, display_name: e.name, source: e.source});
      e.id = status.upload_id;
      if (!this.current(e, generation)) {
        // Switching drafts cancels work, not its source or resumable upload. Explicit
        // removal still releases the late upload on the original live draft.
        if (!this.retained(e, draft) && !this.dead && this.key === key)
          this.rpc("discard", {upload_id: e.id}).catch(function () {});
        return;
      }
      while (status.received < bytes.length && status.state === "uploading") {
        if (!this.current(e, generation)) return;
        var end = Math.min(status.received + this.chunk, bytes.length);
        status = await this.rpc("append", {upload_id: e.id, offset: status.received, image_data: base64(bytes.subarray(status.received, end))});
        e.progress = Math.round(status.received / bytes.length * 100); this.render();
      }
      if (!this.current(e, generation)) return;
      status = await this.rpc("finish", {upload_id: e.id, sha256: e.hash});
      await this.poll(e, generation, status);
    },
    poll: async function (e, generation, status) {
      for (var n = 0; n < 120 && this.current(e, generation); n++) {
        e.state = status.state;
        e.remoteState = status.state;
        if (status.state === "ready") {
          var duplicate = this.entries.find(function (other) { return other !== e && other.state === "ready" && other.sha256 === status.sha256; });
          if (duplicate) {
            this.entries = this.entries.filter(function (other) { return other !== e; });
            this.rpc("discard", {upload_id: e.id}).catch(function () {});
            this.hint.textContent = "Image already attached.";
          } else { Object.assign(e, status); e.state = "ready"; }
          e.file = null; this.render(); return;
        }
        if (status.state === "failed") throw new Error(status.error || "Image could not be prepared. Remove it and choose another image.");
        if (status.state === "uploading") throw new Error("Upload interrupted. Retry to resume, or choose the image again.");
        this.render(); await new Promise(function (resolve) { setTimeout(resolve, 500); });
        if (!this.current(e, generation)) return;
        status = await this.rpc("status", {upload_id: e.id});
      }
      if (this.current(e, generation)) throw new Error("Image preparation is taking longer than expected. Retry to check it.");
    },
    recover: async function () {
      var generation = this.generation;
      for (var e of this.entries) {
        if (!e.id || e.file || !this.current(e, generation)) continue;
        try {
          var status = await this.rpc("status", {upload_id: e.id});
          if (status.state === "uploading" && e.hash && status.received === e.size)
            status = await this.rpc("finish", {upload_id: e.id, sha256: e.hash});
          await this.poll(e, generation, status);
        } catch (error) { if (this.current(e, generation)) { e.state = "failed"; e.error = error.message; this.render(); } }
      }
    },
    retry: async function (e) {
      if (e.retrying) return;
      var generation = this.generation;
      e.retrying = true;
      e.error = null;
      try {
        // A lost response is reconciled first. Uploading/preparing keep their attempt
        // identity; only a terminal failed attempt is replaced.
        var status = e.id ? await this.rpc("status", {upload_id: e.id}) : null;
        if (!this.current(e, generation)) return;
        if (status && status.state === "failed") {
          if (!e.file) throw new Error("Remove this entry and choose the image again.");
          await this.rpc("discard", {upload_id: e.id});
          if (!this.current(e, generation)) return;
          e.id = null; e.attempt = uuid(); e.progress = 0; e.remoteState = null;
        } else if (status && status.state !== "uploading") {
          await this.poll(e, generation, status); return;
        }
        if (!e.file) throw new Error("Remove this entry and choose the image again.");
        e.state = "waiting"; this.render(); this.pump();
      } catch (error) {
        if (this.current(e, generation)) { e.state = "failed"; e.error = error.message; this.render(); }
      } finally {
        e.retrying = false;
      }
    },
    remember: function () {
      if (this.entries.some(function (e) { return e.file; }))
        drafts.set(this.draft, {entries: this.entries, batchError: this.batchError});
      else drafts.delete(this.draft);
      storage("ouroboros.images." + this.draft, JSON.stringify(this.entries.map(function (e) {
        var saved = Object.assign({}, e); delete saved.file; delete saved.retrying; return saved;
      })));
    },
    render: function () {
      this.tray.replaceChildren();
      this.entries.forEach(function (e) {
        var card = document.createElement("div"); card.className = "ouro-image-card"; card.setAttribute("role", "listitem");
        if (e.state === "ready") {
          var open = document.createElement("button"), img = document.createElement("img");
          open.type = "button"; open.setAttribute("aria-label", "Preview " + e.name);
          img.src = imageUrl(this.el, e.id, "thumbnail"); img.alt = e.name; img.loading = "lazy";
          img.onerror = function () { img.replaceWith(document.createTextNode("Preview unavailable")); };
          open.append(img); open.onclick = function () { preview(imageUrl(this.el, e.id, "content"), e.name); }.bind(this);
          card.append(open);
        }
        var label = document.createElement("span");
        label.textContent = e.name + " · " + (e.state === "ready" ? e.width + " × " + e.height : e.state + (e.progress ? " " + e.progress + "%" : ""));
        card.append(label);
        if (e.error && e.state === "failed") { var error = document.createElement("span"); error.textContent = e.error; card.append(error); }
        if (e.state === "failed") {
          var retry = document.createElement("button"); retry.type = "button"; retry.textContent = "Retry"; retry.disabled = this.el.dataset.locked === "true";
          retry.onclick = function () { this.retry(e); }.bind(this); card.append(retry);
        }
        var remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove"; remove.disabled = this.el.dataset.locked === "true";
        remove.setAttribute("aria-label", "Remove " + e.name);
        remove.onclick = function () {
          this.entries = this.entries.filter(function (other) { return other !== e; });
          if (e.id) this.rpc("discard", {upload_id: e.id}).catch(function () {});
          e.file = null; this.render(); this.text.focus();
        }.bind(this); card.append(remove); this.tray.append(card);
      }.bind(this));
      this.remember();
      this.sync();
    },
    sync: function () {
      this.attach.disabled = !this.enabled || this.el.dataset.locked === "true";
      var ready = this.entries.length > 0 && this.entries.every(function (e) { return e.state === "ready"; });
      var pending = this.batchError || this.entries.some(function (e) { return e.state !== "ready"; });
      this.el.querySelector("[name=images_json]").value = pending ? "null" : JSON.stringify(this.entries.map(function (e) { return {id: e.id}; }));
      this.el.querySelector("[name=images_draft]").value = this.draft;
      this.form.dataset.imagesReady = ready ? "true" : "false";
      this.form.dataset.imagesPending = pending ? "true" : "false";
      this.text.required = this.text.name === "message" && !ready;
      var send = this.form.querySelector("[data-ouro-send]");
      if (send) send.disabled = pending || (!ready && !this.text.value.trim());
      var steer = this.form.querySelector("[data-ouro-steer]");
      if (steer) { steer.disabled = this.entries.length > 0 || !this.text.value.trim(); steer.title = this.entries.length ? "Use Queue to send images" : "Steer the running turn"; }
    }
  };
})();
