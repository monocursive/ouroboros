const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const { setTimeout: pause } = require('node:timers/promises');

function harness(options = {}) {
  const stored = new Map(), records = new Map(), calls = [];
  let releaseBegin, fail = !!options.failPreparation, interrupt = !!options.interruptAppend;
  const delayed = options.delayBegin ? new Promise(resolve => { releaseBegin = resolve; }) : null;
  const sandbox = {
    window: {}, crypto: webcrypto, Uint8Array, URLSearchParams, Event,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    document: { addEventListener() {}, createElement: () => ({}) },
    sessionStorage: { getItem: key => stored.get(key) || null, setItem: (key, value) => stored.set(key, value), removeItem: key => stored.delete(key) },
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
  };
  vm.runInNewContext(fs.readFileSync('priv/static/web/image-attachments.js', 'utf8'), sandbox);
  async function rpc(op, params) {
    calls.push({op, params: {...params}});
    if (op === 'limits') return {image_attachments_v1: true, chunk_bytes: 65536};
    if (op === 'begin') {
      const id = `att_${params.attempt_id}`;
      if (!records.has(id)) records.set(id, {upload_id: id, id, received: 0, state: 'uploading'});
      if (delayed && calls.filter(c => c.op === 'begin').length === 1) await delayed;
      return {...records.get(id)};
    }
    const record = records.get(params.upload_id);
    if (op === 'discard') { records.delete(params.upload_id); return {}; }
    assert.ok(record, `record exists for ${op}`);
    if (op === 'append') {
      record.received = params.offset + Buffer.from(params.image_data, 'base64').length;
      if (interrupt) { interrupt = false; throw new Error('lost append acknowledgement'); }
    }
    if (op === 'finish' && record.state === 'uploading') {
      if (fail) { fail = false; record.state = 'failed'; record.error = 'attachment_prepare_timeout'; }
      else Object.assign(record, {state: 'ready', width: 2, height: 1, sha256: 'normalized'});
    }
    return {...record};
  }
  function mount(key, session = key) {
    const events = new Map();
    const text = {addEventListener() {}, removeEventListener() {}}, picker = {}, tray = {}, hint = {append() {}}, attach = {};
    const form = {querySelector: () => text, addEventListener() {}, removeEventListener() {}};
    const elements = {'[data-image-picker]': picker, '.ouro-image-tray': tray, '[role=status]': hint, '[role=tooltip]': {}, '[data-attach]': attach};
    const instance = Object.assign({}, sandbox.window.OuroImageAttachments, {
      el: {dataset: {draftKey: key, sessionId: session}, closest: () => form, querySelector: selector => elements[selector]},
      handleEvent: (name, fn) => events.set(name, fn), rpc,
      // Exercise real persistence and lifecycle while DOM layout is covered by Playwright.
      render() { this.remember(); }, sync() {}, events,
    });
    instance.mounted();
    return instance;
  }
  return {mount, calls, records, stored, releaseBegin: () => releaseBegin()};
}
const file = () => ({name: 'screen.png', size: 4, arrayBuffer: async () => Uint8Array.from([1, 2, 3, 4]).buffer});
async function until(check) {
  for (let n = 0; n < 200; n++) { if (check()) return; await pause(5); }
  assert.ok(check(), 'expected state reached');
}

test('switching drafts preserves a source and resumes the original upload', async () => {
  const h = harness({delayBegin: true}), view = h.mount('one'), source = file();
  await until(() => view.enabled);
  view.add([source], 'clipboard');
  await until(() => h.calls.some(c => c.op === 'begin'));
  view.el.dataset.draftKey = 'two'; view.updated();
  view.el.dataset.draftKey = 'one'; view.updated();
  assert.equal(view.entries[0].file, source);
  h.releaseBegin();
  await until(() => view.entries[0].state === 'ready');
  assert.equal(new Set(h.calls.filter(c => c.op === 'begin').map(c => c.params.attempt_id)).size, 1);
  assert.equal(h.calls.filter(c => c.op === 'discard').length, 0);
  assert.equal(view.entries[0].file, null);
  view.destroyed();
});

test('a remounted LiveView recovers unfinished sources without page storage containing bytes', async () => {
  const h = harness({delayBegin: true}), old = h.mount('one'), source = file();
  await until(() => old.enabled);
  old.add([source], 'clipboard');
  await until(() => h.calls.some(c => c.op === 'begin'));
  old.destroyed();
  const current = h.mount('one');
  assert.equal(current.entries[0].file, source);
  h.releaseBegin();
  await until(() => current.entries[0].state === 'ready');
  assert.ok([...h.stored.values()].every(value => !value.includes('arrayBuffer') && !value.includes('"file"')));
  assert.equal(h.calls.filter(c => c.op === 'discard').length, 0);
  current.destroyed();
});

test('ready images recover alongside an unfinished source after switching drafts', async () => {
  const h = harness({delayBegin: true}), view = h.mount('one');
  await until(() => view.enabled);
  view.add([file()], 'clipboard');
  await until(() => h.calls.some(c => c.op === 'begin'));
  for (const id of ['att_ready_one', 'att_ready_two']) {
    h.records.set(id, {id, upload_id: id, state: 'ready', received: 4, sha256: id, width: 2, height: 1});
    view.entries.push({id, name: 'ready.png', size: 4, state: 'ready'});
  }
  view.el.dataset.draftKey = 'two'; view.updated();
  view.el.dataset.draftKey = 'one'; view.updated();
  await until(() => view.entries.slice(1).every(e => e.state === 'ready'));
  h.releaseBegin();
  await until(() => view.entries.every(e => e.state === 'ready'));
  assert.equal(view.entries.length, 3);
  view.destroyed();
});

test('unfinished source memory is bounded across conversation drafts', async () => {
  const h = harness(), view = h.mount('one');
  view.pump = () => {}; // Keep sources pending without allocating their declared bytes.
  await until(() => view.enabled);
  const source = size => ({...file(), size});
  view.add(Array.from({length: 3}, () => source(20 * 1024 * 1024)), 'clipboard');
  assert.equal(view.entries.length, 3);
  view.el.dataset.draftKey = 'two'; view.updated();
  await until(() => view.enabled);
  view.add([source(5 * 1024 * 1024)], 'clipboard');
  assert.equal(view.entries.length, 0);
  assert.equal(view.batchError, true);
  assert.match(view.hint.textContent, /across this page/);
  view.el.dataset.draftKey = 'one'; view.updated();
  assert.equal(view.entries.length, 3);
  view.destroyed();
});

test('retry replaces a terminal preparation failure and releases its old attempt', async () => {
  const h = harness({failPreparation: true}), view = h.mount('one');
  await until(() => view.enabled);
  view.add([file()], 'clipboard');
  await until(() => view.entries[0].state === 'failed' && !view.running);
  const entry = view.entries[0], prior = entry.attempt;
  await view.retry(entry);
  await until(() => entry.state === 'ready');
  assert.notEqual(entry.attempt, prior);
  assert.equal(h.calls.filter(c => c.op === 'discard').length, 1);
  assert.equal(h.records.size, 1);
  view.destroyed();
});

test('lost append acknowledgements resume the same attempt', async () => {
  const h = harness({interruptAppend: true}), view = h.mount('one');
  await until(() => view.enabled);
  view.add([file()], 'clipboard');
  await until(() => view.entries[0].state === 'failed' && !view.running);
  const entry = view.entries[0], prior = entry.attempt;
  await view.retry(entry);
  await until(() => entry.state === 'ready');
  assert.equal(entry.attempt, prior);
  assert.equal(h.calls.filter(c => c.op === 'discard').length, 0);
  view.destroyed();
});

test('successful initial messages rotate the draft while replayed acknowledgements are harmless', async () => {
  const h = harness(), view = h.mount('new', '');
  await until(() => view.enabled);
  view.add([file()], 'clipboard');
  await until(() => view.entries[0].state === 'ready');
  const prior = view.draft, id = view.entries[0].id;
  view.events.get('draft-sent')({key: 'new', images: [{id}]});
  assert.notEqual(view.draft, prior);
  const next = view.draft;
  view.events.get('draft-sent')({key: 'new', images: [{id}]});
  assert.equal(view.draft, next);
  view.destroyed();
  const remount = h.mount('new', '');
  assert.equal(remount.draft, next);
  remount.destroyed();
});
