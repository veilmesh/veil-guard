// veil-guard Tier 1 — page-side loader.
//
// Registers the worker and renders what it reports. The overlay is user interface,
// not a security boundary: by the time anything is drawn, the worker has already
// refused to hand the page the bytes in question. Blocking happens in the worker;
// this only explains it.
//
// Deliberately plain: no framework, no build step, and nothing that would make it
// harder to read than the thing it is protecting.

(function () {
  'use strict';

  var SW_URL = '/veil-guard-sw.js';
  var STYLE_ID = 'veil-guard-style';

  if (!('serviceWorker' in navigator)) return;
  // A Service Worker needs a secure context; on http:// there is nothing to do and
  // no reason to alarm anyone.
  if (!window.isSecureContext) return;

  function ensureStyles() {
    if (document.getElementById(STYLE_ID)) return;
    var css = [
      '.veil-guard-overlay{position:fixed;inset:0;z-index:2147483647;display:flex;',
      'align-items:center;justify-content:center;padding:24px;',
      'background:rgba(8,10,14,.94);backdrop-filter:blur(6px);',
      'font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#e8ecf1}',
      '.veil-guard-card{max-width:34rem;width:100%;border-radius:14px;padding:26px 28px;',
      'background:#12161d;border:1px solid #2a323e;box-shadow:0 18px 50px rgba(0,0,0,.55)}',
      '.veil-guard-card h2{margin:0 0 10px;font-size:17px;font-weight:650;letter-spacing:-.01em}',
      '.veil-guard-card p{margin:0 0 12px;color:#aeb8c6}',
      '.veil-guard-card code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;',
      'background:#1b212b;border-radius:5px;padding:1px 6px;color:#cfd8e3}',
      '.veil-guard-card .vg-accent-security{color:#ff6b6b}',
      '.veil-guard-card .vg-accent-unsupported{color:#f0b429}',
      '.veil-guard-toast{position:fixed;left:16px;bottom:16px;z-index:2147483646;max-width:26rem;',
      'border-radius:10px;padding:12px 14px;background:#161b23;border:1px solid #2a323e;color:#cbd4e0;',
      'font:13px/1.5 ui-sans-serif,system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.4)}',
      '.veil-guard-toast button{margin-left:10px;border:0;border-radius:6px;padding:4px 10px;',
      'background:#28313d;color:#e8ecf1;font:inherit;cursor:pointer}',
      '@media (prefers-color-scheme: light){',
      '.veil-guard-overlay{background:rgba(244,246,249,.94);color:#161b23}',
      '.veil-guard-card{background:#fff;border-color:#d8dee7}',
      '.veil-guard-card p{color:#4a5666}',
      '.veil-guard-card code{background:#eef1f6;color:#333c48}',
      '.veil-guard-toast{background:#fff;border-color:#d8dee7;color:#333c48}',
      '.veil-guard-toast button{background:#eef1f6;color:#161b23}}',
    ].join('');
    var el = document.createElement('style');
    el.id = STYLE_ID;
    el.textContent = css;
    document.head.appendChild(el);
  }

  function clear(selector) {
    var existing = document.querySelector(selector);
    if (existing) existing.remove();
  }

  function showOverlay(kind, title, body) {
    ensureStyles();
    clear('.veil-guard-overlay');
    var wrap = document.createElement('div');
    wrap.className = 'veil-guard-overlay';
    wrap.setAttribute('role', 'alertdialog');
    wrap.setAttribute('aria-modal', 'true');

    var card = document.createElement('div');
    card.className = 'veil-guard-card';

    var h = document.createElement('h2');
    h.className = 'vg-accent-' + kind;
    h.textContent = title;
    card.appendChild(h);

    // textContent throughout: this overlay reports on untrusted input, so it must
    // never be a way to get markup executed.
    body.forEach(function (line) {
      var p = document.createElement('p');
      p.textContent = line;
      card.appendChild(p);
    });

    wrap.appendChild(card);
    document.body.appendChild(wrap);
  }

  function showToast(message, actionLabel, action) {
    ensureStyles();
    clear('.veil-guard-toast');
    var box = document.createElement('div');
    box.className = 'veil-guard-toast';
    box.setAttribute('role', 'status');
    box.textContent = message;
    if (actionLabel) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = actionLabel;
      btn.addEventListener('click', action);
      box.appendChild(btn);
    }
    document.body.appendChild(box);
  }

  function render(msg) {
    switch (msg.ui) {
      case 'security':
        showOverlay('security', 'Code tampering blocked', [
          'The code this site served does not match what its developers signed, so it was not run.',
          'Do not enter passwords or other sensitive information. Reloading will not help if the site itself is compromised.',
          msg.subject ? 'Affected: ' + msg.subject : 'The signed manifest failed verification.',
        ]);
        break;

      case 'unsupported':
        showOverlay('unsupported', 'Cannot verify this site', [
          'This browser does not implement any of the signature algorithms this site uses, so its code could not be checked before running.',
          'Updating the browser will usually resolve this.',
        ]);
        break;

      case 'retry':
        // Deliberately not the security overlay. A CDN outage dressed up as an
        // attack teaches people to dismiss the alert that matters.
        showToast('Could not reach the server. Some resources may be missing.', 'Retry', function () {
          window.location.reload();
        });
        break;

      case 'notice':
        showToast('This site has not been re-signed recently. Its code is still verified.');
        break;

      default:
        clear('.veil-guard-overlay');
        clear('.veil-guard-toast');
    }
  }

  navigator.serviceWorker.addEventListener('message', function (event) {
    var data = event.data;
    if (!data || typeof data.type !== 'string') return;
    if (data.type.indexOf('veil-guard:') !== 0) return;
    render(data);
  });

  navigator.serviceWorker
    .register(SW_URL, { scope: '/' })
    .then(function (registration) {
      // Ask for the current verdict rather than waiting for the next event, so a
      // page loaded into an already-controlled client is told immediately.
      var worker = registration.active || navigator.serviceWorker.controller;
      if (worker) worker.postMessage({ type: 'veil-guard:status' });
    })
    .catch(function (err) {
      // Registration failing is not evidence of an attack — it is the ordinary
      // outcome in a private window, with storage disabled, or behind a policy.
      // Failing loudly here would produce alarms nobody can act on.
      if (window.console && console.info) {
        console.info('veil-guard: worker not registered —', err && err.message);
      }
    });

  window.veilGuard = {
    status: function () {
      var w = navigator.serviceWorker.controller;
      if (w) w.postMessage({ type: 'veil-guard:status' });
    },
    refresh: function () {
      var w = navigator.serviceWorker.controller;
      if (w) w.postMessage({ type: 'veil-guard:refresh' });
    },
  };
})();
