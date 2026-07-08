"use strict";
(function () {
  var ACTIONS = { 0: "SAFE", 1: "LOG", 2: "ALERT", 3: "BLOCK", 4: "ISOLATE" };
  var SAMPLES = {
    url: "https://paypal.com@secure-login.sbs/verify",
    text: "URGENT: Your account is locked. Buy iTunes gift cards now and send the codes to restore access.",
    // Sample secrets are assembled at runtime so the source file itself
    // never contains a contiguous token literal (avoids secret-scanner false
    // positives); HLSE re-detects them once concatenated.
    secrets: "AWS_ACCESS_KEY_ID=" + "AKIA" + "2E3MWORQXYZ4567PQ" +
             "\nGITLAB_TOKEN=" + "glpat-" + "abcdef1234567890ABCD"
  };

  var form = document.getElementById("scan-form");
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  var fields = Array.prototype.slice.call(document.querySelectorAll(".field"));
  var result = document.getElementById("result");
  var scanBtn = document.getElementById("scan-btn");
  var sampleBtn = document.getElementById("sample-btn");
  var current = "url";

  function selectTab(name) {
    current = name;
    tabs.forEach(function (t) {
      var on = t.getAttribute("data-tab") === name;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
    });
    fields.forEach(function (f) {
      f.classList.toggle("hidden", f.getAttribute("data-for") !== name);
    });
  }

  tabs.forEach(function (t) {
    t.addEventListener("click", function () { selectTab(t.getAttribute("data-tab")); });
  });

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function currentInput() {
    if (current === "url") return document.getElementById("in-url").value.trim();
    if (current === "text") return document.getElementById("in-text").value;
    return document.getElementById("in-secrets").value;
  }

  function endpoint() {
    if (current === "url") return "/api/v1/scan/url";
    if (current === "text") return "/api/v1/scan/text";
    return "/api/v1/scan/secrets";
  }

  function payload(value) {
    if (current === "url") return { url: value };
    return { text: value };
  }

  function renderError(msg) {
    result.innerHTML = '<p class="error">' + escapeHtml(msg) + "</p>";
  }

  function renderScan(data) {
    var action = ACTIONS[data.severity] || "SAFE";
    var pct = Math.max(0, Math.min(100, data.score));
    var html = '<div class="verdict sev-' + action + '">';
    html += '<div class="gauge" style="--v:' + pct + '"><span class="score">' + pct + "</span></div>";
    html += '<div class="verdict-main">';
    html += '<span class="badge">' + action + "</span>";
    html += "<h2>" + (data.kind === "url" ? "URL analysis" : "Message analysis") + "</h2>";
    html += '<p class="muted">Risk score ' + pct + "/100</p>";
    html += "</div></div>";
    if (data.reasons && data.reasons.length) {
      html += '<ul class="reasons sev-' + action + '">';
      data.reasons.forEach(function (r) { html += "<li>" + escapeHtml(r) + "</li>"; });
      html += "</ul>";
    } else {
      html += '<p class="no-reasons">No suspicious signals detected.</p>';
    }
    result.innerHTML = html;
  }

  function renderSecrets(data) {
    var n = data.findings ? data.findings.length : 0;
    var action = n ? "ISOLATE" : "SAFE";
    var html = '<div class="verdict sev-' + action + '">';
    html += '<div class="gauge" style="--v:' + Math.max(0, Math.min(100, data.score)) + '"><span class="score">' + n + "</span></div>";
    html += '<div class="verdict-main"><span class="badge">' + (n ? "SECRETS FOUND" : "CLEAN") + "</span>";
    html += "<h2>Secret scan</h2>";
    html += '<p class="muted">' + n + " finding" + (n === 1 ? "" : "s") + "</p></div></div>";
    if (n) {
      html += '<ul class="reasons sev-' + action + '">';
      data.findings.forEach(function (f) {
        html += '<li class="finding"><span class="ftype">' + escapeHtml(f.type) + "</span>" + escapeHtml(f.detail) + "</li>";
      });
      html += "</ul>";
    } else {
      html += '<p class="no-reasons">No leaked credentials detected.</p>';
    }
    result.innerHTML = html;
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var value = currentInput();
    if (!value) { renderError("Please enter something to scan."); return; }
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning…";
    var mode = current;
    fetch(endpoint(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload(value))
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok) { renderError(res.j && res.j.error ? res.j.error : "Scan failed."); return; }
        if (mode === "secrets") renderSecrets(res.j); else renderScan(res.j);
      })
      .catch(function () { renderError("Could not reach the HLSE server."); })
      .finally(function () { scanBtn.disabled = false; scanBtn.textContent = "Scan"; });
  });

  sampleBtn.addEventListener("click", function () {
    if (current === "url") document.getElementById("in-url").value = SAMPLES.url;
    else if (current === "text") document.getElementById("in-text").value = SAMPLES.text;
    else document.getElementById("in-secrets").value = SAMPLES.secrets;
  });

  // Load engine version for the header pill.
  fetch("/api/v1/health").then(function (r) { return r.json(); }).then(function (j) {
    var el = document.getElementById("engine-version");
    if (el && j.engine) el.textContent = "engine " + j.engine;
  }).catch(function () {});
})();
