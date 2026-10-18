/**
 * SOC Console // TCP Port Reconnaissance & Streaming Controller
 * Vanilla ES6+ Frontend Telemetry Engine
 */

(function () {
  "use strict";

  // -------------------------------------------------------------------------
  // DOM Element References
  // -------------------------------------------------------------------------
  const form = document.getElementById("scan-form");
  const targetInput = document.getElementById("target-input");
  const customPortsWrap = document.getElementById("custom-ports-wrap");
  const customPortsInput = document.getElementById("custom-ports");
  const identifyToggle = document.getElementById("identify-toggle");
  const speedSlider = document.getElementById("speed-slider");
  const speedIndicator = document.getElementById("speed-indicator");
  const nmapCommandLine = document.getElementById("nmap-command-line");
  const btnCopyCmd = document.getElementById("btn-copy-cmd");
  const consentCheck = document.getElementById("consent-check");
  const formErrorBanner = document.getElementById("form-error-banner");
  const formErrorMsg = document.getElementById("form-error-msg");
  const btnInitiate = document.getElementById("btn-initiate");

  // Telemetry HUD Elements
  const hudTarget = document.getElementById("hud-target");
  const hudProfile = document.getElementById("hud-profile");
  const hudThreads = document.getElementById("hud-threads");
  const hudElapsed = document.getElementById("hud-elapsed");
  const hudRate = document.getElementById("hud-rate");
  const engineStatus = document.getElementById("engine-status");
  const engineDot = document.getElementById("engine-dot");

  // Results & Metrics Elements
  const summaryPill = document.getElementById("summary-pill");
  const summaryPillText = document.getElementById("summary-pill-text");
  const progressPercent = document.getElementById("progress-percent");
  const progressRatio = document.getElementById("progress-ratio");
  const progressSpeed = document.getElementById("progress-speed");
  const meterFill = document.getElementById("meter-fill");
  const resultsBody = document.getElementById("results-body");
  const countOpen = document.getElementById("count-open");
  const countAll = document.getElementById("count-all");
  const reportsToolbar = document.getElementById("reports-toolbar");
  const btnDlPdf = document.getElementById("btn-dl-pdf");
  const btnDlCsv = document.getElementById("btn-dl-csv");
  const btnDlJson = document.getElementById("btn-dl-json");

  // Terminal Log Elements
  const terminalBody = document.getElementById("terminal-body");
  const liveLogContainer = document.getElementById("live-log-container");
  const btnAutoscroll = document.getElementById("btn-autoscroll");
  const btnCopyLog = document.getElementById("btn-copy-log");
  const btnClearLog = document.getElementById("btn-clear-log");

  // -------------------------------------------------------------------------
  // State Constants & Variables
  // -------------------------------------------------------------------------
  const SERVICE_PORTS_MAP = {
    web: [80, 443, 8080],
    remote: [22, 3389],
    database: [3306, 5432, 27017],
    mail: [25, 110, 143],
    file: [21, 445],
  };

  let activeEventSource = null;
  let activeScanId = null;
  let currentFilter = "open";
  let autoscroll = true;
  let discoveredPorts = new Set();
  let allFindings = [];
  let scanStartTime = null;
  let timerInterval = null;

  // -------------------------------------------------------------------------
  // Subtle Background Canvas Node Animation
  // -------------------------------------------------------------------------
  function initBackgroundCanvas() {
    const canvas = document.getElementById("bg-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    window.addEventListener("resize", () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    const nodes = [];
    const count = Math.min(35, Math.floor((width * height) / 35000));
    for (let i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 1.5 + 0.8,
      });
    }

    function render() {
      ctx.clearRect(0, 0, width, height);

      // Draw connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 140) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            const alpha = (1 - dist / 140) * 0.15;
            ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            ctx.lineWidth = 0.6;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 255, 156, 0.4)";
        ctx.fill();
      }

      requestAnimationFrame(render);
    }
    render();
  }

  // -------------------------------------------------------------------------
  // Helper & Formatting Functions
  // -------------------------------------------------------------------------
  function formatTimestamp(d = new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `[${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}]`;
  }

  function getSelectedPreset() {
    const checked = form.querySelector("input[name=preset]:checked");
    return checked ? checked.value : "standard";
  }

  function getActiveServices() {
    return Array.from(document.querySelectorAll(".service-chip.active")).map(
      (btn) => btn.dataset.service
    );
  }

  function getSpeedLabel(val) {
    const n = Number(val);
    if (n <= 30) return `STEALTH [${n} WORKERS]`;
    if (n <= 120) return `NORMAL [${n} WORKERS]`;
    return `AGGRESSIVE [${n} WORKERS]`;
  }

  function calculatePortsPhrase() {
    const preset = getSelectedPreset();
    const services = getActiveServices();
    const customVal = customPortsInput.value.trim();

    if (preset === "quick" && !services.length) return "top-100";
    if (preset === "standard" && !services.length) return "1-1024";
    if (preset === "full" && !services.length) return "1-65535";
    if (preset === "custom" && !services.length) return customVal || "...";

    const extraPorts = [];
    services.forEach((s) => {
      if (SERVICE_PORTS_MAP[s]) extraPorts.push(...SERVICE_PORTS_MAP[s]);
    });

    if (preset === "custom" && customVal) {
      return extraPorts.length ? `${customVal},${extraPorts.join(",")}` : customVal;
    }
    if (extraPorts.length && (preset === "quick" || preset === "standard" || preset === "full")) {
      return `${preset}+${extraPorts.join(",")}`;
    }
    return extraPorts.length ? extraPorts.join(",") : "...";
  }

  function refreshNmapPreview() {
    if (!form) return;
    const preset = getSelectedPreset();
    customPortsWrap.hidden = preset !== "custom";

    const host = targetInput.value.trim() || "target";
    const svFlag = identifyToggle.checked ? "-sV " : "";
    const ports = calculatePortsPhrase();
    const cmd = `nmap ${svFlag}-p ${ports} ${host}`;

    nmapCommandLine.textContent = cmd;

    // Update HUD telemetry preview
    hudTarget.textContent = host;
    hudProfile.textContent = preset.toUpperCase();
    hudThreads.textContent = speedSlider.value;
    speedIndicator.textContent = getSpeedLabel(speedSlider.value);
  }

  function showError(msg) {
    if (!msg) {
      formErrorBanner.hidden = true;
      formErrorMsg.textContent = "";
      return;
    }
    formErrorBanner.hidden = false;
    formErrorMsg.textContent = msg;
    appendTerminalLog(`[!] Error: ${msg}`, "log-error");
  }

  // -------------------------------------------------------------------------
  // Terminal Log Manager
  // -------------------------------------------------------------------------
  function appendTerminalLog(text, className = "") {
    if (!liveLogContainer) return;
    const line = document.createElement("div");
    line.className = `log-line ${className}`.trim();
    const timeStr = `<span class="text-muted">${formatTimestamp()}</span> `;
    line.innerHTML = timeStr + escapeHtml(text);
    liveLogContainer.appendChild(line);

    if (autoscroll && terminalBody) {
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // -------------------------------------------------------------------------
  // Results Table Renderer
  // -------------------------------------------------------------------------
  function renderTableRow(finding) {
    // Check if port was already rendered
    if (discoveredPorts.has(finding.port)) return;
    discoveredPorts.add(finding.port);

    // Remove empty placeholder row if present
    const emptyRow = document.getElementById("empty-state-row");
    if (emptyRow) emptyRow.remove();

    const tr = document.createElement("tr");
    tr.className = "row-open";
    tr.dataset.port = finding.port;
    tr.dataset.state = finding.state || "open";

    const tdPort = document.createElement("td");
    tdPort.className = "port-cell";
    tdPort.textContent = `${finding.port}/tcp`;

    const tdState = document.createElement("td");
    const stateBadge = document.createElement("span");
    stateBadge.className = `state-badge ${finding.state === "open" ? "open" : "filtered"}`;
    stateBadge.textContent = (finding.state || "open").toUpperCase();
    tdState.appendChild(stateBadge);

    const tdService = document.createElement("td");
    tdService.className = "service-cell";
    tdService.textContent = finding.service || "unknown";

    const tdBanner = document.createElement("td");
    tdBanner.className = "banner-cell";
    tdBanner.textContent = finding.banner || "— (No greeting banner returned)";

    tr.append(tdPort, tdState, tdService, tdBanner);
    resultsBody.appendChild(tr);

    // Update counts
    countOpen.textContent = discoveredPorts.size;
    countAll.textContent = discoveredPorts.size;
  }

  // -------------------------------------------------------------------------
  // SSE Telemetry Event Handler
  // -------------------------------------------------------------------------
  function handleStreamSnapshot(data) {
    if (!data) return;

    // Progress updates
    const pct = data.percent || 0;
    meterFill.style.width = `${pct}%`;
    progressPercent.textContent = `${pct}%`;
    progressRatio.textContent = `${data.completed || 0} / ${data.total || 0} PORTS`;

    const rateVal = data.rate || 0;
    progressSpeed.textContent = `${rateVal} PORTS/S`;
    hudRate.textContent = `${rateVal} P/S`;

    if (data.elapsed !== undefined) {
      const s = data.elapsed;
      const mins = Math.floor(s / 60);
      const secs = (s % 60).toFixed(1);
      hudElapsed.textContent = `${String(mins).padStart(2, "0")}:${secs < 10 ? "0" : ""}${secs}s`;
    }

    if (data.ip) {
      hudTarget.textContent = `${data.target} (${data.ip})`;
    }

    // Process new log entries
    if (data.new_logs && Array.isArray(data.new_logs)) {
      data.new_logs.forEach((log) => {
        let cls = "log-info";
        if (log.startsWith("[+]")) cls = "log-finding";
        else if (log.startsWith("[!]")) cls = "log-error";
        else if (log.startsWith("[✓]")) cls = "log-finding";
        appendTerminalLog(log, cls);
      });
    }

    // Process discovered findings
    if (data.results && Array.isArray(data.results)) {
      data.results.forEach((finding) => renderTableRow(finding));
    }

    // Handle Scan Completion
    if (data.status === "done") {
      cleanupScan("done");
      summaryPillText.textContent = data.summary || "SURVEY COMPLETE";
      summaryPill.style.borderColor = "var(--accent-green)";
      summaryPill.style.color = "var(--accent-green)";

      // Setup Report Downloads
      const base = `/api/report/${data.id}`;
      btnDlPdf.href = `${base}?format=pdf`;
      btnDlCsv.href = `${base}?format=csv`;
      btnDlJson.href = `${base}?format=json`;
      reportsToolbar.hidden = false;

      engineStatus.textContent = "ENGINE ONLINE // IDLE";
      engineDot.style.backgroundColor = "var(--accent-green)";
    } else if (data.status === "error") {
      cleanupScan("error");
      showError(data.error || "Survey terminated with an error.");
      summaryPillText.textContent = "SURVEY FAILED";
      summaryPill.style.borderColor = "var(--accent-red)";
      summaryPill.style.color = "var(--accent-red)";
      engineStatus.textContent = "ENGINE ERROR";
      engineDot.style.backgroundColor = "var(--accent-red)";
    }
  }

  function cleanupScan(finalState) {
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
    btnInitiate.disabled = false;
    btnInitiate.innerHTML = `
      <span class="btn-inner">
        <span class="btn-bracket">[</span>
        <span class="btn-icon">⚡</span>
        <span class="btn-text">INITIATE SCAN</span>
        <span class="btn-bracket">]</span>
      </span>
    `;
  }

  // -------------------------------------------------------------------------
  // Fallback Polling (if SSE is blocked)
  // -------------------------------------------------------------------------
  async function pollStatus(jobId) {
    try {
      const res = await fetch(`/api/scan/${jobId}`);
      if (!res.ok) throw new Error("Status query failed");
      const data = await res.json();
      handleStreamSnapshot(data);
      if (data.status === "running") {
        setTimeout(() => pollStatus(jobId), 300);
      }
    } catch (err) {
      console.warn("Polling error:", err);
    }
  }

  // -------------------------------------------------------------------------
  // Event Listeners & UI Binding
  // -------------------------------------------------------------------------
  if (form) {
    // Live update on input & change
    form.addEventListener("input", refreshNmapPreview);
    form.addEventListener("change", refreshNmapPreview);

    // Quick target buttons
    document.querySelectorAll(".btn-chip-target").forEach((btn) => {
      btn.addEventListener("click", () => {
        targetInput.value = btn.dataset.target;
        refreshNmapPreview();
      });
    });

    // Service toggle chips
    document.querySelectorAll(".service-chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        btn.classList.toggle("active");
        refreshNmapPreview();
      });
    });

    // Speed slider discrete mark clicks
    document.querySelectorAll(".range-marks .mark-label").forEach((mark) => {
      mark.addEventListener("click", () => {
        speedSlider.value = mark.dataset.val;
        document.querySelectorAll(".range-marks .mark-label").forEach((m) => m.classList.remove("active"));
        mark.classList.add("active");
        refreshNmapPreview();
      });
    });

    speedSlider.addEventListener("input", () => {
      const val = Number(speedSlider.value);
      document.querySelectorAll(".range-marks .mark-label").forEach((m) => {
        m.classList.toggle("active", Math.abs(Number(m.dataset.val) - val) < 30);
      });
    });

    // Copy live Nmap command
    btnCopyCmd.addEventListener("click", async () => {
      const text = nmapCommandLine.textContent;
      try {
        await navigator.clipboard.writeText(text);
        const copySpan = btnCopyCmd.querySelector(".copy-text");
        copySpan.textContent = "COPIED!";
        setTimeout(() => (copySpan.textContent = "COPY"), 1500);
      } catch (err) {
        console.error("Clipboard write failed:", err);
      }
    });

    // Form Submission
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      showError("");

      if (!consentCheck.checked) {
        showError("Scope verification required: You must confirm authorization to scan this target.");
        return;
      }

      const target = targetInput.value.trim();
      if (!target) {
        showError("Target host or IPv4 address is required.");
        return;
      }

      // Lock UI
      btnInitiate.disabled = true;
      btnInitiate.innerHTML = `
        <span class="btn-inner">
          <span class="btn-bracket">[</span>
          <span class="btn-text">RECON IN PROGRESS...</span>
          <span class="btn-bracket">]</span>
        </span>
      `;
      reportsToolbar.hidden = true;
      discoveredPorts.clear();
      allFindings = [];
      resultsBody.innerHTML = `
        <tr class="empty-row" id="empty-state-row">
          <td colspan="4">
            <div class="empty-state">
              <span class="empty-code" style="color: var(--accent-cyan);">[ SURVEY IN PROGRESS // LISTENING FOR REPLIES ]</span>
              <p>Clerks are actively probing target TCP sockets...</p>
            </div>
          </td>
        </tr>
      `;
      countOpen.textContent = "0";
      countAll.textContent = "0";
      meterFill.style.width = "0%";
      progressPercent.textContent = "0%";
      summaryPillText.textContent = "SURVEY ACTIVE...";
      engineStatus.textContent = "SCANNING ACTIVE";
      engineDot.style.backgroundColor = "var(--accent-cyan)";

      appendTerminalLog(`[*] Dispatching scan against target: ${target}`);

      const payload = {
        target: target,
        preset: getSelectedPreset(),
        ports: customPortsInput.value,
        services: getActiveServices(),
        identify: identifyToggle.checked,
        threads: Number(speedSlider.value),
        consent: true,
      };

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "Scan request was declined by engine.");
        }

        activeScanId = data.id;
        handleStreamSnapshot(data);

        // Connect Server-Sent Events (SSE)
        if (window.EventSource) {
          activeEventSource = new EventSource(`/api/progress/${activeScanId}`);
          activeEventSource.onmessage = (event) => {
            try {
              const snapshot = JSON.parse(event.data);
              handleStreamSnapshot(snapshot);
            } catch (err) {
              console.error("SSE parse error:", err);
            }
          };
          activeEventSource.onerror = (err) => {
            console.warn("SSE error/disconnection, falling back to polling:", err);
            if (activeEventSource) {
              activeEventSource.close();
              activeEventSource = null;
            }
            pollStatus(activeScanId);
          };
        } else {
          pollStatus(activeScanId);
        }
      } catch (err) {
        showError(err.message);
        cleanupScan("error");
      }
    });
  }

  // -------------------------------------------------------------------------
  // Terminal Action Buttons
  // -------------------------------------------------------------------------
  if (btnAutoscroll) {
    btnAutoscroll.addEventListener("click", () => {
      autoscroll = !autoscroll;
      btnAutoscroll.textContent = `AUTOSCROLL: ${autoscroll ? "ON" : "OFF"}`;
      btnAutoscroll.style.color = autoscroll ? "var(--accent-cyan)" : "var(--text-muted)";
    });
  }

  if (btnCopyLog) {
    btnCopyLog.addEventListener("click", async () => {
      if (!terminalBody) return;
      const text = terminalBody.innerText;
      try {
        await navigator.clipboard.writeText(text);
        btnCopyLog.textContent = "COPIED!";
        setTimeout(() => (btnCopyLog.textContent = "COPY LOG"), 1500);
      } catch (err) {
        console.error("Clipboard write failed:", err);
      }
    });
  }

  if (btnClearLog) {
    btnClearLog.addEventListener("click", () => {
      if (liveLogContainer) liveLogContainer.innerHTML = "";
    });
  }

  // -------------------------------------------------------------------------
  // Filter Buttons
  // -------------------------------------------------------------------------
  document.querySelectorAll(".btn-filter").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".btn-filter").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      // Filter rows
      document.querySelectorAll("#results-body tr.row-open").forEach((row) => {
        if (currentFilter === "open") {
          row.style.display = row.dataset.state === "open" ? "" : "none";
        } else {
          row.style.display = "";
        }
      });
    });
  });

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  initBackgroundCanvas();
  refreshNmapPreview();
})();
