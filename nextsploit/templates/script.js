/* script.js — Interactive Client Logic for NextSploit Reports */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Navigation Tabs
  const navItems = document.querySelectorAll(".nav-links li");
  const tabContents = document.querySelectorAll(".tab-content");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(n => n.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      item.classList.add("active");
      const target = item.getAttribute("data-target");
      document.getElementById(target).classList.add("active");
    });
  });

  // 2. Findings Generation & Filtering
  const findings = window.NEXTSPLOIT_FINDINGS || [];
  const findingsContainer = document.getElementById("findings-container");
  const filterButtons = document.querySelectorAll(".filter-bar .filter-btn");

  function renderFindings(filter = "all") {
    findingsContainer.innerHTML = "";
    
    const filtered = findings.filter(f => {
      if (filter === "all") return true;
      const sev = (f.metadata?.severity || f.severity || "").toLowerCase();
      return sev === filter;
    });

    if (filtered.length === 0) {
      findingsContainer.innerHTML = `<div class="card"><p>No findings match the selected severity filter.</p></div>`;
      return;
    }

    filtered.forEach(f => {
      const meta = f.metadata || {};
      const classif = f.classification || {};
      const ev = f.evidence || {};
      const rep = f.replay || {};
      
      const severity = (meta.severity || f.severity || "info").toLowerCase();
      const uuid = meta.uuid || f.uuid || "N/A";
      const title = f.title || "Vulnerability";
      
      const itemDiv = document.createElement("div");
      itemDiv.className = "finding-item";

      const headerHtml = `
        <div class="finding-header-bar">
          <div class="finding-meta">
            <span class="sev-badge sev-${severity}">${severity}</span>
            <span class="finding-title">${title}</span>
          </div>
          <span class="finding-uuid-lbl">${uuid}</span>
        </div>
      `;

      // Build Details section
      let evidenceRequest = ev.request ? escapeHtml(ev.request) : "N/A";
      let evidenceResponse = ev.response ? escapeHtml(ev.response) : "N/A";
      let remediationHtml = f.remediation || "No remediation advice provided.";

      // Replay snapshots HTML
      let replayHtml = "";
      if (rep.snapshots && rep.snapshots.length > 0) {
        replayHtml = `
          <div class="detail-section" style="grid-column: span 2;">
            <h4>Replay Log Snapshot</h4>
            <div class="code-block">${escapeHtml(JSON.stringify(rep.snapshots, null, 2))}</div>
          </div>
        `;
      } else {
        replayHtml = `
          <div class="detail-section" style="grid-column: span 2;">
            <h4>Replay Status</h4>
            <p>Status: <strong>${rep.status || "Not Replayed"}</strong> | Result: <strong>${rep.result || "N/A"}</strong></p>
          </div>
        `;
      }

      const detailsHtml = `
        <div class="finding-details">
          <div class="details-grid">
            <div class="detail-section">
              <h4>Vulnerability Info</h4>
              <table class="data-table">
                <tr><td><strong>Category</strong></td><td>${meta.category || "N/A"}</td></tr>
                <tr><td><strong>Module</strong></td><td>${meta.module || "N/A"}</td></tr>
                <tr><td><strong>Confidence</strong></td><td>${meta.confidence || f.confidence || 1.0}</td></tr>
                <tr><td><strong>Risk Score</strong></td><td>${meta.risk_score || f.risk_score || 0.0} / 100</td></tr>
              </table>
            </div>
            
            <div class="detail-section">
              <h4>Classifications</h4>
              <table class="data-table">
                <tr><td><strong>CVE</strong></td><td>${classif.cve || "N/A"}</td></tr>
                <tr><td><strong>CWE</strong></td><td>${classif.cwe || "N/A"}</td></tr>
                <tr><td><strong>OWASP</strong></td><td>${classif.owasp || "N/A"}</td></tr>
              </table>
            </div>

            <div class="detail-section" style="grid-column: span 2;">
              <h4>Remediation Advice</h4>
              <p>${remediationHtml}</p>
            </div>

            <div class="detail-section">
              <h4>Request Payload Snapshot</h4>
              <div class="code-block">${evidenceRequest}</div>
              <div style="font-size:11px; color:#8b9bb4; margin-top:5px;">SHA256: ${ev.request_hash || "N/A"}</div>
            </div>

            <div class="detail-section">
              <h4>Response Body Snapshot</h4>
              <div class="code-block">${evidenceResponse}</div>
              <div style="font-size:11px; color:#8b9bb4; margin-top:5px;">SHA256: ${ev.response_hash || "N/A"}</div>
            </div>

            ${replayHtml}
          </div>
        </div>
      `;

      itemDiv.innerHTML = headerHtml + detailsHtml;
      findingsContainer.appendChild(itemDiv);

      // Accordion click handler
      const headerBar = itemDiv.querySelector(".finding-header-bar");
      const detailsSection = itemDiv.querySelector(".finding-details");
      headerBar.addEventListener("click", () => {
        const isVisible = detailsSection.style.display === "block";
        detailsSection.style.display = isVisible ? "none" : "block";
      });
    });
  }

  // Filter button handlers
  filterButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      filterButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const filterValue = btn.getAttribute("data-filter");
      renderFindings(filterValue);
    });
  });

  // Initial render
  renderFindings();

  function escapeHtml(text) {
    if (!text) return "";
    return text
      .toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
