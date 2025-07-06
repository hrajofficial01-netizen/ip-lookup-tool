// Validate IPv4 and IPv6 format
function isValidIP(ip) {
  const ipv4 = /^\b(\d{1,3}\.){3}\d{1,3}\b$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

// Check if IP is private/reserved (basic IPv4)
function isPrivateIP(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const [a, b] = parts.map(Number);
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254)
  );
}

async function fetchIPData() {
  const inputField = document.getElementById("ipInput");
  const lookupButton = document.getElementById("lookupButton");
  const summaryDiv = document.getElementById("summary");
  const tableBody = document.getElementById("tableBody");
  const summarySection = document.getElementById("summarySection");
  const tableSection = document.getElementById("tableSection");
  const errorMsg = document.getElementById("errorMsg");
  const messageDiv = document.getElementById("message");
  const downloadBtn = document.getElementById("downloadExcelBtn");

  // Clear previous results and messages
  errorMsg.classList.add("hidden");
  summarySection.classList.add("hidden");
  tableSection.classList.add("hidden");
  summaryDiv.textContent = "";
  tableBody.innerHTML = "";
  downloadBtn.style.display = "none";
  messageDiv.innerHTML = "";

  // Parse and validate input IPs
  let rawIPs = inputField.value
    .split(/[\s,\n]+/)
    .map(ip => ip.trim())
    .filter(ip => ip.length > 0);

  if (rawIPs.length === 0) {
    errorMsg.textContent = "⚠️ Please enter at least one IP address.";
    errorMsg.classList.remove("hidden");
    return;
  }

  // Find duplicates
  const ipCounts = rawIPs.reduce((acc, ip) => {
    acc[ip] = (acc[ip] || 0) + 1;
    return acc;
  }, {});
  const duplicateIPs = Object.keys(ipCounts).filter(ip => ipCounts[ip] > 1);

  // Deduplicate while preserving order
  let seen = new Set();
  const uniqueIPs = [];
  for (const ip of rawIPs) {
    if (!seen.has(ip)) {
      seen.add(ip);
      uniqueIPs.push(ip);
    }
  }

  // Filter out invalid IP formats too
  const validFormatIPs = uniqueIPs.filter(isValidIP);

  // Filter private/reserved IPs
  const privateIPs = validFormatIPs.filter(isPrivateIP);
  const validPublicIPs = validFormatIPs.filter(ip => !isPrivateIP(ip));

  if (validPublicIPs.length === 0) {
    errorMsg.textContent = "⚠️ No valid public IPs to process after filtering.";
    errorMsg.classList.remove("hidden");
    return;
  }

  // Compose messages for UI below textarea
  let messages = [];
  if (duplicateIPs.length > 0) {
    messages.push(`⚠️ Duplicate IPs filtered out: ${duplicateIPs.join(", ")}`);
  }
  if (privateIPs.length > 0) {
    messages.push(`⚠️ Private/Reserved IPs filtered out: ${privateIPs.join(", ")}`);
  }

  // If more than 100 valid public IPs, slice to 100 and warn
  let extraIPs = [];
  if (validPublicIPs.length > 100) {
    extraIPs = validPublicIPs.slice(100);
    messages.push(
      `⚠️ You entered ${validPublicIPs.length} valid public IPs. Only the first 100 will be processed.`
    );
    messages.push(`IPs excluded from processing: ${extraIPs.join(", ")}`);
  }

  messageDiv.innerHTML = messages.join("<br>") || "";

  // Limit to first 100 valid public IPs
  const ipsToProcess = validPublicIPs.slice(0, 100);

  // Disable button and change text
  lookupButton.disabled = true;
  lookupButton.textContent = "Fetching...";

  try {
    const response = await fetch("/get_ip_info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: ipsToProcess }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || "Server error occurred.");
    }

    const data = await response.json();

    summaryDiv.innerText = data.summary;
    summarySection.classList.remove("hidden");

    tableBody.innerHTML = data.table;
    tableSection.classList.remove("hidden");

    downloadBtn.style.display = "inline-block";

    // Save latest for copy/download
    window._latestSummary = data.summary;
    window._latestTable = data.raw_table;
  } catch (err) {
    console.error("Error:", err);
    alert("❌ Error retrieving IP info:\n" + err.message);
  } finally {
    lookupButton.disabled = false;
    lookupButton.textContent = "Get Info";
  }
}

// Copy summary text to clipboard
function copyToClipboard(elementId, btnId) {
  const text = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => (btn.innerHTML = original), 1500);
  });
}

// Copy table content to clipboard (TSV)
function copyTableToClipboard(btnId) {
  const headers = [...document.querySelectorAll("#tableSection thead th")]
    .map(th => th.innerText.trim())
    .join("\t");

  const rows = [...document.querySelectorAll("#tableBody tr")].map(row => {
    const cells = [...row.children].map((cell, i) => {
      let text = cell.innerText.trim();
      if (i === 3) text = `"${text}"`; // quote detection count
      return text;
    });
    return cells.join("\t");
  });

  const text = [headers, ...rows].join("\n");

  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => (btn.innerHTML = original), 1500);
  });
}

// Download Excel file
function downloadExcel() {
  fetch("/download_excel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      table_data: window._latestTable || [],
      summary: window._latestSummary || "",
    }),
  })
    .then((resp) => resp.blob())
    .then((blob) => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "IP_Info.xlsx";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      const btn = document.getElementById("downloadExcelBtn");
      btn.textContent = "Downloaded";
      btn.classList.add("downloaded");
      btn.disabled = true;

      setTimeout(() => {
        btn.innerHTML = '<i class="ph ph-download-simple"></i> Export to Excel';
        btn.classList.remove("downloaded");
        btn.disabled = false;
      }, 5000);
    })
    .catch((error) => {
      console.error("Download failed:", error);
      alert("Download failed. Please try again.");
    });
}

// Reset tool inputs and outputs
function resetTool() {
  document.getElementById("ipInput").value = "";
  document.getElementById("message").innerHTML = "";
  document.getElementById("summarySection").classList.add("hidden");
  document.getElementById("summary").innerHTML = "";
  document.getElementById("tableSection").classList.add("hidden");
  document.getElementById("tableBody").innerHTML = "";

  const downloadBtn = document.getElementById("downloadExcelBtn");
  downloadBtn.style.display = "none";
  downloadBtn.textContent = "Export to Excel";
  downloadBtn.classList.remove("downloaded");
  downloadBtn.disabled = false;

  const errorMsg = document.getElementById("errorMsg");
  errorMsg.classList.add("hidden");
  errorMsg.textContent = "";

  window._latestSummary = "";
  window._latestTable = [];
}
