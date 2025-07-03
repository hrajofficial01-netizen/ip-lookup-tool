function isValidIP(ip) {
  const ipv4 = /^\b(\d{1,3}\.){3}\d{1,3}\b$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

function isPrivateIP(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false; // Not IPv4, skip (or add IPv6 check if needed)
  const [a, b] = parts.map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;  // loopback
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

async function fetchIPData() {
  const input = document.getElementById('ipInput').value;
  const ipList = input.split(/[\n,\s]+/).map(ip => ip.trim()).filter(ip => ip.length > 0);
  const validIps = ipList.filter(ip => isValidIP(ip));
  
  // Filter out private IPs here
  const publicIps = validIps.filter(ip => !isPrivateIP(ip));

  const errorMsg = document.getElementById('errorMsg');
  if (publicIps.length === 0) {
    errorMsg.classList.remove('hidden');
    errorMsg.textContent = 'No valid public IPs to lookup.';
    return;
  } else {
    errorMsg.classList.add('hidden');
  }

  document.getElementById('spinner').classList.remove('hidden');
  document.getElementById('summarySection').classList.add('hidden');
  document.getElementById('tableSection').classList.add('hidden');

  const response = await fetch('/get_ip_info', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips: publicIps })
  });

  const result = await response.json();
  document.getElementById('summary').textContent = result.summary;
  document.getElementById('tableBody').innerHTML = result.table;
  window._latestTable = result.raw_table;
  window._latestSummary = result.summary;
  document.getElementById('downloadExcelBtn').classList.remove('hidden');

  document.getElementById('spinner').classList.add('hidden');
  document.getElementById('summarySection').classList.remove('hidden');
  document.getElementById('tableSection').classList.remove('hidden');
}


function copyToClipboard(elementId, btnId) {
  const text = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => btn.innerHTML = original, 1500);
  });
}

function copyTableToClipboard(btnId) {
  const headers = [...document.querySelectorAll('#tableSection thead th')]
    .map(th => th.innerText.trim())
    .join('\t');

  const rows = [...document.querySelectorAll('#tableBody tr')].map(row => {
    const cells = [...row.children].map((cell, i) => {
      let text = cell.innerText.trim();
      // Wrap detection count (last column) with quotes to prevent Excel date autoformat
      if (i === 3) text = `"${text}"`;
      return text;
    });
    return cells.join('\t');
  });

  const text = [headers, ...rows].join('\n');

  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => btn.innerHTML = original, 1500);
  });
}
function downloadExcel() {
  fetch('/download_excel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      table_data: window._latestTable || [],
      summary: window._latestSummary || ''
    })
  })
  .then(resp => resp.blob())
  .then(blob => {
    // Trigger download
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'IP_Info.xlsx';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    // Update button UI
    const btn = document.getElementById('downloadExcelBtn');
    btn.textContent = 'Downloaded';
    btn.classList.add('downloaded');
    btn.disabled = true;

    // Optional: reset button after 5 seconds
   setTimeout(() => {
  btn.innerHTML = '<i class="ph ph-download-simple"></i> Export to Excel';
  btn.classList.remove('downloaded');
  btn.disabled = false;
}, 5000);

  })
  .catch(error => {
    console.error('Download failed:', error);
    alert('Download failed. Please try again.');
  });
}
function resetTool() {
  // Clear the IP input
  document.getElementById('ipInput').value = '';

  // Hide error message
  document.getElementById('errorMsg').classList.add('hidden');

  // Hide and clear summary section
  const summarySection = document.getElementById('summarySection');
  summarySection.classList.add('hidden');
  document.getElementById('summary').innerHTML = '';

  // Hide and clear table section
  const tableSection = document.getElementById('tableSection');
  tableSection.classList.add('hidden');
  document.getElementById('tableBody').innerHTML = '';

  // Reset the download button
  const downloadBtn = document.getElementById('downloadExcelBtn');
  downloadBtn.classList.add('hidden');
  downloadBtn.textContent = 'Export to Excel';
  downloadBtn.classList.remove('downloaded');
  downloadBtn.disabled = false;

  // Clear globally stored data
  window._latestSummary = '';
  window._latestTable = [];
}
