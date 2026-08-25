function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.').map(Number);

    if (
      parts.every(
        octet => octet >= 0 && octet <= 255
      )
    ) {
      return (
        ipaddr.isValid(ip) &&
        ipaddr.parse(ip).kind() === 'ipv4'
      );
    }

    return false;
  }

  if (ipaddr.isValid(ip)) {
    return (
      ipaddr.parse(ip).kind() === 'ipv6'
    );
  }

  return false;
}


function isValidHash(str) {
  const s = str.toLowerCase();

  return (
    /^[a-f0-9]{32}$/.test(s) ||
    /^[a-f0-9]{40}$/.test(s) ||
    /^[a-f0-9]{64}$/.test(s)
  );
}


function isPrivateIP(ip) {

  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(isNaN)
  ) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}


function isValidURL(str) {

  try {

    const url = new URL(
      str.startsWith("http")
        ? str
        : `http://${str}`
    );

    const hostname = url.hostname;

    if (
      /^\d{1,3}(\.\d{1,3}){1,2}$/.test(
        hostname
      )
    ) {
      return false;
    }

    if (
      !hostname.includes(".") ||
      !/[a-zA-Z]{2,}$/.test(
        hostname.split(".").pop()
      )
    ) {
      return false;
    }

    return true;

  } catch {

    return false;
  }
}


// =========================
// API KEY INPUT HELPERS
// =========================

function getApiKeyValue(ids) {

  for (const id of ids) {

    const element =
      document.getElementById(id);

    if (element) {

      return element.value.trim();
    }
  }

  return "";
}


function getUserApiKeys() {

  return {

    vt_api_key: getApiKeyValue([
      "vtApiKey",
      "vt_api_key",
      "virustotalApiKey",
      "virustotal_api_key"
    ]),

    apivoid_api_key: getApiKeyValue([
      "apivoidApiKey",
      "apivoid_api_key",
      "apiVoidApiKey",
      "apiVoid_api_key"
    ]),

    abuseipdb_api_key: getApiKeyValue([
      "abuseipdbApiKey",
      "abuseipdb_api_key",
      "abuseApiKey",
      "abuse_api_key"
    ])
  };
}


// =========================
// USER API KEY POPUP
// =========================
//
// This popup is shown ONLY when
// the user actually entered a custom
// API key and that key was rejected.
//
// No popup is shown when the user
// leaves the API key fields empty.
// =========================

function showInvalidApiKeyPopup(
  invalidKeys
) {

  if (
    !Array.isArray(invalidKeys) ||
    invalidKeys.length === 0
  ) {
    return Promise.resolve(
      "continue"
    );
  }

  return new Promise(resolve => {

    const existing =
      document.getElementById(
        "invalidApiKeyPopup"
      );

    if (existing) {
      existing.remove();
    }

    const services =
      invalidKeys
        .map(item => item.service)
        .filter(
          (value, index, array) =>
            array.indexOf(value) === index
        )
        .join(", ");

    const overlay =
      document.createElement("div");

    overlay.id =
      "invalidApiKeyPopup";

    overlay.style.position =
      "fixed";

    overlay.style.inset = "0";

    overlay.style.background =
      "rgba(0, 0, 0, 0.70)";

    overlay.style.display =
      "flex";

    overlay.style.alignItems =
      "center";

    overlay.style.justifyContent =
      "center";

    overlay.style.zIndex =
      "99999";

    const popup =
      document.createElement("div");

    popup.style.width =
      "min(500px, 90%)";

    popup.style.padding =
      "24px";

    popup.style.borderRadius =
      "12px";

    popup.style.background =
      "#111827";

    popup.style.color =
      "#ffffff";

    popup.style.boxShadow =
      "0 20px 50px rgba(0,0,0,0.5)";

    popup.innerHTML = `
      <h3 style="
        margin:0 0 12px;
        font-size:20px;
        font-weight:700;
      ">
        ⚠️ API Key Rejected
      </h3>

      <p style="
        margin-bottom:12px;
        line-height:1.5;
      ">
        The API key entered for
        <strong>${services}</strong>
        was rejected by the service.
      </p>

      <p style="
        margin-bottom:20px;
        line-height:1.5;
      ">
        Would you like to continue using
        the existing API keys configured
        in the system?
      </p>

      <div style="
        display:flex;
        gap:10px;
        justify-content:flex-end;
        flex-wrap:wrap;
      ">

        <button
          id="apiKeyUseExistingBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:none;
            cursor:pointer;
            background:#2563eb;
            color:white;
            font-weight:600;
          "
        >
          Use Existing Keys
        </button>

        <button
          id="apiKeyEnterNewBtn"
          style="
            padding:10px 16px;
            border-radius:8px;
            border:none;
            cursor:pointer;
            background:#7c3aed;
            color:white;
            font-weight:600;
          "
        >
          Enter Another Key
        </button>

      </div>
    `;

    overlay.appendChild(popup);

    document.body.appendChild(
      overlay
    );

    document
      .getElementById(
        "apiKeyUseExistingBtn"
      )
      .addEventListener(
        "click",
        () => {

          overlay.remove();

          resolve(
            "continue"
          );
        }
      );

    document
      .getElementById(
        "apiKeyEnterNewBtn"
      )
      .addEventListener(
        "click",
        () => {

          overlay.remove();

          resolve(
            "replace"
          );
        }
      );

  });
}


// =========================
// FETCH IP DATA
// =========================

async function fetchIPData() {

  const inputField =
    document.getElementById(
      "ipInput"
    );

  const lookupButton =
    document.getElementById(
      "lookupButton"
    );

  const summaryDiv =
    document.getElementById(
      "summary"
    );

  const tableBody =
    document.getElementById(
      "tableBody"
    );

  const summarySection =
    document.getElementById(
      "summarySection"
    );

  const tableSection =
    document.getElementById(
      "tableSection"
    );

  const errorMsg =
    document.getElementById(
      "errorMsg"
    );

  const messageDiv =
    document.getElementById(
      "message"
    );

  const messageBlock =
    document.getElementById(
      "messageBlock"
    );

  const downloadBtn =
    document.getElementById(
      "downloadExcelBtn"
    );


  errorMsg.classList.add(
    "hidden"
  );

  summarySection.classList.add(
    "hidden"
  );

  tableSection.classList.add(
    "hidden"
  );

  summaryDiv.textContent =
    "";

  tableBody.innerHTML =
    "";

  downloadBtn.style.display =
    "none";

  messageDiv.innerHTML =
    "";

  messageBlock.classList.remove(
    "show",
    "hidden"
  );


  let rawEntries =
    inputField.value
      .split(/[\s,\n]+/)
      .map(e => e.trim())
      .filter(
        e => e.length > 0
      );


  const seen =
    new Set();

  const validIPs =
    [];

  const validURLs =
    [];

  const validHashes =
    [];

  const skippedInvalid =
    [];

  const duplicates =
    [];


  for (
    const entry of rawEntries
  ) {

    if (
      seen.has(entry)
    ) {

      duplicates.push(
        entry
      );

      continue;
    }

    seen.add(
      entry
    );


    if (
      isValidIP(entry)
    ) {

      if (
        !isPrivateIP(entry)
      ) {

        validIPs.push(
          entry
        );
      }

    } else if (
      isValidURL(entry)
    ) {

      validURLs.push(
        entry
      );

    } else if (
      isValidHash(entry)
    ) {

      validHashes.push(
        entry
      );

    } else {

      skippedInvalid.push(
        entry
      );
    }
  }


  let validEntries = [
    ...validIPs,
    ...validURLs,
    ...validHashes
  ];


  const messages =
    [];


  if (
    validEntries.length === 0
  ) {

    errorMsg.textContent =
      "⚠️ No valid public IPs, URLs or Hashes found.";

    errorMsg.classList.remove(
      "hidden"
    );

    return;
  }


  if (
    skippedInvalid.length > 0
  ) {

    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        skippedInvalid.length
      } Invalid entr${
        skippedInvalid.length !== 1
          ? "ies"
          : "y"
      } skipped</span> : ${
        skippedInvalid.join(", ")
      }`
    );
  }


  if (
    duplicates.length > 0
  ) {

    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        duplicates.length
      } Duplicate${
        duplicates.length !== 1
          ? "s"
          : ""
      } removed</span>: ${
        duplicates.join(", ")
      }`
    );
  }


  const privateIPs =
    rawEntries.filter(
      ip =>
        isValidIP(ip) &&
        isPrivateIP(ip)
    );


  if (
    privateIPs.length > 0
  ) {

    messages.push(
      `⚠️ <span class="text-red-400 font-bold glow-red">${
        privateIPs.length
      } Private/reserved IP${
        privateIPs.length !== 1
          ? "s"
          : ""
      } filtered </span>: ${
        privateIPs.join(", ")
      }`
    );
  }


  if (
    validEntries.length > 100
  ) {

    messages.push(
      `⚠️ You entered <span class="text-green-400 font-bold">${
        validEntries.length
      }</span> valid entries. Only the first 100 will be processed.`
    );

    messages.push(
      `⚠️ <span class="text-purple-400 font-bold">${
        validEntries.length - 100
      } entries skipped</span>: ${
        validEntries
          .slice(100)
          .join(", ")
      }`
    );

    validEntries =
      validEntries.slice(
        0,
        100
      );
  }


  lookupButton.disabled =
    true;

  lookupButton.textContent =
    "Fetching...";


  // =========================
  // GET USER API KEYS
  // =========================

  const userApiKeys =
    getUserApiKeys();


  // =========================
  // REQUEST FUNCTION
  // =========================

  async function performLookup(
    apiKeys
  ) {

    const response =
      await fetch(
        "/get_ip_info",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({

            ips:
              validEntries,

            vt_api_key:
              apiKeys.vt_api_key,

            apivoid_api_key:
              apiKeys.apivoid_api_key,

            abuseipdb_api_key:
              apiKeys.abuseipdb_api_key
          })
        }
      );


    if (
      !response.ok
    ) {

      const error =
        await response
          .json()
          .catch(
            () => ({})
          );

      throw new Error(
        error.error ||
        "Server error occurred."
      );
    }


    return response.json();
  }


  try {

    let data =
      await performLookup(
        userApiKeys
      );


    // =========================
    // INVALID USER KEY
    // =========================
    //
    // Popup is shown ONLY when
    // the user actually entered
    // a key.
    // =========================

    if (
      Array.isArray(
        data.invalid_user_keys
      ) &&
      data.invalid_user_keys.length > 0
    ) {

      const choice =
        await showInvalidApiKeyPopup(
          data.invalid_user_keys
        );


      if (
        choice === "continue"
      ) {

        // Remove user supplied keys
        // and run the request again
        // using only the existing
        // system keys.

        data =
          await performLookup({

            vt_api_key:
              "",

            apivoid_api_key:
              "",

            abuseipdb_api_key:
              ""
          });

      } else {

        // User chose to enter
        // another key.

        const services =
          data.invalid_user_keys
            .map(
              item =>
                item.service
            )
            .filter(
              (value, index, array) =>
                array.indexOf(value) === index
            );


        for (
          const service of services
        ) {

          let newKey =
            prompt(
              `Enter another ${service} API key:`
            );


          if (
            newKey &&
            newKey.trim()
          ) {

            if (
              service === "VirusTotal"
            ) {

              userApiKeys.vt_api_key =
                newKey.trim();

            } else if (
              service === "APIVoid"
            ) {

              userApiKeys.apivoid_api_key =
                newKey.trim();

            } else if (
              service === "AbuseIPDB"
            ) {

              userApiKeys.abuseipdb_api_key =
                newKey.trim();
            }
          }
        }


        data =
          await performLookup(
            userApiKeys
          );
      }
    }


    const processedCount =
      data.raw_table?.length ||
      0;


    summaryDiv.innerHTML =
      data.summary;


    if (
      Array.isArray(
        data.exhausted_messages
      ) &&
      data.exhausted_messages.length > 0
    ) {

      data.exhausted_messages
        .forEach(
          msg => {

            messages.push(
              `<div class="font-medium mb-3 text-red-600">${msg}</div>`
            );
          }
        );
    }


    if (
      Array.isArray(
        data.no_data_ips
      ) &&
      data.no_data_ips.length > 0
    ) {

      const displayList =
        data.no_data_ips
          .slice(0, 5)
          .join(", ");

      const more =
        data.no_data_ips.length > 5
          ? ` and ${
              data.no_data_ips.length - 5
            } more...`
          : "";


      messages.push(
        `⚠️ ${
          data.no_data_ips.length
        } entr${
          data.no_data_ips.length !== 1
            ? "ies"
            : "y"
        } returned no fields: ${
          displayList
        }${more}`
      );
    }


    // =========================
    // USER KEY SUMMARY
    // =========================

    if (
      Array.isArray(
        data.user_key_messages
      ) &&
      data.user_key_messages.length > 0
    ) {

      data.user_key_messages
        .forEach(
          msg => {

            messages.push(
              `<div class="font-medium mb-3 text-blue-400">${msg}</div>`
            );
          }
        );
    }


    const entryMsg =
      `✅ Data found for <span class="text-green-400 font-bold">${
        processedCount
      } entr${
        processedCount !== 1
          ? "ies"
          : "y"
      }</span> in <span class="text-blue-400 font-bold">${
        data.elapsed
      } second${
        data.elapsed !== 1
          ? "s"
          : ""
      }</span>.`;


    const serviceList =
      Array.isArray(
        data.services_used
      )
        ? data.services_used
        : [];


    const serviceMsg =
      `🔧 Service${
        serviceList.length !== 1
          ? "s"
          : ""
      } used: <span class="text-purple-400 font-bold">${
        serviceList.join(", ") ||
        "None"
      }</span>`;


    messages.unshift(
      serviceMsg
    );

    messages.unshift(
      entryMsg
    );


    // =========================
    // TABLE HEADER
    // =========================

    const tableHead =
      document.getElementById(
        "tableHead"
      );

    tableHead.innerHTML =
      "";

    const headerRow =
      document.createElement(
        "tr"
      );


    let headerTitles = [

      "IP/URL/HASH",

      "ISP",

      "Country",

      "VT Detection Count",

      "APIVoid Risk Score",

      "APIVoid Detections Count",

      "AbuseIPDB Confidence Score(%)",

      "AbuseIPDB Report Count",

      // "Threat Actor",
      // "Country Of Origin",
      // "Target Sector",
      // "Threat Category",
      // "Campaign Name",
      // "Malware Families"

    ];


    for (
      const title of headerTitles
    ) {

      const th =
        document.createElement(
          "th"
        );

      th.innerText =
        title;

      th.className =
        "border px-3 py-2 text-center";

      headerRow.appendChild(
        th
      );
    }


    tableHead.appendChild(
      headerRow
    );


    // =========================
    // TABLE BODY
    // =========================

    tableBody.innerHTML =
      "";


    // IMPORTANT:
    // Backend now returns the
    // rows in the exact input order.

    for (
      const row of
      data.raw_table || []
    ) {

      const [

        inputValue,

        isp,

        country,

        detections,

        apivoidRiskScore,

        apivoidBlacklistDetections,

        abuseipdbConfidenceRaw,

        abuseipdbReportCountRaw,

        // threatActorRaw,
        // countryOriginRaw,
        // targetSectorRaw,
        // threatCategoryRaw,
        // campaignNameRaw,
        // malwareFamiliesRaw,

      ] = row;


      function formatField(
        field
      ) {

        if (
          field === null ||
          field === undefined ||
          field === ""
        ) {

          return "-";
        }

        if (
          Array.isArray(field)
        ) {

          return field.length
            ? field.join(", ")
            : "-";
        }

        return field.toString();
      }


      let cells = [

        inputValue,

        formatField(isp),

        formatField(country),

        formatField(
          detections
        ),

        formatField(
          apivoidRiskScore
        ),

        formatField(
          apivoidBlacklistDetections
        ),

        formatField(
          abuseipdbConfidenceRaw
        ),

        formatField(
          abuseipdbReportCountRaw
        ),

        // formatField(threatActorRaw),
        // formatField(countryOriginRaw),
        // formatField(targetSectorRaw),
        // formatField(threatCategoryRaw),
        // formatField(campaignNameRaw),
        // formatField(malwareFamiliesRaw)

      ];


      const tr =
        document.createElement(
          "tr"
        );


      for (
        const cell of cells
      ) {

        const td =
          document.createElement(
            "td"
          );

        td.innerText =
          cell;

        td.className =
          "border px-3 py-1 text-center";

        tr.appendChild(
          td
        );
      }


      tableBody.appendChild(
        tr
      );
    }


    summarySection.classList.remove(
      "hidden"
    );

    tableSection.classList.remove(
      "hidden"
    );

    messageBlock.style.display =
      "block";


    messageDiv.innerHTML =
      messages
        .map(
          m =>
            `<div class="font-medium mb-3">${m}</div>`
        )
        .join("");


    requestAnimationFrame(
      () => {

        summarySection.classList.add(
          "show"
        );

        tableSection.classList.add(
          "show"
        );

        messageBlock.classList.add(
          "show"
        );
      }
    );


    downloadBtn.style.display =
      "inline-block";


    document
      .getElementById(
        "resetContainer"
      )
      .classList.remove(
        "hidden"
      );


    window._latestSummary =
      data.summary;

    window._latestTable =
      data.raw_table;

    window._columnLabel =
      data.column_label ||
      "IP";


  } catch (err) {

    console.error(
      "Error:",
      err
    );

    alert(
      "❌ Error retrieving data:\n" +
      err.message
    );

  } finally {

    lookupButton.disabled =
      false;

    lookupButton.textContent =
      "Get Info";
  }
}


// =========================
// Copy summary to clipboard
// =========================

function copyToClipboard(
  elementId,
  btnId
) {

  const text =
    document.getElementById(
      elementId
    ).innerHTML;


  navigator.clipboard
    .writeText(text)
    .then(
      () => {

        const btn =
          document.getElementById(
            btnId
          );

        const original =
          btn.innerHTML;


        btn.innerHTML =
          '<i class="ph ph-check"></i> Copied!';


        setTimeout(
          () =>
            (
              btn.innerHTML =
                original
            ),
          1500
        );
      }
    );
}


// =========================
// Copy table to clipboard
// =========================

function copyTableToClipboard(
  btnId
) {

  const headers =
    [
      ...document.querySelectorAll(
        "#tableSection thead th"
      )
    ]
      .map(
        th =>
          th.innerText.trim()
      )
      .join("\t");


  const rows =
    [
      ...document.querySelectorAll(
        "#tableBody tr"
      )
    ]
      .map(
        row => {

          const cells =
            [
              ...row.children
            ]
              .map(
                (cell, i) => {

                  let text =
                    cell.innerText.trim();

                  if (
                    i === 3
                  ) {

                    text =
                      `"${text}"`;
                  }

                  return text;
                }
              );

          return cells.join(
            "\t"
          );
        }
      );


  const text =
    [
      headers,
      ...rows
    ].join("\n");


  navigator.clipboard
    .writeText(text)
    .then(
      () => {

        const btn =
          document.getElementById(
            btnId
          );

        const original =
          btn.innerHTML;


        btn.innerHTML =
          '<i class="ph ph-check"></i> Copied!';


        setTimeout(
          () =>
            (
              btn.innerHTML =
                original
            ),
          1500
        );
      }
    );
}


// =========================
// Download Excel file
// =========================

function downloadExcel() {

  //const clientName = document.getElementById("clientName").value.trim();

  fetch(
    "/download_excel",
    {

      method: "POST",

      headers: {
        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({

        table_data:
          window._latestTable ||
          [],

        summary:
          window._latestSummary ||
          "",

        column_label:
          window._columnLabel ||
          "IP",

        //client_name: clientName || "N/A"
      })
    }
  )

  .then(
    resp =>
      resp.blob()
  )

  .then(
    blob => {

      const url =
        window.URL.createObjectURL(
          blob
        );

      const a =
        document.createElement(
          "a"
        );

      a.href =
        url;

      a.download =
        "IP_Info.xlsx";

      document.body.appendChild(
        a
      );

      a.click();

      a.remove();

      window.URL.revokeObjectURL(
        url
      );


      const btn =
        document.getElementById(
          "downloadExcelBtn"
        );


      btn.textContent =
        "Downloaded";

      btn.classList.add(
        "downloaded"
      );

      btn.disabled =
        true;


      setTimeout(
        () => {

          btn.innerHTML =
            '<i class="ph ph-download-simple"></i> Export to Excel';

          btn.classList.remove(
            "downloaded"
          );

          btn.disabled =
            false;

        },
        5000
      );
    }
  )

  .catch(
    error => {

      console.error(
        "Download failed:",
        error
      );

      alert(
        "Download failed. Please try again."
      );
    }
  );
}


// =========================
// Reset tool
// =========================

function resetTool() {

  document.getElementById(
    "ipInput"
  ).value = "";


  document.getElementById(
    "message"
  ).innerHTML = "";


  const messageBlock =
    document.getElementById(
      "messageBlock"
    );


  if (
    messageBlock
  ) {

    messageBlock.classList.remove(
      "show"
    );

    messageBlock.classList.add(
      "hidden"
    );

    messageBlock.style.display =
      "none";
  }


  document.getElementById(
    "errorMsg"
  ).classList.add(
    "hidden"
  );


  document.getElementById(
    "summarySection"
  ).classList.add(
    "hidden"
  );


  document.getElementById(
    "tableSection"
  ).classList.add(
    "hidden"
  );


  document.getElementById(
    "summary"
  ).innerHTML = "";


  document.getElementById(
    "tableBody"
  ).innerHTML = "";


  document.getElementById(
    "downloadExcelBtn"
  ).style.display =
    "none";


  document.getElementById(
    "resetContainer"
  ).classList.add(
    "hidden"
  );
}


// =========================
// Theme toggle
// =========================

const toggleThemeBtn =
  document.getElementById(
    "toggleTheme"
  );


window.addEventListener(
  "DOMContentLoaded",
  () => {

    const savedTheme =
      localStorage.getItem(
        "theme"
      );


    if (
      savedTheme === "light"
    ) {

      document.body.classList.add(
        "light-mode"
      );

      toggleThemeBtn.innerHTML =
        '<i class="ph ph-moon"></i>';

    } else {

      document.body.classList.remove(
        "light-mode"
      );

      toggleThemeBtn.innerHTML =
        '<i class="ph ph-sun"></i>';
    }
  }
);


toggleThemeBtn.addEventListener(
  "click",
  () => {

    document.body.classList.toggle(
      "light-mode"
    );

    const isLight =
      document.body.classList.contains(
        "light-mode"
      );


    toggleThemeBtn.innerHTML =
      isLight
        ? '<i class="ph ph-moon"></i>'
        : '<i class="ph ph-sun"></i>';


    localStorage.setItem(
      "theme",
      isLight
        ? "light"
        : "dark"
    );
  }
);