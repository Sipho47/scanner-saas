const form = document.querySelector("#scan-form");
const scanButton = document.querySelector("#scan-button");
const statusMessage = document.querySelector("#status");
const results = document.querySelector("#results");

const fields = {
  statusCode: document.querySelector("#status-code"),
  reachable: document.querySelector("#reachable"),
  openPorts: document.querySelector("#open-ports"),
  issueCount: document.querySelector("#issue-count"),
  targetList: document.querySelector("#target-list"),
  headersList: document.querySelector("#headers-list"),
  sslList: document.querySelector("#ssl-list"),
  portsList: document.querySelector("#ports-list"),
  issuesList: document.querySelector("#issues-list"),
  subdomainsList: document.querySelector("#subdomains-list"),
};

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const url = formData.get("url").trim();
  const ports = formData.get("ports").trim();
  const params = new URLSearchParams({ url });

  if (ports) {
    params.set("ports", ports);
  }

  setLoading(true);
  setStatus("Scanning target...");

  try {
    const response = await fetch(`/scan?${params.toString()}`);
    const data = await response.json();

    if (data.error) {
      throw new Error(data.error);
    }

    renderResults(data);
    setStatus("Scan complete.");
  } catch (error) {
    results.hidden = true;
    setStatus(error.message || "Scan failed.", true);
  } finally {
    setLoading(false);
  }
});

function renderResults(data) {
  results.hidden = false;

  fields.statusCode.textContent = valueOrDash(data.status_code);
  fields.reachable.textContent = data.reachable ? "Yes" : "No";
  fields.openPorts.textContent = data.ports?.open?.length
    ? data.ports.open.join(", ")
    : "None";
  fields.issueCount.textContent = data.issues?.length ?? 0;

  renderDetails(fields.targetList, {
    Target: data.target,
    Hostname: data.hostname,
    "Resolved IP": data.resolved_ip,
    "Final URL": data.final_url,
    Server: data.server,
  });

  renderDetails(fields.headersList, data.security_headers || {});

  renderDetails(fields.sslList, {
    Valid: data.ssl?.valid ? "Yes" : "No",
    Expires: data.ssl?.expires_at,
    "Days left": data.ssl?.days_until_expiry,
    Issuer: data.ssl?.issuer?.organizationName || data.ssl?.issuer?.commonName,
    Subject: data.ssl?.subject?.commonName,
    Error: data.ssl?.error,
  });

  renderDetails(fields.portsList, {
    Checked: data.ports?.checked?.join(", "),
    Open: data.ports?.open?.join(", ") || "None",
    "Closed/filtered": data.ports?.closed_or_filtered?.join(", ") || "None",
  });

  renderIssues(data.issues || []);
  renderSubdomains(data.subdomains || []);
}

function renderDetails(container, details) {
  container.innerHTML = "";

  Object.entries(details).forEach(([label, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");

    term.textContent = label;
    description.textContent = valueOrDash(value);

    row.append(term, description);
    container.append(row);
  });
}

function renderIssues(issues) {
  fields.issuesList.innerHTML = "";

  if (!issues.length) {
    const item = document.createElement("li");
    item.className = "clear";
    item.textContent = "No basic issues found";
    fields.issuesList.append(item);
    return;
  }

  issues.forEach((issue) => {
    const item = document.createElement("li");
    item.className = "issue";
    item.textContent = issue;
    fields.issuesList.append(item);
  });
}

function renderSubdomains(subdomains) {
  fields.subdomainsList.innerHTML = "";

  if (!subdomains.length) {
    const item = document.createElement("li");
    item.textContent = "None found";
    fields.subdomainsList.append(item);
    return;
  }

  subdomains.forEach((subdomain) => {
    const item = document.createElement("li");
    item.textContent = `${subdomain.host} (${subdomain.ip})`;
    fields.subdomainsList.append(item);
  });
}

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  scanButton.textContent = isLoading ? "Scanning..." : "Scan";
}

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle("error", isError);
}

function valueOrDash(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  return String(value);
}
