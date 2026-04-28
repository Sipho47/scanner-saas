const form = document.querySelector("#scan-form");
const authForm = document.querySelector("#auth-form");
const scanButton = document.querySelector("#scan-button");
const loginButton = document.querySelector("#login-button");
const logoutButton = document.querySelector("#logout-button");
const registerButton = document.querySelector("#register-button");
const refreshHistoryButton = document.querySelector("#refresh-history");
const statusMessage = document.querySelector("#status");
const results = document.querySelector("#results");

let authToken = localStorage.getItem("scanner_token");
let currentUser = null;

const fields = {
  accountStatus: document.querySelector("#account-status"),
  accountPlan: document.querySelector("#account-plan"),
  statusCode: document.querySelector("#status-code"),
  reachable: document.querySelector("#reachable"),
  openPorts: document.querySelector("#open-ports"),
  issueCount: document.querySelector("#issue-count"),
  scanId: document.querySelector("#scan-id"),
  targetList: document.querySelector("#target-list"),
  headersList: document.querySelector("#headers-list"),
  sslList: document.querySelector("#ssl-list"),
  portsList: document.querySelector("#ports-list"),
  issuesList: document.querySelector("#issues-list"),
  subdomainsList: document.querySelector("#subdomains-list"),
  historyList: document.querySelector("#history-list"),
  plansList: document.querySelector("#plans-list"),
};

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await login();
});

registerButton.addEventListener("click", async () => {
  await register();
});

logoutButton.addEventListener("click", () => {
  authToken = null;
  currentUser = null;
  localStorage.removeItem("scanner_token");
  updateAccountUi();
  renderHistory([]);
  results.hidden = true;
  setStatus("Logged out.");
});

refreshHistoryButton.addEventListener("click", () => {
  loadHistory();
});

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
    const response = await authFetch(`/scan?${params.toString()}`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Scan failed.");
    }

    if (data.error) {
      throw new Error(data.error);
    }

    renderResults(data);
    setStatus("Scan complete.");
    loadHistory();
  } catch (error) {
    results.hidden = true;
    setStatus(error.message || "Scan failed.", true);
  } finally {
    setLoading(false);
  }
});

initializeAuth();
showBillingReturnStatus();

async function initializeAuth() {
  if (!authToken) {
    updateAccountUi();
    loadPlans();
    renderHistory([]);
    setStatus("Create an account or log in to start scanning.");
    return;
  }

  try {
    const response = await authFetch("/me");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Session expired.");
    }

    currentUser = data.user;
    updateAccountUi();
    loadHistory();
    loadPlans();
  } catch (error) {
    authToken = null;
    currentUser = null;
    localStorage.removeItem("scanner_token");
    updateAccountUi();
    loadPlans();
    renderHistory([]);
    setStatus("Please log in to continue.", true);
  }
}

async function login() {
  const formData = new FormData(authForm);
  const body = new URLSearchParams();
  body.set("username", formData.get("email").trim());
  body.set("password", formData.get("password"));

  setAuthButtons(true);
  setStatus("Logging in...");

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Login failed.");
    }

    setSession(data);
    setStatus("Logged in.");
    loadHistory();
    loadPlans();
  } catch (error) {
    setStatus(error.message || "Login failed.", true);
  } finally {
    setAuthButtons(false);
  }
}

async function register() {
  const formData = new FormData(authForm);
  const email = formData.get("email").trim();
  const password = formData.get("password");

  setAuthButtons(true);
  setStatus("Creating account...");

  try {
    const response = await fetch("/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Registration failed.");
    }

    setSession(data);
    setStatus("Account created.");
    loadHistory();
    loadPlans();
  } catch (error) {
    setStatus(error.message || "Registration failed.", true);
  } finally {
    setAuthButtons(false);
  }
}

function setSession(data) {
  authToken = data.access_token;
  currentUser = data.user;
  localStorage.setItem("scanner_token", authToken);
  updateAccountUi();
}

function updateAccountUi() {
  const signedIn = Boolean(currentUser);

  fields.accountStatus.textContent = signedIn
    ? currentUser.email
    : "Not signed in";
  fields.accountPlan.textContent = signedIn
    ? `${currentUser.plan} plan | ${currentUser.port_limit} ports${formatPlanExpiry(currentUser.plan_expires_at)}`
    : "Free";
  logoutButton.hidden = !signedIn;
  scanButton.disabled = !signedIn;
  refreshHistoryButton.disabled = !signedIn;
}

function renderResults(data) {
  results.hidden = false;

  fields.statusCode.textContent = valueOrDash(data.status_code);
  fields.reachable.textContent = data.reachable ? "Yes" : "No";
  fields.openPorts.textContent = data.ports?.open?.length
    ? data.ports.open.join(", ")
    : "None";
  fields.issueCount.textContent = data.issues?.length ?? 0;
  fields.scanId.textContent = valueOrDash(data.scan_id);

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

async function loadHistory() {
  if (!authToken) {
    renderHistory([]);
    return;
  }

  fields.historyList.innerHTML = `<li class="empty-history">Loading scans...</li>`;

  try {
    const response = await authFetch("/scans?limit=10");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Could not load history.");
    }

    renderHistory(data.scans || []);
  } catch (error) {
    fields.historyList.innerHTML = `<li class="empty-history">Could not load history.</li>`;
  }
}

async function loadPlans() {
  fields.plansList.innerHTML = `<p class="empty-history">Loading plans...</p>`;

  try {
    const response = await fetch("/billing/plans");
    const data = await response.json();
    renderPlans(data.plans || []);
  } catch (error) {
    fields.plansList.innerHTML = `<p class="empty-history">Could not load plans.</p>`;
  }
}

function renderPlans(plans) {
  fields.plansList.innerHTML = "";

  plans.forEach((plan) => {
    const card = document.createElement("article");
    const name = document.createElement("h3");
    const price = document.createElement("strong");
    const details = document.createElement("p");
    const button = document.createElement("button");

    card.className = "plan-card";
    name.textContent = plan.name;
    price.textContent = plan.price;
    details.textContent = `${plan.scan_limit.toLocaleString()} scans per month`;

    button.type = "button";
    button.className = plan.paid ? "" : "secondary-button";
    button.textContent = plan.paid ? "Start checkout" : "Current starter plan";
    button.disabled = !plan.paid;

    if (plan.paid) {
      button.addEventListener("click", () => startCheckout(plan.id, button));
    }

    if (plan.paid && !plan.configured) {
      const note = document.createElement("span");
      note.className = "plan-note";
      note.textContent = "Stripe price ID not configured yet";
      card.append(name, price, details, button, note);
    } else {
      card.append(name, price, details, button);
    }

    fields.plansList.append(card);
  });
}

async function startCheckout(planId, button) {
  if (!authToken) {
    setStatus("Log in before upgrading your plan.", true);
    return;
  }

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Opening Stripe...";
  setStatus("Creating checkout session...");

  try {
    const response = await authFetch("/billing/create-checkout-session", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ plan_id: planId }),
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Could not create checkout session.");
    }

    window.location.href = data.checkout_url;
  } catch (error) {
    setStatus(error.message || "Checkout failed.", true);
    button.disabled = false;
    button.textContent = originalText;
  }
}

function renderHistory(scans) {
  fields.historyList.innerHTML = "";

  if (!scans.length) {
    fields.historyList.innerHTML = `<li class="empty-history">No scans saved yet.</li>`;
    return;
  }

  scans.forEach((scan) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    const title = document.createElement("strong");
    const meta = document.createElement("span");

    button.type = "button";
    button.className = "history-item";
    title.textContent = scan.target;
    meta.textContent = `#${scan.id} | ${scan.status_code || "-"} | ${scan.issue_count} issues | ${formatDate(scan.created_at)}`;

    button.append(title, meta);
    button.addEventListener("click", () => loadSavedScan(scan.id));
    item.append(button);
    fields.historyList.append(item);
  });
}

async function loadSavedScan(scanId) {
  setStatus(`Loading saved scan #${scanId}...`);

  try {
    const response = await authFetch(`/scans/${scanId}`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Saved scan not found.");
    }

    renderResults({
      ...data.result,
      scan_id: data.id,
      created_at: data.created_at,
    });
    setStatus(`Loaded saved scan #${scanId}.`);
  } catch (error) {
    setStatus(error.message || "Could not load saved scan.", true);
  }
}

function authFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});

  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }

  return fetch(url, {
    ...options,
    headers,
  });
}

function setAuthButtons(isLoading) {
  loginButton.disabled = isLoading;
  registerButton.disabled = isLoading;
  loginButton.textContent = isLoading ? "Please wait..." : "Log in";
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

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function formatPlanExpiry(value) {
  if (!value) {
    return "";
  }

  return ` | expires ${formatDate(value)}`;
}

function showBillingReturnStatus() {
  const params = new URLSearchParams(window.location.search);
  const billingStatus = params.get("billing");

  if (billingStatus === "success") {
    setStatus("Payment completed. Your subscription webhook will finish account updates.");
  }

  if (billingStatus === "cancel") {
    setStatus("Checkout canceled. No payment was taken.");
  }
}
