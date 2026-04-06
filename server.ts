// timelock - TEE-backed time-lock encryption demo
// The enclave holds decryption keys and only releases them after a specified time.
// Client-side encryption using Web Crypto API. TEE attestation proves time enforcement.

interface SealedMessage {
  id: string;
  ciphertext: string;       // base64 encrypted message
  iv: string;              // base64 IV
  releaseTime: number;     // unix timestamp ms
  createdAt: number;
}

interface StoredSecret {
  id: string;
  key: string;             // base64 AES key
  iv: string;
  ciphertext: string;
  releaseTime: number;
  createdAt: number;
}


// Trusted time: fetch from multiple time servers, use median
interface TimeSource {
  name: string;
  url: string;
  parse: (data: string) => number | null;
}

const TIME_SOURCES: TimeSource[] = [
  {
    name: "timeapi.io",
    url: "https://timeapi.io/api/time/current/zone?timeZone=UTC",
    parse: (d) => { try { const j = JSON.parse(d); return new Date(j.dateTime + "Z").getTime(); } catch { return null; } },
  },
  {
    name: "worldtimeapi",
    url: "http://worldtimeapi.org/api/timezone/Etc/UTC",
    parse: (d) => { try { return Math.round(new Date(JSON.parse(d).utc_datetime).getTime()); } catch { return null; } },
  },
];

let cachedTime: number | null = null;
let cacheExpiry = 0;
const TIME_CACHE_MS = 5_000; // refresh every 5s

async function trustedNow(): Promise<number> {
  if (cachedTime && Date.now() < cacheExpiry) return cachedTime;

  const results: number[] = [];
  const errors: string[] = [];

  const promises = TIME_SOURCES.map(async (src) => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2_000);
      const resp = await fetch(src.url, { signal: controller.signal });
      clearTimeout(timeout);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      const t = src.parse(text);
      if (t && t > 1_000_000_000_000) { // sanity: after year 2001 in ms
        results.push(t);
      }
    } catch (e: any) {
      errors.push(`${src.name}: ${e.message}`);
    }
  });

  await Promise.allSettled(promises);

  if (results.length === 0) {
    console.error("All time sources failed:", errors.join("; "));
    // Fallback to system clock (less trustworthy)
    return Date.now();
  }

  // Use median for robustness
  results.sort((a, b) => a - b);
  const median = results[Math.floor(results.length / 2)];
  cachedTime = median;
  cacheExpiry = Date.now() + TIME_CACHE_MS;

  if (results.length > 1) {
    const skew = Math.abs(results[0] - results[results.length - 1]);
    if (skew > 10_000) {
      console.warn(`Time source skew: ${skew}ms across ${results.length} sources`, errors);
    }
  }

  return median;
}

// In-memory store (demo only - would use persistent storage in production)
const vault = new Map<string, StoredSecret>();

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of vault) {
    if (now - s.createdAt > 24 * 60 * 60 * 1000) vault.delete(id);
  }
}, 5 * 60_000);

function genId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function checkAuth(req: Request): boolean {
  const token = Deno.env.get("TIMLOCK_TOKEN") || "";
  if (!token) return true;
  return req.headers.get("authorization") === "Bearer " + token;
}

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TEE Time-Lock Encryption</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #f8f7f4;
    color: #2c2c2c;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem 1rem;
  }
  .container { max-width: 640px; width: 100%; }
  h1 {
    font-size: 1.6rem;
    font-weight: 600;
    margin-bottom: 0.3rem;
    color: #1a1a1a;
  }
  .subtitle {
    font-size: 0.9rem;
    color: #888;
    margin-bottom: 2rem;
    line-height: 1.5;
  }
  .subtitle strong { color: #059669; }
  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 1.5rem;
    border-bottom: 2px solid #e5e5e0;
  }
  .tab {
    padding: 0.7rem 1.5rem;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
    color: #888;
    border: none;
    background: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: all 0.2s;
  }
  .tab:hover { color: #333; }
  .tab.active {
    color: #059669;
    border-bottom-color: #059669;
  }
  .panel { display: none; }
  .panel.active { display: block; }
  label {
    display: block;
    font-size: 0.8rem;
    font-weight: 600;
    color: #666;
    margin-bottom: 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  textarea, input, select {
    width: 100%;
    padding: 0.7rem 0.9rem;
    border: 1.5px solid #d4d4cf;
    border-radius: 8px;
    font-size: 0.95rem;
    font-family: inherit;
    background: white;
    color: #2c2c2c;
    margin-bottom: 1rem;
    transition: border-color 0.2s;
  }
  textarea { min-height: 100px; resize: vertical; }
  textarea:focus, input:focus, select:focus {
    outline: none;
    border-color: #059669;
  }
  .row { display: flex; gap: 1rem; }
  .row > * { flex: 1; }
  button {
    width: 100%;
    padding: 0.75rem;
    border: none;
    border-radius: 8px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-primary {
    background: #059669;
    color: white;
  }
  .btn-primary:hover { background: #047857; }
  .btn-primary:disabled { background: #a7f3d0; cursor: not-allowed; }
  .btn-secondary {
    background: white;
    color: #2c2c2c;
    border: 1.5px solid #d4d4cf;
  }
  .btn-secondary:hover { border-color: #999; }
  .output {
    margin-top: 1rem;
    padding: 1rem;
    background: white;
    border: 1.5px solid #e5e5e0;
    border-radius: 8px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.82rem;
    word-break: break-all;
    line-height: 1.6;
    display: none;
  }
  .output.show { display: block; }
  .output .label {
    font-family: -apple-system, sans-serif;
    font-size: 0.75rem;
    font-weight: 600;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.3rem;
  }
  .copy-btn {
    display: inline-block;
    margin-top: 0.5rem;
    padding: 0.3rem 0.8rem;
    font-size: 0.78rem;
    background: #f0f0ec;
    border: 1px solid #d4d4cf;
    border-radius: 4px;
    cursor: pointer;
  }
  .copy-btn:hover { background: #e5e5e0; }
  .countdown {
    text-align: center;
    padding: 1.5rem;
    background: white;
    border: 1.5px solid #e5e5e0;
    border-radius: 8px;
    margin-top: 1rem;
    display: none;
  }
  .countdown.show { display: block; }
  .countdown .time {
    font-size: 2rem;
    font-weight: 700;
    color: #059669;
    font-variant-numeric: tabular-nums;
  }
  .countdown .hint { font-size: 0.8rem; color: #888; margin-top: 0.3rem; }
  .attestation {
    margin-top: 2rem;
    padding: 0.8rem 1rem;
    background: #fefce8;
    border: 1px solid #fde68a;
    border-radius: 8px;
    font-size: 0.8rem;
    color: #92400e;
  }
  .attestation strong { color: #78350f; }
  .decrypt-result {
    margin-top: 1rem;
    padding: 1rem;
    background: #ecfdf5;
    border: 1.5px solid #a7f3d0;
    border-radius: 8px;
    font-size: 1rem;
    line-height: 1.6;
    display: none;
  }
  .decrypt-result.show { display: block; }
  .error {
    color: #dc2626;
    font-size: 0.85rem;
    margin-top: 0.3rem;
    display: none;
  }
  .error.show { display: block; }
  .how-it-works {
    margin-top: 2rem;
    padding: 1.2rem;
    background: white;
    border: 1.5px solid #e5e5e0;
    border-radius: 8px;
  }
  .how-it-works h3 { font-size: 0.9rem; margin-bottom: 0.6rem; }
  .how-it-works ol {
    padding-left: 1.2rem;
    font-size: 0.82rem;
    color: #555;
    line-height: 1.8;
  }
</style>
</head>
<body>
<div class="container">
  <h1>Time-Lock Encryption</h1>
  <p class="subtitle">
    Encrypt a message that can only be decrypted after a chosen time.
    <strong>The TEE enclave holds the key</strong> and attests it won't release it early.
  </p>

  <div class="tabs">
    <button class="tab active" onclick="showPanel('seal')">Seal Message</button>
    <button class="tab" onclick="showPanel('unseal')">Unseal</button>
  </div>

  <div id="seal-panel" class="panel active">
    <label>Your Message</label>
    <textarea id="msg" placeholder="Type your secret message..."></textarea>

    <div class="row">
      <div>
        <label>Release Time</label>
        <select id="duration">
          <option value="30">30 seconds (demo)</option>
          <option value="60">1 minute</option>
          <option value="300">5 minutes</option>
          <option value="3600">1 hour</option>
          <option value="86400">1 day</option>
          <option value="custom">Custom...</option>
        </select>
      </div>
      <div id="custom-row" style="display:none">
        <label>Seconds</label>
        <input id="custom-secs" type="number" min="1" value="60">
      </div>
    </div>

    <button class="btn-primary" onclick="seal()">Encrypt & Seal</button>
    <div id="seal-error" class="error"></div>

    <div id="seal-output" class="output">
      <div class="label">Sealed Message</div>
      <div id="sealed-text"></div>
      <button class="copy-btn" onclick="copyText('sealed-text')">Copy</button>
      <div class="label" style="margin-top:1rem">Secret ID</div>
      <div id="sealed-id"></div>
      <button class="copy-btn" onclick="copyText('sealed-id')">Copy</button>
      <div style="margin-top:0.8rem;font-size:0.8rem;color:#888">
        Release: <span id="release-display"></span>
      </div>
    </div>
  </div>

  <div id="unseal-panel" class="panel">
    <label>Secret ID</label>
    <input id="secret-id" placeholder="Paste the secret ID...">

    <button class="btn-primary" onclick="unseal()">Unseal</button>
    <div id="unseal-error" class="error"></div>

    <div id="countdown" class="countdown">
      <div class="hint">Time remaining</div>
      <div class="time" id="countdown-time">--:--</div>
    </div>

    <div id="decrypt-result" class="decrypt-result"></div>
  </div>

  <div class="attestation">
    <strong>TEE Attestation:</strong> This enclave runs inside a Phala dstack Trusted Execution Environment.
    The decryption key cannot be accessed by anyone -- including the cloud provider.
    Time is fetched from multiple public time servers. The TEE attests this code runs unchanged inside the enclave.
  </div>

  <div class="how-it-works">
    <h3>How it works</h3>
    <ol>
      <li>Your browser generates a random AES-256 key and encrypts the message locally.</li>
      <li>The ciphertext stays in your browser. Only the encryption key is sent to the TEE.</li>
      <li>The enclave stores the key and <strong>will not release it</strong> until the release time passes.</li>
      <li>Anyone with the Secret ID can request unsealing -- but they get nothing until the time is up.</li>
      <li>TEE hardware guarantees the enclave code cannot be tampered with.</li>
    </ol>
  </div>
</div>

<script>
const BASE = location.pathname.replace(/\\/$/, '');

function showPanel(name) {
  document.querySelectorAll('.tab').forEach((t, i) => t.classList.toggle('active', (name === 'seal' ? i === 0 : i === 1)));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById(name + '-panel').classList.add('active');
}

document.getElementById('duration').addEventListener('change', e => {
  document.getElementById('custom-row').style.display = e.target.value === 'custom' ? 'block' : 'none';
});

function getDurationSecs() {
  const v = document.getElementById('duration').value;
  if (v === 'custom') return parseInt(document.getElementById('custom-secs').value) || 60;
  return parseInt(v);
}

function copyText(id) {
  navigator.clipboard.writeText(document.getElementById(id).textContent);
}

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 5000);
}

async function seal() {
  const msg = document.getElementById('msg').value.trim();
  if (!msg) return showError('seal-error', 'Enter a message');

  const duration = getDurationSecs() * 1000;
  const releaseTime = Date.now() + duration;

  try {
    // Generate AES-256 key
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(msg);

    // Encrypt client-side
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    // Export key to base64 (this is what the TEE holds)
    const rawKey = await crypto.subtle.exportKey('raw', key);
    const keyB64 = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
    const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
    const ivB64 = btoa(String.fromCharCode(...iv));

    // Send key to TEE (NOT the ciphertext)
    const resp = await fetch(BASE + '/seal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: keyB64,
        iv: ivB64,
        releaseTime: releaseTime,
      })
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: 'Server error' }));
      throw new Error(err.error || 'Failed to seal');
    }

    const data = await resp.json();

    // Return sealed message to user (ciphertext + id)
    const sealed = JSON.stringify({ id: data.id, ct: ctB64 });

    document.getElementById('sealed-text').textContent = sealed;
    document.getElementById('sealed-id').textContent = data.id;
    document.getElementById('release-display').textContent = new Date(releaseTime).toLocaleString();
    document.getElementById('seal-output').classList.add('show');

    // Clear key from memory
    await crypto.subtle.deleteKey(key);
  } catch (e) {
    showError('seal-error', e.message);
  }
}

let countdownInterval = null;

async function unseal() {
  const id = document.getElementById('secret-id').value.trim();
  if (!id) return showError('unseal-error', 'Enter a Secret ID');

  if (countdownInterval) clearInterval(countdownInterval);
  document.getElementById('decrypt-result').classList.remove('show');

  try {
    // Ask TEE for the key
    const resp = await fetch(BASE + '/unseal/' + id);
    const data = await resp.json();

    if (data.error) return showError('unseal-error', data.error);
      if (data.serverTime) console.log('TEE trusted time:', new Date(data.serverTime).toISOString());

    if (data.released) {
      // We have the key! But we need the ciphertext too.
      // Prompt user for sealed message
      const sealed = prompt('Paste your sealed message (the JSON with id and ct):');
      if (!sealed) return;

      let parsed;
      try { parsed = JSON.parse(sealed); } catch { return showError('unseal-error', 'Invalid sealed message JSON'); }

      if (parsed.id !== id) return showError('unseal-error', 'Secret ID mismatch');

      const keyBytes = Uint8Array.from(atob(data.key), c => c.charCodeAt(0));
      const ivBytes = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
      const ctBytes = Uint8Array.from(atob(parsed.ct), c => c.charCodeAt(0));

      const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, cryptoKey, ctBytes);
      const plaintext = new TextDecoder().decode(plainBuffer);

      document.getElementById('decrypt-result').textContent = plaintext;
      document.getElementById('decrypt-result').classList.add('show');
      document.getElementById('countdown').classList.remove('show');
    } else {
      // Not yet released
      const cd = document.getElementById('countdown');
      cd.classList.add('show');

      const updateCountdown = () => {
        const remaining = data.releaseTime - Date.now();
        if (remaining <= 0) {
          clearInterval(countdownInterval);
          cd.classList.remove('show');
          unseal(); // auto-retry
          return;
        }
        const mins = Math.floor(remaining / 60000);
        const secs = Math.floor((remaining % 60000) / 1000);
        document.getElementById('countdown-time').textContent =
          String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
      };

      updateCountdown();
      countdownInterval = setInterval(updateCountdown, 1000);
    }
  } catch (e) {
    showError('unseal-error', e.message);
  }
}
</script>
</body>
</html>`;

export default async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (path === "/" && req.method === "GET") {
    return new Response(HTML, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // POST /seal -- receive key from client, store in vault
  if (path === "/seal" && req.method === "POST") {
    const body = await req.json();
    const { key, iv, releaseTime } = body;
    if (!key || !iv || !releaseTime) {
      return Response.json({ error: "missing fields: key, iv, releaseTime" }, { status: 400 });
    }
    const id = genId();
    vault.set(id, {
      id,
      key,
      iv,
      ciphertext: "",
      releaseTime,
      createdAt: Date.now(),
    });
    return Response.json({ id, releaseTime });
  }

  // GET /unseal/:id -- release key if time is up
  const match = path.match(/^\/unseal\/([a-f0-9]+)$/);
  if (match && req.method === "GET") {
    const id = match[1];
    const secret = vault.get(id);
    if (!secret) {
      return Response.json({ error: "not found" }, { status: 404 });
    }
    const now = await trustedNow();
    if (now < secret.releaseTime) {
      const now = await trustedNow();
    return Response.json({
        released: false,
        releaseTime: secret.releaseTime,
        serverTime: now,
      });
    }
    // Time is up! Return the key, then delete from vault
    vault.delete(id);
    console.log(`Released ${id} at trusted time ${now}`);
    return Response.json({
      released: true,
      key: secret.key,
      iv: secret.iv,
    });
  }

  // GET /status -- vault stats
  if (path === "/status" && req.method === "GET") {
    return Response.json({
      stored: vault.size,
      entries: [...vault.entries()].map(([id, s]) => ({
        id,
        releaseTime: s.releaseTime,
        createdAt: s.createdAt,
        released: Date.now() >= s.releaseTime,
      })),
    });
  }


  // GET /time -- expose current trusted time for verification
  if (path === "/time" && req.method === "GET") {
    const now = await trustedNow();
    return Response.json({
      time: now,
      iso: new Date(now).toISOString(),
      sources: TIME_SOURCES.map(s => s.name),
    });
  }
  return new Response("timelock: see / for UI", { status: 404 });
}


// Standalone server (for local dev / non-Deno-Deploy environments)
if (import.meta.main) {
  const PORT = parseInt(Deno.env.get("PORT") || "3000");
  Deno.serve({ port: PORT }, handler);
  console.log(`Timelock server listening on :${PORT}`);
}
