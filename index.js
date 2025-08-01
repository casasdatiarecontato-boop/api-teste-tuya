/*
 * Tia Rê Conecta – Tuya backend integration
 *
 * This script exposes a simple HTTP server with a single route
 *    POST /api/tuya/create-password
 * that generates a temporary numeric password for a given smart lock.
 *
 * The implementation follows Tuya’s cloud API guidelines for
 * authentication and signing. To create a password the backend
 * performs the following steps:
 *   1. Fetch an access token from Tuya’s Open API using the project’s
 *      client ID and secret. The token is valid for two hours.
 *   2. Request a password ticket for the target device. Tuya returns
 *      a `ticket_id` and `ticket_key`. According to the documentation,
 *      the password must be encrypted using the AES‑128 algorithm in
 *      ECB mode with PKCS7 padding. First the `ticket_key` is used as
 *      the encryption key and then the numeric password (7 digits) is
 *      encrypted and converted to an uppercase hex string【584420215879194†L180-L189】.  
 *      The resulting cipher text is passed to the API along with the
 *      `ticket_id`, validity timestamps and other metadata.
 *   3. Submit the encrypted password to the Tuya API.
 *
 * To make a request to Tuya’s API you must compute a signature for
 * every call. The signature algorithm concatenates the client ID,
 * access token (if present), current timestamp, HTTP method, the
 * SHA‑256 hash of the request body, and the request path with query.
 * This string is then signed using HMAC‑SHA256 with your client
 * secret and converted to uppercase hex【584420215879194†L180-L189】.
 *
 * Environment variables expected:
 *   TUYA_ACCESS_ID      – client ID (also called access key)
 *   TUYA_ACCESS_SECRET  – client secret
 *   TUYA_UID            – end user identifier (not used in this sample)
 *   TUYA_DEVICE_ID_SUITE – device ID of the suite lock
 *   TUYA_DEVICE_ID_CASA1 – device ID of casa1 lock
 *   TUYA_DEVICE_ID_CASA2 – device ID of casa2 lock
 *   TUYA_ENDPOINT        – optional Tuya API host (default: openapi.tuyaus.com)
 *   TZ_OFFSET           – optional time‑zone offset, e.g. “-03:00”
 *
 * Note: This server does not persist tokens or cache responses. In
 * production you may want to cache the access token to avoid
 * repeatedly fetching it on every request. Also note that this code
 * cannot be fully tested in the current environment because outbound
 * network requests are blocked. You should deploy the server on a
 * platform with external network access (Railway, Render, Vercel, etc.).
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// Read configuration from environment variables
const CLIENT_ID = process.env.TUYA_ACCESS_ID;
const CLIENT_SECRET = process.env.TUYA_ACCESS_SECRET;
const UID = process.env.TUYA_UID;
const DEVICE_SUITE = process.env.TUYA_DEVICE_ID_SUITE;
const DEVICE_CASA1 = process.env.TUYA_DEVICE_ID_CASA1;
const DEVICE_CASA2 = process.env.TUYA_DEVICE_ID_CASA2;
const API_HOST = process.env.TUYA_ENDPOINT || 'openapi.tuyaus.com';
const TZ_OFFSET = process.env.TZ_OFFSET || '-03:00';

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Error: TUYA_ACCESS_ID and TUYA_ACCESS_SECRET must be set as environment variables.');
  process.exit(1);
}

/**
 * Perform an HTTPS request and return a promise that resolves
 * with the parsed JSON body. If the response cannot be parsed
 * JSON, the raw text is returned. Errors are propagated.
 *
 * @param {Object} options HTTPS request options
 * @param {Object|string|undefined} body Optional request body
 */
function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch (e) {
          resolve(data);
        }
      });
    });
    req.on('error', reject);
    if (body) {
      if (typeof body === 'string' || Buffer.isBuffer(body)) {
        req.write(body);
      } else {
        req.write(JSON.stringify(body));
      }
    }
    req.end();
  });
}

/**
 * Acquire an access token from Tuya. Tokens are valid for two hours.
 * The signature for token requests is simply HMAC‑SHA256(clientId + t, secret)
 * converted to uppercase hex.
 */
async function getAccessToken() {
  const t = Date.now().toString();
  const signStr = CLIENT_ID + t;
  const sign = crypto.createHmac('sha256', CLIENT_SECRET)
    .update(signStr)
    .digest('hex')
    .toUpperCase();
  const path = '/v1.0/token?grant_type=1';
  const options = {
    hostname: API_HOST,
    path: path,
    method: 'GET',
    headers: {
      'client_id': CLIENT_ID,
      'sign': sign,
      't': t,
      'sign_method': 'HMAC-SHA256'
    }
  };
  const result = await httpsRequest(options);
  if (!result || result.success === false) {
    throw new Error(`Failed to obtain access token: ${JSON.stringify(result)}`);
  }
  return result.result.access_token;
}

/**
 * Generate request signature and timestamp for Tuya API calls. This follows
 * the algorithm described in Tuya’s documentation【584420215879194†L180-L189】:
 *
 *   signContent = clientId + accessToken + t + method.toUpperCase() + '\n' +
 *                 SHA256(body) + '\n\n' + pathAndQuery
 *   sign = HMAC‑SHA256(signContent, secret).toUpperCase()
 *
 * @param {string} method HTTP method (GET, POST, DELETE)
 * @param {string} fullPath The request path including query
 * @param {string|Object|undefined} body Request body or undefined
 * @param {string} accessToken The active access token
 */
function buildSignature(method, fullPath, body, accessToken) {
  const t = Date.now().toString();
  const bodyStr = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : '';
  const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');

  const content = CLIENT_ID + accessToken + t + method.toUpperCase() + '\n' + bodyHash + '\n\n' + fullPath;

  // 🔐 DEBUG: mostra no terminal a string usada na assinatura
  console.log('🔐 String to sign:', content);

  const sign = crypto.createHmac('sha256', CLIENT_SECRET)
    .update(content)
    .digest('hex')
    .toUpperCase();

  return { sign, t };
}

/**
 * Make a signed API request to Tuya. Automatically fetches an access token
 * and computes the required signature.
 *
 * @param {string} method HTTP method
 * @param {string} path Path including leading slash and query
 * @param {Object|undefined} body JSON body for POST/DELETE requests
 */
async function tuyaRequest(method, path, body) {
  const accessToken = await getAccessToken();
  const { sign, t } = buildSignature(method, path, body, accessToken);
  const headers = {
    'client_id': CLIENT_ID,
    't': t,
    'sign': sign,
    'sign_method': 'HMAC-SHA256',
    'access_token': accessToken,
    'Content-Type': 'application/json'
  };
  const options = {
    hostname: API_HOST,
    path: path,
    method: method,
    headers: headers
  };
  const response = await httpsRequest(options, body);
  return response;
}

/**
 * Generate a random numeric string of a given length. Defaults to 7 digits.
 * Leading zeros are preserved.
 *
 * @param {number} len Length of the numeric string
 */
function randomNumericString(len = 7) {
  let code = '';
  for (let i = 0; i < len; i++) {
    code += Math.floor(Math.random() * 10).toString();
  }
  return code;
}

/**
 * Encrypt a password using the provided ticket key. The ticket key is
 * expected to be a hex string. The password must be encrypted with
 * AES‑128‑ECB and PKCS7 padding, and the result returned as an
 * uppercase hex string【584420215879194†L180-L189】.
 *
 * @param {string} password Numeric password in plaintext
 * @param {string} ticketKey Hexadecimal ticket key returned by Tuya
 */
function encryptPassword(password, ticketKey) {
  // Convert ticket key to a Buffer. The key length must be 16 bytes (128 bits).
  // If the provided key is longer than 16 bytes, truncate it. If it is shorter,
  // pad with zero bytes. This follows AES key sizing rules.
  let keyBuf = Buffer.from(ticketKey, 'hex');
  if (keyBuf.length > 16) {
    keyBuf = keyBuf.slice(0, 16);
  } else if (keyBuf.length < 16) {
    const padded = Buffer.alloc(16);
    keyBuf.copy(padded);
    keyBuf = padded;
  }
  const cipher = crypto.createCipheriv('aes-128-ecb', keyBuf, null);
  // Enable PKCS7 padding (default for Node’s crypto)
  let encrypted = cipher.update(password, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString('hex').toUpperCase();
}

/**
 * Obtain a password ticket for a specific device. Returns an object with
 * `ticket_id` and `ticket_key`.
 *
 * @param {string} deviceId The ID of the lock device
 */
async function getPasswordTicket(deviceId) {
  const result = await tuyaRequest('POST', `/v1.0/devices/${deviceId}/door-lock/password-ticket`, {});
  if (!result || result.success === false) {
    throw new Error(`Failed to get password ticket: ${JSON.stringify(result)}`);
  }
  return result.result;
}

/**
 * Create a temporary password for a device. Wraps the call sequence of
 * acquiring a ticket, encrypting the password and invoking the API.
 *
 * @param {string} deviceId Target device ID
 * @param {string} code Plain numeric password
 * @param {number} effectiveTime Unix timestamp (seconds) when the password becomes valid
 * @param {number} invalidTime Unix timestamp (seconds) when the password expires
 * @param {string} [name] Optional name for the password
 */
async function createTemporaryPassword(deviceId, code, effectiveTime, invalidTime, name) {
  // Step 1: request ticket
  const ticket = await getPasswordTicket(deviceId);
  // Step 2: encrypt password
  const encrypted = encryptPassword(code, ticket.ticket_key);
  // Step 3: call temp-password API
  const body = {
    name: name || `code-${code}`,
    password: encrypted,
    password_type: 'ticket',
    ticket_id: ticket.ticket_id,
    effective_time: effectiveTime,
    invalid_time: invalidTime,
    type: 0,
    time_zone: TZ_OFFSET
  };
  const response = await tuyaRequest('POST', `/v1.0/devices/${deviceId}/door-lock/temp-password`, body);
  return response;
}

/**
 * Utility to parse JSON request bodies. Returns a promise that resolves
 * with the parsed object or rejects on error. Empty bodies resolve to {}.
 *
 * @param {http.IncomingMessage} req The incoming HTTP request
 */
function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        const obj = JSON.parse(data);
        resolve(obj);
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Create HTTP server
const server = http.createServer(async (req, res) => {
  // CORS headers to allow cross‑origin requests from the Base44 frontend
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.method === 'POST' && req.url === '/api/tuya/create-password') {
    try {
      const body = await parseRequestBody(req);
      // Determine which device to target. Accepts `device` field or fallback to suite
      let deviceId;
      switch ((body.device || '').toLowerCase()) {
        case 'suite':
        case 'suíte':
        case 'suite_lock':
          deviceId = DEVICE_SUITE;
          break;
        case 'casa1':
        case 'house1':
          deviceId = DEVICE_CASA1;
          break;
        case 'casa2':
        case 'house2':
          deviceId = DEVICE_CASA2;
          break;
        default:
          // If a specific deviceId is provided in the body, use that
          deviceId = body.device_id || DEVICE_SUITE;
          break;
      }
      if (!deviceId) {
        throw new Error('No device ID could be determined.');
      }
      const code = body.code && /^[0-9]{7}$/.test(body.code) ? body.code : randomNumericString(7);
      // Effective and invalid times as seconds since epoch
      const nowSec = Math.floor(Date.now() / 1000);
      const effectiveTime = body.effective_time || nowSec;
      // Default expiry: 24 hours from now
      const invalidTime = body.invalid_time || (nowSec + 24 * 60 * 60);
      const name = body.name || undefined;
      const result = await createTemporaryPassword(deviceId, code, effectiveTime, invalidTime, name);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, code, result }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, message: err.message }));
    }
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Tuya backend server listening on port ${PORT}`);
});
