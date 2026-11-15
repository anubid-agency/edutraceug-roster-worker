/* ==================================================================
 * edutraceug-roster-worker — Cloudflare Worker (D1 edition)
 * Single-file build.
 *
 * Accepts a school's student or teacher roster (xlsx/xls/xlsm/xltx/xltm/csv),
 * virus-scans it via Cloudmersive, archives the raw file to Cloudinary,
 * parses it with SheetJS, and merges structured rows into Cloudflare D1
 * (database edutraceug-db, binding DB).
 *
 * Also serves the roster viewer/editor endpoints:
 *   POST /roster/list | /roster/classes | /roster/update | /roster/add | /roster/delete
 *
 * Firebase ID tokens are verified with crypto.subtle against Google's JWKS.
 * No service accounts, no OAuth, no Firestore.
 * ================================================================== */

import * as XLSX from 'xlsx';

// ==================================================================
// Constants
// ==================================================================

const FIREBASE_PROJECT_ID = 'edutrace-ug';

const MAX_ROWS_PER_CALL = 300;
const DEFAULT_MAX_FILE_SIZE_MB = 25;
const ACCEPTED_EXTENSIONS = ['.xlsx', '.xls', '.xlsm', '.xltx', '.xltm', '.csv'];

const ACCEPTED_MIME = new Set([
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'application/vnd.ms-excel.sheet.macroenabled.12',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
  'application/vnd.ms-excel.template.macroenabled.12',
  'text/csv',
  'application/csv',
  'text/comma-separated-values',
  'text/plain',
  'application/octet-stream',
  '',
]);

const GOOGLE_JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

const CLOUDMERSIVE_SCAN_URL = 'https://api.cloudmersive.com/virus/scan/file';
const SCAN_TIMEOUT_MS = 60_000;

const JWKS_TTL_MS = 6 * 60 * 60 * 1000; // 6h

const RECORD_TYPES = new Set(['student', 'teacher']);

const LIST_DEFAULT_LIMIT = 100;
const LIST_MAX_LIMIT = 200;
const ADD_MAX_ROWS = 100;

const SENTINEL = '\uffff';

// ==================================================================
// Module-level caches
// ==================================================================

let jwksCache = { keys: null, expiresAt: 0 };

// ==================================================================
// Errors
// ==================================================================

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

class UploadValidationError extends HttpError {
  constructor(message, extra = {}) {
    super(400, message, extra);
  }
}

// ==================================================================
// Response helpers
// ==================================================================

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, GET, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-max-age': '86400',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(err) {
  if (err instanceof HttpError) {
    return jsonResponse({ status: 'error', error: err.message, ...err.extra }, err.status);
  }
  console.error('[roster-worker] unhandled error:', err && err.stack ? err.stack : err);
  return jsonResponse({ status: 'error', error: 'Internal server error.' }, 500);
}

// ==================================================================
// Encoding helpers
// ==================================================================

function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

function b64urlToBytes(str) {
  const norm = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? norm : norm + '='.repeat(4 - (norm.length % 4));
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToString(str) {
  return new TextDecoder().decode(b64urlToBytes(str));
}

function safeBaseName(name) {
  return (
    String(name || 'roster')
      .replace(/[^a-zA-Z0-9_-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 60) || 'roster'
  );
}

function generateDocId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += chars[bytes[i] % 62];
  return out;
}

function strOrEmpty(v) {
  return v === undefined || v === null ? '' : String(v).trim();
}

function nowIso() {
  return new Date().toISOString();
}

// ==================================================================
// JWKS: Firebase ID token verification
// ==================================================================

async function getGoogleJwks() {
  const now = Date.now();
  if (jwksCache.keys && jwksCache.expiresAt > now) return jwksCache.keys;

  const res = await fetch(GOOGLE_JWKS_URL, { cf: { cacheTtl: 3600 } });
  if (!res.ok) {
    throw new HttpError(502, `Failed to fetch Google JWKS (${res.status}).`);
  }
  const body = await res.json();
  if (!body || !Array.isArray(body.keys)) {
    throw new HttpError(502, 'Google JWKS response was malformed.');
  }
  jwksCache = { keys: body.keys, expiresAt: now + JWKS_TTL_MS };
  return body.keys;
}

async function verifyFirebaseIdToken(idToken, projectId) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Token is not a JWT.');
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(b64urlToString(headerB64));
  const payload = JSON.parse(b64urlToString(payloadB64));

  if (header.alg !== 'RS256') throw new Error(`Unsupported alg: ${header.alg}`);
  if (!header.kid) throw new Error('Token header is missing kid.');

  const keys = await getGoogleJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('No matching JWK for token kid.');

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const signingInput = utf8ToBytes(`${headerB64}.${payloadB64}`);
  const signature = b64urlToBytes(sigB64);

  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signingInput);
  if (!valid) throw new Error('Signature verification failed.');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('Token expired.');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    throw new Error('Bad token issuer.');
  }
  if (payload.aud !== projectId) throw new Error('Bad token audience.');
  if (!payload.sub || typeof payload.sub !== 'string') throw new Error('Token has no sub.');

  if (typeof payload.auth_time === 'number' && payload.auth_time > now + 60) {
    throw new Error('auth_time is in the future.');
  }

  return payload;
}

async function requireUser(request, allowedRoles) {
  const m = (request.headers.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError(401, 'Missing Authorization header.');
  let claims;
  try {
    claims = await verifyFirebaseIdToken(m[1].trim(), FIREBASE_PROJECT_ID);
  } catch (err) {
    throw new HttpError(401, `Invalid or expired ID token. (${err.message})`);
  }
  const user = {
    uid: claims.sub,
    role: claims.role || null,
    schoolId: claims.schoolId || null,
  };
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    throw new HttpError(403, `Requires role: ${allowedRoles.join(' or ')}.`);
  }
  return user;
}

// ==================================================================
// Cloudmersive virus scan
// ==================================================================

async function scanFileForViruses(env, file) {
  if (!env.CLOUDMERSIVE_API_KEY) {
    throw new HttpError(500, 'CLOUDMERSIVE_API_KEY is not configured.');
  }

  const form = new FormData();
  form.append('inputFile', file, file.name || 'upload');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  let res;
  try {
    res = await fetch(CLOUDMERSIVE_SCAN_URL, {
      method: 'POST',
      headers: { Apikey: env.CLOUDMERSIVE_API_KEY, Accept: 'application/json' },
      body: form,
      signal: controller.signal,
    });
  } catch (err) {
    throw new HttpError(502, `Virus scan service unreachable: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new HttpError(
      502,
      `Virus scan service returned ${res.status}. ${detail.slice(0, 200)}`.trim()
    );
  }

  const data = await res.json().catch(() => ({}));
  const found = Array.isArray(data.FoundViruses) ? data.FoundViruses : [];
  const clean = data.CleanResult !== false && found.length === 0;

  return { clean, foundViruses: found };
}

// ==================================================================
// Cloudinary raw upload
// ==================================================================

async function cloudinarySignature(params, apiSecret) {
  const toSign =
    Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join('&') + apiSecret;

  const digest = await crypto.subtle.digest('SHA-1', utf8ToBytes(toSign));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function uploadRawToCloudinary(env, file, { folder }) {
  const cloudName = env.CLOUDINARY_CLOUD_NAME;
  const apiKey = env.CLOUDINARY_API_KEY;
  const apiSecret = env.CLOUDINARY_API_SECRET;

  if (!cloudName || !apiKey || !apiSecret) {
    throw new HttpError(500, 'Cloudinary credentials are not configured.');
  }

  const parsedExt = (() => {
    const name = file.name || 'roster.xlsx';
    const dot = name.lastIndexOf('.');
    return dot > 0 ? name.slice(dot).toLowerCase() : '.xlsx';
  })();

  const publicId = `${safeBaseName(
    (file.name || 'roster').replace(/\.[^.]+$/, '')
  )}_${Date.now()}${parsedExt}`;
  const timestamp = Math.floor(Date.now() / 1000);

  const signedParams = {
    folder,
    public_id: publicId,
    timestamp: String(timestamp),
  };
  const signature = await cloudinarySignature(signedParams, apiSecret);

  const form = new FormData();
  form.append('file', file, file.name || `roster${parsedExt}`);
  form.append('api_key', apiKey);
  form.append('timestamp', signedParams.timestamp);
  form.append('public_id', signedParams.public_id);
  form.append('folder', signedParams.folder);
  form.append('signature', signature);

  const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, {
    method: 'POST',
    body: form,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(502, `Cloudinary upload failed (${res.status}): ${text.slice(0, 200)}`);
  }

  const data = await res.json();
  if (!data.secure_url) throw new HttpError(502, 'Cloudinary response missing secure_url.');
  return data;
}

// ==================================================================
// SheetJS parser — header detection & row extraction
// ==================================================================

const CANONICAL_FIELDS = [
  'studentId',
  'firstName',
  'lastName',
  'class',
  'gender',
  'stream',
  'subject',
  'extraDetail',
];

const POSITIONAL_ORDER = [...CANONICAL_FIELDS];

const ALIASES = {
  studentId: ['studentid', 'id', 'regno', 'regnumber', 'registration', 'lin', 'no'],
  firstName: ['firstname', 'givenname', 'forename', 'first', 'fname', 'christianname'],
  lastName: ['lastname', 'surname', 'familyname', 'secondname', 'last', 'lname'],
  class: ['class', 'classname', 'grade', 'form', 'level', 'year'],
  gender: ['gender', 'sex'],
  stream: ['stream', 'section', 'arm', 'division'],
  subject: ['subject', 'subjects', 'subjectcombination', 'combination', 'papers'],
  extraDetail: [
    'extradetail',
    'extra',
    'notes',
    'note',
    'disambiguation',
    'remark',
    'remarks',
    'comment',
    'comments',
  ],
};

function normalizeHeader(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function cellAt(values, index) {
  if (index === undefined || index === null || index < 0) return '';
  const raw = values[index];
  if (raw === undefined || raw === null) return '';
  return String(raw).replace(/\s+/g, ' ').trim();
}

function detectColumns(matrix) {
  const scanLimit = Math.min(matrix.length, 15);
  let best = null;

  for (let r = 0; r < scanLimit; r += 1) {
    const row = matrix[r] || [];
    const map = {};
    let score = 0;

    for (let c = 0; c < row.length; c += 1) {
      const key = normalizeHeader(row[c]);
      if (!key) continue;

      for (const field of CANONICAL_FIELDS) {
        if (map[field] !== undefined) continue;
        if (ALIASES[field].includes(key)) {
          map[field] = c;
          score += 1;
          break;
        }
      }
    }

    const hasCore =
      map.firstName !== undefined && map.lastName !== undefined && map.class !== undefined;

    if (hasCore && (!best || score > best.score)) {
      best = { headerRowIndex: r, map, score, positional: false };
    }
  }

  if (best) return best;

  const map = {};
  POSITIONAL_ORDER.forEach((field, i) => {
    map[field] = i;
  });
  return { headerRowIndex: -1, map, score: 0, positional: true };
}

function parseWorkbook(buffer) {
  let workbook;
  try {
    workbook = XLSX.read(new Uint8Array(buffer), { type: 'array', cellDates: false });
  } catch (err) {
    throw new UploadValidationError(
      `Could not read the spreadsheet: ${err.message}. Is the file corrupt or password-protected?`
    );
  }

  if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
    throw new UploadValidationError('The workbook contains no sheets.');
  }

  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];

  const matrix = XLSX.utils.sheet_to_json(sheet, {
    header: 1,
    defval: '',
    blankrows: false,
    raw: false,
  });

  return { sheetName, matrix };
}

function readRosterRows(buffer) {
  const { sheetName, matrix } = parseWorkbook(buffer);

  if (matrix.length === 0) {
    throw new UploadValidationError('The sheet is empty.');
  }

  const columns = detectColumns(matrix);
  const startIndex = columns.headerRowIndex + 1;
  const rows = [];

  for (let i = startIndex; i < matrix.length; i += 1) {
    const raw = matrix[i] || [];
    const isBlank = !raw.some((v) => String(v ?? '').trim() !== '');
    if (isBlank) continue;

    rows.push({
      excelRow: i + 1,
      studentId: cellAt(raw, columns.map.studentId),
      firstName: cellAt(raw, columns.map.firstName),
      lastName: cellAt(raw, columns.map.lastName),
      class: cellAt(raw, columns.map.class),
      gender: cellAt(raw, columns.map.gender),
      stream: cellAt(raw, columns.map.stream),
      subject: cellAt(raw, columns.map.subject),
      extraDetail: cellAt(raw, columns.map.extraDetail),
    });
  }

  if (rows.length === 0) {
    throw new UploadValidationError(
      'No data rows found. The file must contain a header row (first name, last name, class, ...) followed by data rows.'
    );
  }

  return { sheetName, columns, rows };
}

// ==================================================================
// Merge / validation helpers
// ==================================================================

function splitList(v) {
  return String(v || '')
    .split(/[,;]+/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

function mergeList(a, b) {
  const out = Array.isArray(a) ? [...a] : [];
  for (const item of b || []) {
    if (!out.some((x) => String(x).toLowerCase() === String(item).toLowerCase())) {
      out.push(item);
    }
  }
  return out;
}

function normalizeGender(raw) {
  const g = String(raw || '').trim().toLowerCase();
  if (g === 'male' || g === 'm') return 'Male';
  if (g === 'female' || g === 'f') return 'Female';
  return '';
}

function nameKey(firstName, lastName) {
  const norm = (v) => String(v || '').toLowerCase().replace(/\s+/g, ' ').trim();
  return `${norm(firstName)}|${norm(lastName)}`;
}

function validateAndNormalize(row, fileClass, fileStream, recordType) {
  const errors = [];

  const firstName = row.firstName;
  const lastName = row.lastName;
  const className = row.class || fileClass || '';
  const stream = row.stream || fileStream || '';
  const subjects = splitList(row.subject);
  const extraDetail = row.extraDetail;
  const studentId = row.studentId || '';

  let gender = '';
  const rawGender = String(row.gender || '').trim();
  if (rawGender) {
    gender = normalizeGender(rawGender);
    if (!gender) errors.push('gender must be Male or Female');
  }

  if (!firstName) errors.push('first name is required');
  if (!lastName) errors.push('last name is required');
  if (!className) errors.push('class is required');

  if (recordType === 'teacher' && subjects.length === 0) {
    errors.push('subject is required');
  }

  if (errors.length > 0) return { errors };

  return {
    errors: [],
    value: {
      firstName,
      lastName,
      class: className,
      gender,
      stream,
      subjects,
      extraDetail: extraDetail || '',
      studentId,
    },
  };
}

// ==================================================================
// Roster matching helpers
// ==================================================================

function normKey(v) {
  return String(v || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function exactStudentKey(d) {
  return [normKey(d.firstName), normKey(d.lastName), normKey(d.class), normKey(d.stream)].join('|');
}

function looseStudentKey(d) {
  return [normKey(d.firstName), normKey(d.lastName), normKey(d.class)].join('|');
}

function desiredKey(recordType, d) {
  return recordType === 'teacher'
    ? [normKey(d.firstName), normKey(d.lastName)].join('|')
    : exactStudentKey(d);
}

// ==================================================================
// Class-structure / class-subjects refresh (FIX 2 — selective)
// ==================================================================

function placeholdersFor(n) {
  return Array.from({ length: n }, () => '?').join(',');
}

async function refreshClassStructure(env, schoolId, classNames) {
  const db = env.DB;
  if (classNames && classNames.length > 0) {
    const classes = [...new Set(classNames)];
    const ph = placeholdersFor(classes.length);
    await db.batch([
      db
        .prepare(`DELETE FROM class_structure WHERE school_id = ? AND class_name IN (${ph})`)
        .bind(schoolId, ...classes),
      db
        .prepare(
          `INSERT INTO class_structure (school_id, class_name, stream, student_count)
           SELECT school_id, class_name, stream, COUNT(*)
           FROM roster
           WHERE school_id = ? AND record_type = 'student'
             AND class_name IN (${ph})
           GROUP BY school_id, class_name, stream`
        )
        .bind(schoolId, ...classes),
    ]);
  } else {
    await db.batch([
      db.prepare(`DELETE FROM class_structure WHERE school_id = ?`).bind(schoolId),
      db
        .prepare(
          `INSERT INTO class_structure (school_id, class_name, stream, student_count)
           SELECT school_id, class_name, stream, COUNT(*)
           FROM roster
           WHERE school_id = ? AND record_type = 'student'
           GROUP BY school_id, class_name, stream`
        )
        .bind(schoolId),
    ]);
  }
}

async function refreshClassSubjects(env, schoolId, classNames) {
  const db = env.DB;
  if (classNames && classNames.length > 0) {
    const classes = [...new Set(classNames)];
    const ph = placeholdersFor(classes.length);
    await db.batch([
      db
        .prepare(`DELETE FROM class_subjects WHERE school_id = ? AND class_name IN (${ph})`)
        .bind(schoolId, ...classes),
      db
        .prepare(
          `INSERT INTO class_subjects (school_id, class_name, subject, student_count)
           SELECT roster.school_id, roster.class_name, je.value, COUNT(DISTINCT roster.id)
           FROM roster, json_each(roster.subjects_json) je
           WHERE roster.school_id = ?
             AND roster.record_type = 'student'
             AND json_valid(roster.subjects_json)
             AND roster.class_name IN (${ph})
           GROUP BY roster.school_id, roster.class_name, je.value`
        )
        .bind(schoolId, ...classes),
    ]);
  } else {
    await db.batch([
      db.prepare(`DELETE FROM class_subjects WHERE school_id = ?`).bind(schoolId),
      db
        .prepare(
          `INSERT INTO class_subjects (school_id, class_name, subject, student_count)
           SELECT roster.school_id, roster.class_name, je.value, COUNT(DISTINCT roster.id)
           FROM roster, json_each(roster.subjects_json) je
           WHERE roster.school_id = ?
             AND roster.record_type = 'student'
             AND json_valid(roster.subjects_json)
           GROUP BY roster.school_id, roster.class_name, je.value`
        )
        .bind(schoolId),
    ]);
  }
}

async function refreshClasses(env, schoolId, classNames) {
  await refreshClassStructure(env, schoolId, classNames);
  await refreshClassSubjects(env, schoolId, classNames);
}

// ==================================================================
// Teacher "assigned" scope helper
// ==================================================================

// Returns null if teacher has full access; otherwise an object with
// streamOnly (array of {class, stream}) and classOnly (array of class names).
// The caller passes these to build a WHERE clause. Empty arrays => no access.
async function getTeacherScope(env, schoolId, user) {
  if (user.role !== 'teacher') return null;
  const settings = await env.DB.prepare(
    `SELECT teacher_access_mode FROM school_settings WHERE school_id = ?`
  )
    .bind(schoolId)
    .first();
  const mode = settings ? settings.teacher_access_mode : 'open';
  if (mode !== 'assigned') return null;

  const assignRows = await env.DB.prepare(
    `SELECT DISTINCT class_name, stream FROM teacher_assignments
     WHERE school_id = ? AND uid = ?`
  )
    .bind(schoolId, user.uid)
    .all();
  const assigns = assignRows.results || [];
  const streamOnly = assigns.filter((a) => a.stream).map((a) => ({
    class: a.class_name,
    stream: a.stream,
  }));
  const classOnly = assigns.filter((a) => !a.stream).map((a) => a.class_name);
  return { streamOnly, classOnly };
}

// Appends the teacher scope predicate (if any) to a where/params pair.
// FIX 4 — EXISTS (SELECT 1 FROM json_each(?) …) for the stream-bearing part.
function applyTeacherScope(where, params, scope) {
  if (!scope) return;
  const parts = [];
  if (scope.streamOnly.length > 0) {
    parts.push(
      `EXISTS (SELECT 1 FROM json_each(?) j
               WHERE j.value->>'class' = roster.class_name
                 AND j.value->>'stream' = roster.stream)`
    );
    params.push(JSON.stringify(scope.streamOnly));
  }
  if (scope.classOnly.length > 0) {
    parts.push(`roster.class_name IN (SELECT value FROM json_each(?))`);
    params.push(JSON.stringify(scope.classOnly));
  }
  if (parts.length === 0) {
    // No assignments → no rows.
    where.push('0 = 1');
    return;
  }
  where.push(`(${parts.join(' OR ')})`);
}

// ==================================================================
// /upload-roster
// ==================================================================

async function handleUploadRoster(request, env) {
  /* ---- 0. Auth ---- */
  const user = await requireUser(request, ['schoolAdmin']);

  /* ---- 1. Multipart parse ---- */
  let form;
  try {
    form = await request.formData();
  } catch (err) {
    throw new UploadValidationError(`Could not parse multipart body: ${err.message}`);
  }

  const file = form.get('file');
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    throw new UploadValidationError(
      '"file" is required (multipart/form-data, field name "file").'
    );
  }

  const schoolId = strOrEmpty(form.get('schoolId'));
  const fileClass = strOrEmpty(form.get('class'));
  const fileStream = strOrEmpty(form.get('stream'));
  const recordType = strOrEmpty(form.get('recordType')).toLowerCase();
  const providedBatchId = strOrEmpty(form.get('batchId')) || null;

  const offsetRaw = strOrEmpty(form.get('offset'));
  const offset = offsetRaw === '' ? 0 : Number.parseInt(offsetRaw, 10);

  /* ---- 2. Validate ---- */
  if (!schoolId) throw new UploadValidationError('"schoolId" is required.');
  if (user.schoolId !== schoolId) {
    throw new HttpError(403, "Your token's schoolId does not match the requested schoolId.");
  }
  if (!RECORD_TYPES.has(recordType)) {
    throw new UploadValidationError('"recordType" must be either "student" or "teacher".');
  }
  if (!Number.isFinite(offset) || offset < 0) {
    throw new UploadValidationError('"offset" must be a non-negative integer.');
  }

  const maxBytes = (Number(env.MAX_FILE_SIZE_MB) || DEFAULT_MAX_FILE_SIZE_MB) * 1024 * 1024;
  if (file.size > maxBytes) {
    throw new UploadValidationError(
      `File is too large (${file.size} bytes; max ${maxBytes}). Please split the roster into smaller files.`
    );
  }

  validateFileMetadata(file);

  /* ---- 3. Resolve batchId and cloudinaryUrl ---- */
  let batchId = providedBatchId;
  let cloudinaryUrl = null;

  if (offset > 0 && batchId) {
    const row = await env.DB.prepare(
      `SELECT cloudinary_url FROM roster_batches WHERE school_id = ? AND id = ?`
    )
      .bind(schoolId, batchId)
      .first();
    if (row) cloudinaryUrl = row.cloudinary_url || null;
  }

  if (offset > 0 && !cloudinaryUrl) {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const row = await env.DB.prepare(
      `SELECT id, cloudinary_url FROM roster_batches
       WHERE school_id = ? AND uploaded_by = ? AND record_type = ?
         AND class_name = ? AND stream = ? AND uploaded_at >= ?
       ORDER BY uploaded_at DESC LIMIT 1`
    )
      .bind(schoolId, user.uid, recordType, fileClass, fileStream, cutoff)
      .first();
    if (row) {
      batchId = row.id;
      cloudinaryUrl = row.cloudinary_url || null;
    }
  }

  /* ---- 4. Virus scan (FIX 3) — at offset 0 or when the file is about to be uploaded ---- */
  if (offset === 0 || !cloudinaryUrl) {
    const scan = await scanFileForViruses(env, file);
    if (!scan.clean) {
      throw new HttpError(400, 'File failed the virus scan and was not processed.', {
        foundViruses: scan.foundViruses,
      });
    }
  }

  /* ---- 5. Cloudinary upload if we don't already have one for this batch ---- */
  if (!cloudinaryUrl) {
    const uploaded = await uploadRawToCloudinary(env, file, {
      folder: `edutraceug/roster-uploads/${schoolId}`,
    });
    cloudinaryUrl = uploaded.secure_url;
    if (!batchId) batchId = generateDocId();
  }

  /* ---- 6. Parse rows ---- */
  const buffer = await file.arrayBuffer();
  const { sheetName, columns, rows } = readRosterRows(buffer);

  /* ---- 7. Process rows ---- */
  const report = await processRosterRows({
    env,
    schoolId,
    recordType,
    fileClass,
    fileStream,
    rows,
    offset,
    batchId,
    cloudinaryUrl,
    uid: user.uid,
  });

  /* ---- 8. Batch progress ---- */
  const now = nowIso();
  const batchStatus = report.remaining === 0 ? 'complete' : 'in_progress';

  if (offset === 0) {
    await env.DB.prepare(
      `INSERT INTO roster_batches
         (school_id, id, record_type, class_name, stream, uploaded_by, uploaded_at,
          file_name, file_size, sheet_name, total_rows, header_row_index, status,
          created_count, updated_count, unchanged_count, rejected_count,
          last_processed_offset, cloudinary_url, completed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(school_id, id) DO UPDATE SET
         record_type = excluded.record_type,
         class_name = excluded.class_name,
         stream = excluded.stream,
         uploaded_by = excluded.uploaded_by,
         uploaded_at = excluded.uploaded_at,
         file_name = excluded.file_name,
         file_size = excluded.file_size,
         sheet_name = excluded.sheet_name,
         total_rows = excluded.total_rows,
         header_row_index = excluded.header_row_index,
         status = excluded.status,
         created_count = excluded.created_count,
         updated_count = excluded.updated_count,
         unchanged_count = excluded.unchanged_count,
         rejected_count = excluded.rejected_count,
         last_processed_offset = excluded.last_processed_offset,
         cloudinary_url = excluded.cloudinary_url,
         completed_at = excluded.completed_at`
    )
      .bind(
        schoolId,
        batchId,
        recordType,
        fileClass,
        fileStream,
        user.uid,
        now,
        file.name || '',
        file.size,
        sheetName,
        rows.length,
        columns.headerRowIndex,
        batchStatus,
        report.created,
        report.updated,
        report.unchanged,
        report.rejected.length,
        report.nextOffset,
        cloudinaryUrl,
        report.remaining === 0 ? now : null
      )
      .run();
  } else {
    await env.DB.prepare(
      `UPDATE roster_batches
       SET cloudinary_url = ?,
           created_count = created_count + ?,
           updated_count = updated_count + ?,
           unchanged_count = unchanged_count + ?,
           rejected_count = rejected_count + ?,
           last_processed_offset = ?,
           status = ?,
           completed_at = CASE WHEN ? = 'complete' THEN ? ELSE completed_at END
       WHERE school_id = ? AND id = ?`
    )
      .bind(
        cloudinaryUrl,
        report.created,
        report.updated,
        report.unchanged,
        report.rejected.length,
        report.nextOffset,
        batchStatus,
        batchStatus,
        now,
        schoolId,
        batchId
      )
      .run();
  }

  /* ---- 9. Refresh class aggregates — only after the last chunk (whole school) ---- */
  if (report.remaining === 0) {
    await refreshClasses(env, schoolId);
  }

  /* ---- 10. Response ---- */
  return jsonResponse({
    status: 'ok',
    processed: report.processed,
    remaining: report.remaining,
    nextOffset: report.nextOffset,
    created: report.created,
    updated: report.updated,
    unchanged: report.unchanged,
    rejected: report.rejected,
    batchId,
  });
}

async function processRosterRows({
  env,
  schoolId,
  recordType,
  fileClass = '',
  fileStream = '',
  rows,
  offset,
  batchId,
  cloudinaryUrl,
  uid,
}) {
  if (!RECORD_TYPES.has(recordType)) {
    throw new Error(`Invalid recordType: ${recordType}`);
  }

  const db = env.DB;
  const slice = rows.slice(offset, offset + MAX_ROWS_PER_CALL);
  const nextOffset = offset + slice.length;
  const remaining = Math.max(0, rows.length - nextOffset);

  let created = 0;
  let updated = 0;
  let unchanged = 0;
  const rejected = [];
  const now = nowIso();

  /* ---- validate + group ---- */
  const groups = new Map();
  for (const row of slice) {
    const { errors, value } = validateAndNormalize(row, fileClass, fileStream, recordType);

    if (errors.length > 0) {
      rejected.push({ row: row.excelRow, reason: errors.join('; ') });
      continue;
    }

    const desired = {
      recordType,
      firstName: value.firstName,
      lastName: value.lastName,
      class: value.class,
      gender: value.gender,
      stream: value.stream,
      extraDetail: value.extraDetail,
      studentId: value.studentId,
      subjects: value.subjects,
    };

    const key = desiredKey(recordType, desired);
    const g = groups.get(key);

    if (!g) {
      groups.set(key, desired);
    } else {
      g.subjects = mergeList(g.subjects, desired.subjects);
      if (!g.gender && desired.gender) g.gender = desired.gender;
      if (!g.studentId && desired.studentId) g.studentId = desired.studentId;
      if (!g.extraDetail && desired.extraDetail) g.extraDetail = desired.extraDetail;
    }
  }

  const desiredList = [...groups.values()];

  /* ---- Query 1: fetch existing rows for this chunk's name_keys ---- */
  const nameKeys = [...new Set(desiredList.map((d) => nameKey(d.firstName, d.lastName)))];

  let existingRows = [];
  if (nameKeys.length > 0) {
    const result = await db
      .prepare(
        `SELECT id, first_name, last_name, class_name, stream, gender, student_id,
                extra_detail, subjects_json, classes_json
         FROM roster
         WHERE school_id = ? AND record_type = ?
           AND name_key IN (SELECT value FROM json_each(?))`
      )
      .bind(schoolId, recordType, JSON.stringify(nameKeys))
      .all();
    existingRows = result.results || [];
  }

  /* ---- Build in-memory index ---- */
  const exactIndex = new Map();
  const looseIndex = new Map();

  for (const r of existingRows) {
    let subjects = [];
    let classes = [];
    try { subjects = JSON.parse(r.subjects_json || '[]'); } catch { subjects = []; }
    try { classes = JSON.parse(r.classes_json || '[]'); } catch { classes = []; }

    const entry = {
      id: r.id,
      firstName: r.first_name,
      lastName: r.last_name,
      class: r.class_name,
      stream: r.stream,
      gender: r.gender,
      studentId: r.student_id,
      extraDetail: r.extra_detail,
      subjects,
      classes,
    };

    const exactK = recordType === 'teacher'
      ? [normKey(r.first_name), normKey(r.last_name)].join('|')
      : exactStudentKey(entry);
    if (!exactIndex.has(exactK)) exactIndex.set(exactK, []);
    exactIndex.get(exactK).push(entry);

    if (recordType === 'student') {
      const looseK = looseStudentKey(entry);
      if (!looseIndex.has(looseK)) looseIndex.set(looseK, []);
      looseIndex.get(looseK).push(entry);
    }
  }

  /* ---- Prepare bulk write payload ---- */
  const updateEntries = [];
  const insertEntries = [];

  for (const desired of desiredList) {
    const exactK = desiredKey(recordType, desired);
    let candidates = exactIndex.get(exactK) || [];
    if (candidates.length === 0 && recordType === 'student' && !desired.stream) {
      candidates = looseIndex.get(looseStudentKey(desired)) || [];
    }

    if (candidates.length > 0) {
      let chosen = candidates.find((c) =>
        String(c.firstName ?? '') === desired.firstName &&
        String(c.lastName ?? '') === desired.lastName &&
        String(c.class ?? '') === desired.class &&
        String(c.stream ?? '') === desired.stream &&
        String(c.gender ?? '') === desired.gender &&
        String(c.studentId ?? '') === desired.studentId &&
        String(c.extraDetail ?? '') === desired.extraDetail &&
        JSON.stringify(c.subjects || []) === JSON.stringify(desired.subjects || [])
      );
      if (!chosen && !desired.stream) {
        chosen = candidates.find((c) => !c.stream);
      }
      if (!chosen) chosen = candidates[0];

      const mergedSubjects = mergeList(chosen.subjects, desired.subjects);
      const mergedClasses = recordType === 'teacher'
        ? mergeList(chosen.classes, [desired.class])
        : chosen.classes;
      const mergedGender = chosen.gender || desired.gender;
      const mergedStudentId = chosen.studentId || desired.studentId;
      const mergedExtra = chosen.extraDetail || desired.extraDetail;

      const unchangedRow =
        String(chosen.firstName) === desired.firstName &&
        String(chosen.lastName) === desired.lastName &&
        String(chosen.class) === desired.class &&
        String(chosen.stream) === desired.stream &&
        String(chosen.gender || '') === mergedGender &&
        String(chosen.studentId || '') === mergedStudentId &&
        String(chosen.extraDetail || '') === mergedExtra &&
        JSON.stringify(chosen.subjects || []) === JSON.stringify(mergedSubjects) &&
        (recordType !== 'teacher' ||
          JSON.stringify(chosen.classes || []) === JSON.stringify(mergedClasses));

      if (unchangedRow) {
        unchanged += 1;
        continue;
      }

      updateEntries.push({
        id: chosen.id,
        first_name: desired.firstName,
        last_name: desired.lastName,
        name_key: nameKey(desired.firstName, desired.lastName),
        class_name: desired.class,
        stream: desired.stream,
        gender: mergedGender,
        student_id: mergedStudentId,
        extra_detail: mergedExtra,
        subjects_json: JSON.stringify(mergedSubjects),
        classes_json: JSON.stringify(mergedClasses),
        batch_id: batchId,
        cloudinary_url: cloudinaryUrl,
        updated_at: now,
        updated_by: uid,
      });
      updated += 1;
    } else {
      const id = generateDocId();
      insertEntries.push({
        id,
        first_name: desired.firstName,
        last_name: desired.lastName,
        name_key: nameKey(desired.firstName, desired.lastName),
        class_name: desired.class,
        stream: desired.stream,
        gender: desired.gender,
        student_id: desired.studentId,
        extra_detail: desired.extraDetail,
        subjects_json: JSON.stringify(desired.subjects || []),
        classes_json: JSON.stringify(recordType === 'teacher' ? [desired.class] : []),
      });
      created += 1;
    }
  }

  /* ---- Query 2: bulk upsert inserts ---- */
  if (insertEntries.length > 0) {
    const payload = JSON.stringify(insertEntries);
    await db
      .prepare(
        `INSERT INTO roster
           (school_id, id, record_type, first_name, last_name, name_key,
            class_name, stream, gender, student_id, extra_detail,
            subjects_json, classes_json, batch_id, cloudinary_url,
            created_by, created_at, updated_at)
         SELECT ?, je.value->>'id', ?, je.value->>'first_name', je.value->>'last_name',
                je.value->>'name_key', je.value->>'class_name', je.value->>'stream',
                je.value->>'gender', je.value->>'student_id', je.value->>'extra_detail',
                je.value->>'subjects_json', je.value->>'classes_json', ?, ?,
                ?, ?, ?
         FROM json_each(?) je
         WHERE true
         ON CONFLICT(school_id, id) DO UPDATE SET
           first_name = excluded.first_name,
           last_name = excluded.last_name,
           name_key = excluded.name_key,
           class_name = excluded.class_name,
           stream = excluded.stream,
           gender = excluded.gender,
           student_id = excluded.student_id,
           extra_detail = excluded.extra_detail,
           subjects_json = excluded.subjects_json,
           classes_json = excluded.classes_json,
           batch_id = excluded.batch_id,
           cloudinary_url = excluded.cloudinary_url,
           updated_at = excluded.updated_at`
      )
      .bind(schoolId, recordType, batchId, cloudinaryUrl, uid, now, now, payload)
      .run();
  }

  /* ---- Query 3: bulk update existing rows ---- */
  if (updateEntries.length > 0) {
    const payload = JSON.stringify(updateEntries);
    await db
      .prepare(
        `UPDATE roster
         SET first_name = je.value->>'first_name',
             last_name = je.value->>'last_name',
             name_key = je.value->>'name_key',
             class_name = je.value->>'class_name',
             stream = je.value->>'stream',
             gender = je.value->>'gender',
             student_id = je.value->>'student_id',
             extra_detail = je.value->>'extra_detail',
             subjects_json = je.value->>'subjects_json',
             classes_json = je.value->>'classes_json',
             batch_id = je.value->>'batch_id',
             cloudinary_url = je.value->>'cloudinary_url',
             updated_at = je.value->>'updated_at',
             updated_by = je.value->>'updated_by'
         FROM json_each(?) je
         WHERE roster.school_id = ?
           AND roster.id = je.value->>'id'`
      )
      .bind(payload, schoolId)
      .run();
  }

  return {
    processed: slice.length,
    remaining,
    nextOffset,
    created,
    updated,
    unchanged,
    rejected,
  };
}

// ==================================================================
// File-extension/MIME gate
// ==================================================================

function validateFileMetadata(file) {
  const original = file.name || '';
  const dot = original.lastIndexOf('.');
  const ext = dot >= 0 ? original.slice(dot).toLowerCase() : '';

  if (ext === '.xlsb') {
    throw new UploadValidationError(
      '".xlsb" files are not supported. Please re-save as .xlsx, .xls, .xlsm, .xltx, .xltm or .csv.'
    );
  }

  if (!ACCEPTED_EXTENSIONS.includes(ext)) {
    throw new UploadValidationError(
      `Unsupported file type "${ext || '(no extension)'}". Accepted: ${ACCEPTED_EXTENSIONS.join(
        ', '
      )}.`
    );
  }

  const mime = String(file.type || '').toLowerCase();
  if (!ACCEPTED_MIME.has(mime)) {
    throw new UploadValidationError(
      `Unsupported content type "${file.type}". Please upload an Excel or CSV file.`
    );
  }
}

// ==================================================================
// Roster viewer/editor endpoints
// ==================================================================

async function readRosterBody(request, user) {
  const body = await request.json().catch(() => ({}));
  const schoolId = strOrEmpty(body.schoolId);
  if (!schoolId || user.schoolId !== schoolId) {
    throw new HttpError(403, "Your token's schoolId does not match the requested schoolId.");
  }
  return { body, schoolId };
}

function cleanStudentFields(input) {
  const s = (v) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim();
  const errors = [];
  const out = {
    studentId: s(input.studentId),
    firstName: s(input.firstName),
    lastName: s(input.lastName),
    class: s(input.class),
    stream: s(input.stream),
    extraDetail: s(input.extraDetail),
    subjects: Array.isArray(input.subjects)
      ? input.subjects.map(s).filter(Boolean)
      : input.subjects !== undefined
      ? splitList(input.subjects)
      : undefined,
  };

  const rawGender = s(input.gender);
  if (rawGender) {
    out.gender = normalizeGender(rawGender);
    if (!out.gender) errors.push('gender must be Male or Female');
  } else {
    out.gender = '';
  }

  if (!out.firstName) errors.push('first name is required');
  if (!out.lastName) errors.push('last name is required');
  if (!out.class) errors.push('class is required');
  return { errors, value: out, hasSubjects: out.subjects !== undefined };
}

// ---- /roster/list ----
async function handleRosterList(request, env) {
  const user = await requireUser(request, ['schoolAdmin', 'teacher']);
  const { body, schoolId } = await readRosterBody(request, user);

  const cls = strOrEmpty(body.class);
  const stream = strOrEmpty(body.stream);
  const qRaw = strOrEmpty(body.q);
  const q = qRaw.toLowerCase();
  const rawLimit =
    body.limit === undefined || body.limit === null ? LIST_DEFAULT_LIMIT : Number(body.limit);
  const limit = Math.min(
    Math.max(Number.isFinite(rawLimit) ? rawLimit : LIST_DEFAULT_LIMIT, 1),
    LIST_MAX_LIMIT
  );
  const cursor = strOrEmpty(body.cursor) || null;

  const where = ['school_id = ?', "record_type = 'student'"];
  const params = [schoolId];

  if (cls) {
    where.push('class_name = ?');
    params.push(cls);
  }
  if (stream) {
    where.push('stream = ?');
    params.push(stream);
  }

  // FIX 1: q search — four binds, no template-string interpolation.
  // (a) first-name side via name_key:  name_key >= q  AND name_key < q + U+FFFF
  // (b) surname side via lower(last_name): same range, applied to lower(last_name)
  if (q) {
    const lower = q;
    const upper = q + SENTINEL;
    where.push(
      `((name_key >= ? AND name_key < ?) OR (lower(last_name) >= ? AND lower(last_name) < ?))`
    );
    params.push(lower, upper, lower, upper);
  }

  // FIX 4: teacher "assigned" scope using EXISTS (json_each).
  const scope = await getTeacherScope(env, schoolId, user);
  if (scope) {
    if (scope.streamOnly.length === 0 && scope.classOnly.length === 0) {
      return jsonResponse({ status: 'ok', rows: [], nextCursor: null });
    }
    const parts = [];
    if (scope.streamOnly.length > 0) {
      parts.push(
        `EXISTS (SELECT 1 FROM json_each(?) j
                 WHERE j.value->>'class' = roster.class_name
                   AND j.value->>'stream' = roster.stream)`
      );
      params.push(JSON.stringify(scope.streamOnly));
    }
    if (scope.classOnly.length > 0) {
      parts.push(`roster.class_name IN (SELECT value FROM json_each(?))`);
      params.push(JSON.stringify(scope.classOnly));
    }
    where.push(`(${parts.join(' OR ')})`);
  }

  // Cursor covers (class_name, stream, last_name, first_name, id).
  if (cursor) {
    const cparts = cursor.split('\x1f');
    if (cparts.length === 5) {
      where.push('(class_name, stream, last_name, first_name, id) > (?, ?, ?, ?, ?)');
      params.push(cparts[0], cparts[1], cparts[2], cparts[3], cparts[4]);
    }
  }

  const sql = `SELECT id, student_id, first_name, last_name, class_name, stream, gender, subjects_json, extra_detail
               FROM roster
               WHERE ${where.join(' AND ')}
               ORDER BY class_name, stream, last_name, first_name, id
               LIMIT ?`;
  params.push(limit + 1);

  const res = await env.DB.prepare(sql).bind(...params).all();
  const all = res.results || [];

  const hasMore = all.length > limit;
  const page = hasMore ? all.slice(0, limit) : all;

  const rows = page.map((r) => {
    let subjects = [];
    try { subjects = JSON.parse(r.subjects_json || '[]'); } catch { subjects = []; }
    return {
      id: r.id,
      studentId: r.student_id || '',
      firstName: r.first_name || '',
      lastName: r.last_name || '',
      class: r.class_name || '',
      stream: r.stream || '',
      gender: r.gender || '',
      subjects,
      extraDetail: r.extra_detail || '',
    };
  });

  let nextCursor = null;
  if (hasMore && page.length > 0) {
    const last = page[page.length - 1];
    nextCursor = [
      last.class_name || '',
      last.stream || '',
      last.last_name || '',
      last.first_name || '',
      last.id || '',
    ].join('\x1f');
  }

  return jsonResponse({ status: 'ok', rows, nextCursor });
}

// ---- /roster/classes ----
async function handleRosterClasses(request, env) {
  const user = await requireUser(request, ['schoolAdmin', 'teacher']);
  const { schoolId } = await readRosterBody(request, user);

  const where = ['school_id = ?'];
  const params = [schoolId];

  // FIX 4: apply teacher "assigned" scope here too.
  const scope = await getTeacherScope(env, schoolId, user);
  if (scope) {
    if (scope.streamOnly.length === 0 && scope.classOnly.length === 0) {
      return jsonResponse({ status: 'ok', rows: [] });
    }
    const parts = [];
    if (scope.streamOnly.length > 0) {
      parts.push(
        `EXISTS (SELECT 1 FROM json_each(?) j
                 WHERE j.value->>'class' = class_structure.class_name
                   AND j.value->>'stream' = class_structure.stream)`
      );
      params.push(JSON.stringify(scope.streamOnly));
    }
    if (scope.classOnly.length > 0) {
      parts.push(`class_structure.class_name IN (SELECT value FROM json_each(?))`);
      params.push(JSON.stringify(scope.classOnly));
    }
    where.push(`(${parts.join(' OR ')})`);
  }

  const res = await env.DB.prepare(
    `SELECT class_name, stream, student_count
     FROM class_structure
     WHERE ${where.join(' AND ')}
     ORDER BY class_name, stream`
  )
    .bind(...params)
    .all();

  const rows = (res.results || []).map((r) => ({
    class: r.class_name,
    stream: r.stream,
    student_count: r.student_count,
  }));

  return jsonResponse({ status: 'ok', rows });
}

// ---- /roster/update ----
async function handleRosterUpdate(request, env) {
  const user = await requireUser(request, ['schoolAdmin']);
  const { body, schoolId } = await readRosterBody(request, user);
  const id = strOrEmpty(body.id);
  if (!id) throw new HttpError(400, '"id" is required.');

  const existing = await env.DB.prepare(
    `SELECT id, record_type, class_name, stream, subjects_json
     FROM roster WHERE school_id = ? AND id = ?`
  )
    .bind(schoolId, id)
    .first();
  if (!existing) throw new HttpError(404, 'Student record not found.');
  if (existing.record_type !== 'student') {
    throw new HttpError(400, 'Only student records can be edited here.');
  }

  // Accept subjectsText as a fallback.
  const fields = { ...(body.fields || {}) };
  if (fields.subjects === undefined && body.subjectsText !== undefined) {
    fields.subjects = body.subjectsText;
  }
  if (fields.subjects === undefined && body.fields && body.fields.subjectsText !== undefined) {
    fields.subjects = body.fields.subjectsText;
  }

  const cleaned = cleanStudentFields(fields);
  if (cleaned.errors.length) throw new HttpError(400, cleaned.errors.join('; '));

  // Preserve existing subjects if none sent.
  let subjects;
  if (cleaned.hasSubjects && cleaned.value.subjects !== undefined) {
    subjects = cleaned.value.subjects;
  } else {
    try { subjects = JSON.parse(existing.subjects_json || '[]'); } catch { subjects = []; }
  }

  const prevClass = existing.class_name || '';
  const prevStream = existing.stream || '';
  const prevSubjectsJson = existing.subjects_json || '[]';

  const now = nowIso();
  await env.DB.prepare(
    `UPDATE roster
     SET first_name = ?, last_name = ?, name_key = ?,
         class_name = ?, stream = ?, gender = ?, student_id = ?,
         extra_detail = ?, subjects_json = ?, updated_at = ?, updated_by = ?
     WHERE school_id = ? AND id = ?`
  )
    .bind(
      cleaned.value.firstName,
      cleaned.value.lastName,
      nameKey(cleaned.value.firstName, cleaned.value.lastName),
      cleaned.value.class,
      cleaned.value.stream,
      cleaned.value.gender,
      cleaned.value.studentId,
      cleaned.value.extraDetail,
      JSON.stringify(subjects),
      now,
      user.uid,
      schoolId,
      id
    )
    .run();

  // FIX 2: refresh only when class/stream/subjects changed; refresh both
  // old and new class.
  const nextSubjectsJson = JSON.stringify(subjects);
  const classChanged = cleaned.value.class !== prevClass || cleaned.value.stream !== prevStream;
  const subjectsChanged = nextSubjectsJson !== prevSubjectsJson;

  if (classChanged || subjectsChanged) {
    const touched = new Set();
    if (prevClass) touched.add(prevClass);
    if (cleaned.value.class) touched.add(cleaned.value.class);
    const classes = [...touched];
    if (classes.length > 0) {
      await refreshClasses(env, schoolId, classes);
    }
  }

  return jsonResponse({ status: 'ok' });
}

// ---- /roster/add ----
async function handleRosterAdd(request, env) {
  const user = await requireUser(request, ['schoolAdmin']);
  const { body, schoolId } = await readRosterBody(request, user);
  const input = Array.isArray(body.rows) ? body.rows : [];
  if (input.length === 0) throw new HttpError(400, '"rows" is required.');
  if (input.length > ADD_MAX_ROWS) {
    throw new HttpError(400, `Add at most ${ADD_MAX_ROWS} students at a time.`);
  }

  const cleaned = [];
  for (let i = 0; i < input.length; i += 1) {
    const { errors, value } = cleanStudentFields(input[i] || {});
    if (errors.length) throw new HttpError(400, `Row ${i + 1}: ${errors.join('; ')}`);
    if (value.subjects === undefined) value.subjects = [];
    cleaned.push(value);
  }

  // Duplicate pre-check using json_each (avoids the 100-bind ceiling).
  const classes = [...new Set(cleaned.map((v) => v.class))];
  const existingSet = new Set();
  if (classes.length > 0) {
    const res = await env.DB.prepare(
      `SELECT first_name, last_name, class_name, stream
       FROM roster
       WHERE school_id = ? AND record_type = 'student'
         AND class_name IN (SELECT value FROM json_each(?))`
    )
      .bind(schoolId, JSON.stringify(classes))
      .all();
    for (const r of res.results || []) {
      existingSet.add(
        [normKey(r.first_name), normKey(r.last_name), normKey(r.class_name), normKey(r.stream)].join('|')
      );
    }
  }

  const now = nowIso();
  const toInsert = [];
  const duplicates = [];

  for (const v of cleaned) {
    const k = [normKey(v.firstName), normKey(v.lastName), normKey(v.class), normKey(v.stream)].join('|');
    if (existingSet.has(k)) {
      duplicates.push(`${v.firstName} ${v.lastName}`);
      continue;
    }
    existingSet.add(k);
    toInsert.push(v);
  }

  if (toInsert.length > 0) {
    const payload = JSON.stringify(
      toInsert.map((v) => ({
        id: generateDocId(),
        first_name: v.firstName,
        last_name: v.lastName,
        name_key: nameKey(v.firstName, v.lastName),
        class_name: v.class,
        stream: v.stream,
        gender: v.gender,
        student_id: v.studentId,
        extra_detail: v.extraDetail,
        subjects_json: JSON.stringify(v.subjects || []),
      }))
    );

    await env.DB.prepare(
      `INSERT INTO roster
         (school_id, id, record_type, first_name, last_name, name_key,
          class_name, stream, gender, student_id, extra_detail,
          subjects_json, classes_json, created_by, created_at, updated_at)
       SELECT ?, je.value->>'id', 'student',
              je.value->>'first_name', je.value->>'last_name', je.value->>'name_key',
              je.value->>'class_name', je.value->>'stream', je.value->>'gender',
              je.value->>'student_id', je.value->>'extra_detail',
              je.value->>'subjects_json', '[]',
              ?, ?, ?
       FROM json_each(?) je
       WHERE true
       ON CONFLICT(school_id, id) DO NOTHING`
    )
      .bind(schoolId, user.uid, now, now, payload)
      .run();
  }

  // FIX 2: refresh only classes touched by this add.
  const touched = [...new Set(cleaned.map((v) => v.class).filter(Boolean))];
  if (touched.length > 0) {
    await refreshClasses(env, schoolId, touched);
  }

  return jsonResponse({ status: 'ok', created: toInsert.length, duplicates });
}

// ---- /roster/delete ----
async function handleRosterDelete(request, env) {
  const user = await requireUser(request, ['schoolAdmin']);
  const { body, schoolId } = await readRosterBody(request, user);
  const id = strOrEmpty(body.id);
  if (!id) throw new HttpError(400, '"id" is required.');

  const existing = await env.DB.prepare(
    `SELECT id, record_type, class_name FROM roster WHERE school_id = ? AND id = ?`
  )
    .bind(schoolId, id)
    .first();
  if (!existing) throw new HttpError(404, 'Student record not found.');
  if (existing.record_type !== 'student') {
    throw new HttpError(400, 'Only student records can be removed here.');
  }

  await env.DB.prepare(`DELETE FROM roster WHERE school_id = ? AND id = ?`)
    .bind(schoolId, id)
    .run();

  // FIX 2: refresh only the class the student belonged to.
  if (existing.class_name) {
    await refreshClasses(env, schoolId, [existing.class_name]);
  }

  return jsonResponse({ status: 'ok' });
}

// ==================================================================
// Router
// ==================================================================

const POST_ROUTES = {
  '/upload-roster': handleUploadRoster,
  '/roster/list': handleRosterList,
  '/roster/classes': handleRosterClasses,
  '/roster/update': handleRosterUpdate,
  '/roster/add': handleRosterAdd,
  '/roster/delete': handleRosterDelete,
};

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'edutraceug-roster-worker' });
    }

    if (request.method === 'POST' && POST_ROUTES[url.pathname]) {
      try {
        return await POST_ROUTES[url.pathname](request, env);
      } catch (err) {
        return errorResponse(err);
      }
    }

    return jsonResponse(
      { status: 'error', error: `Not found: ${request.method} ${url.pathname}` },
      404
    );
  },
};
