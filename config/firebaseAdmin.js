/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Firebase Admin SDK Helper
 * ═══════════════════════════════════════════════════════════════════
 *
 *  PURPOSE:
 *  Server-side verification of Firebase ID tokens issued to clients.
 *  This replaces the insecure "trust any email" approach in /jwt endpoint.
 *
 *  HOW IT WORKS:
 *  1. Client gets ID token from Firebase after login (auth.currentUser.getIdToken())
 *  2. Client sends ID token to server
 *  3. Server calls verifyFirebaseIdToken() — cryptographically verifies
 *     the token was signed by Google's Firebase servers
 *  4. If valid, returns user info (uid, email, etc.)
 *  5. Server can then issue its own app JWT
 *
 *  SECURITY:
 *  - ID tokens are JWT signed with Google's private keys
 *  - Verification uses Firebase Admin SDK which handles key rotation
 *  - checkRevoked: true ensures tokens invalidated server-side are rejected
 *  - Short-lived: ID tokens expire in 1 hour (client auto-refreshes)
 *
 *  ENVIRONMENT VARIABLES (choose ONE format):
 *
 *  Format A (Recommended for Vercel — individual vars):
 *    FIREBASE_PROJECT_ID     = your-project-id
 *    FIREBASE_CLIENT_EMAIL   = firebase-adminsdk-xxx@your-project.iam.gserviceaccount.com
 *    FIREBASE_PRIVATE_KEY    = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
 *
 *  Format B (Simpler for some workflows — full JSON):
 *    FIREBASE_SERVICE_ACCOUNT_JSON = {"type":"service_account","project_id":"..."...}
 *
 *  Format C (Safest against env var length limits — base64):
 *    FIREBASE_SERVICE_ACCOUNT_B64  = eyJ0eXBlIjoi... (base64 of JSON)
 * ═══════════════════════════════════════════════════════════════════
 */

const admin = require('firebase-admin');

let initialized = false;

/**
 * Initialize Firebase Admin SDK. Safe to call multiple times.
 * Throws if credentials are missing/malformed — fail fast.
 */
function initFirebaseAdmin() {
  if (initialized) return admin;

  let serviceAccount;

  try {
    // ── Format A: Individual env vars (most common) ──
    if (
      process.env.FIREBASE_PROJECT_ID &&
      process.env.FIREBASE_CLIENT_EMAIL &&
      process.env.FIREBASE_PRIVATE_KEY
    ) {
      serviceAccount = {
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        // Private key contains literal "\n" — must convert to actual newlines
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      };
    }
    // ── Format B: Full JSON string ──
    else if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
      serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    }
    // ── Format C: Base64-encoded JSON ──
    else if (process.env.FIREBASE_SERVICE_ACCOUNT_B64) {
      const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf-8');
      serviceAccount = JSON.parse(decoded);
    }
    // ── None provided ──
    else {
      throw new Error(
        '❌ Firebase Admin credentials MISSING.\n\n' +
        'Set ONE of these env var groups:\n\n' +
        '  Option A (recommended):\n' +
        '    FIREBASE_PROJECT_ID\n' +
        '    FIREBASE_CLIENT_EMAIL\n' +
        '    FIREBASE_PRIVATE_KEY\n\n' +
        '  Option B:\n' +
        '    FIREBASE_SERVICE_ACCOUNT_JSON (full JSON string)\n\n' +
        '  Option C:\n' +
        '    FIREBASE_SERVICE_ACCOUNT_B64 (base64 of JSON)\n\n' +
        'Get credentials from: Firebase Console → Project Settings → Service Accounts → Generate new private key'
      );
    }

    // Validate required fields
    if (!serviceAccount.projectId || !serviceAccount.clientEmail || !serviceAccount.privateKey) {
      throw new Error(
        'Firebase service account missing required fields: projectId, clientEmail, privateKey'
      );
    }

    // Initialize SDK
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });

    initialized = true;
    console.log(JSON.stringify({
      level: 'info',
      msg: 'Firebase Admin SDK initialized',
      projectId: serviceAccount.projectId,
      time: new Date().toISOString(),
    }));

    return admin;
  } catch (err) {
    console.error(JSON.stringify({
      level: 'error',
      msg: 'Firebase Admin init failed',
      error: err.message,
      time: new Date().toISOString(),
    }));
    throw err;
  }
}

/**
 * Verify a Firebase ID token sent from the client.
 * Returns: { valid: true, uid, email, ... } or { valid: false, error, message }
 *
 * This is the cryptographic proof that the user actually logged in via Firebase.
 * No network call needed after init — verification is done locally using
 * Google's public keys (cached + auto-rotated by firebase-admin).
 */
async function verifyFirebaseIdToken(idToken) {
  if (!initialized) initFirebaseAdmin();

  if (!idToken || typeof idToken !== 'string') {
    return {
      valid: false,
      error: 'missing-token',
      message: 'ID token is required',
    };
  }

  try {
    // checkRevoked: true — extra safety; rejects tokens from users whose
    // session was revoked server-side (e.g., password change, admin action)
    const decoded = await admin.auth().verifyIdToken(idToken, true);

    return {
      valid: true,
      uid: decoded.uid,
      email: decoded.email || null,
      emailVerified: decoded.email_verified || false,
      provider: decoded.firebase?.sign_in_provider || 'unknown',
      issuedAt: new Date(decoded.iat * 1000),
      expiresAt: new Date(decoded.exp * 1000),
      name: decoded.name || null,
      picture: decoded.picture || null,
    };
  } catch (err) {
    // Common error codes:
    //   auth/id-token-expired   — token > 1 hour old (client should refresh)
    //   auth/id-token-revoked   — session revoked
    //   auth/argument-error     — malformed token
    //   auth/invalid-id-token   — signature mismatch (possibly tampered)
    return {
      valid: false,
      error: err.code || 'unknown',
      message: err.message || 'Token verification failed',
    };
  }
}

/**
 * Optional: Revoke all refresh tokens for a user (force re-login everywhere).
 * Useful for "log out from all devices" feature or after password change.
 */
async function revokeUserTokens(uid) {
  if (!initialized) initFirebaseAdmin();
  await admin.auth().revokeRefreshTokens(uid);
}

/**
 * Optional: Fetch Firebase user record by UID.
 * Useful if you want to sync Firebase user info with your DB.
 */
async function getFirebaseUser(uid) {
  if (!initialized) initFirebaseAdmin();
  return admin.auth().getUser(uid);
}

module.exports = {
  initFirebaseAdmin,
  verifyFirebaseIdToken,
  revokeUserTokens,
  getFirebaseUser,
  admin, // Expose raw admin if needed elsewhere
};