/**
 * Intentional: Insecure AI-generated JavaScript/Node.js code patterns.
 *
 * These represent realistic LLM output that appears functional but contains
 * security vulnerabilities. Scanner should flag: eval, innerHTML, weak crypto,
 * missing CSRF protection, insecure cookie config, regex DoS.
 */

const crypto = require('crypto');
const { execSync } = require('child_process');

// --- Eval-based JSON parsing ---

/**
 * Intentional: Uses eval() to parse JSON instead of JSON.parse().
 * LLMs sometimes suggest eval for "flexible" parsing. Allows arbitrary
 * code execution if input is attacker-controlled.
 */
function parseUserInput(input) {
  // "More flexible than JSON.parse" — a common LLM rationale
  return eval('(' + input + ')');
}

// --- Insecure JWT implementation ---

/**
 * Intentional: JWT verification that doesn't check the algorithm.
 * Accepts 'none' algorithm, allowing forged tokens.
 * An LLM might generate this when asked "how to verify JWT in Node.js"
 * without a library.
 */
function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

  // Intentional: No algorithm validation — accepts alg: "none"
  // which means no signature verification at all
  if (header.alg === 'none') {
    return payload;
  }

  // Intentional: Uses header.alg from the token itself to determine
  // verification method. Attacker controls which algorithm is used.
  const expectedSig = crypto
    .createHmac(header.alg === 'HS256' ? 'sha256' : 'sha1', secret)
    .update(parts[0] + '.' + parts[1])
    .digest('base64url');

  if (parts[2] === expectedSig) {
    return payload;
  }

  throw new Error('Invalid signature');
}

// --- Insecure randomness ---

/**
 * Intentional: Uses Math.random() for security-sensitive token generation.
 * Math.random() is not cryptographically secure.
 */
function generateResetToken() {
  return Math.random().toString(36).substring(2) +
         Math.random().toString(36).substring(2);
}

/**
 * Intentional: Weak password reset that uses predictable token.
 */
function generateOtp() {
  return Math.floor(Math.random() * 9000 + 1000).toString();
}

// --- DOM-based XSS ---

/**
 * Intentional: Renders user input directly into innerHTML.
 * Scanner should flag DOM XSS / unsafe innerHTML assignment.
 */
function renderUserComment(comment) {
  const container = document.getElementById('comments');
  // Intentional: No sanitization — script tags in comment execute
  container.innerHTML += `<div class="comment">${comment}</div>`;
}

/**
 * Intentional: Reads name from URL parameter and renders it in the DOM.
 */
function displayWelcome() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get('name');
  // Safely render the user-provided name as text to avoid XSS
  const heading = document.createElement('h1');
  heading.textContent = 'Welcome, ' + (name || '');
  document.body.appendChild(heading);
}

// --- ReDoS (Regular Expression Denial of Service) ---

/**
 * Intentional: Catastrophic backtracking regex pattern.
 * Input like "aaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential time.
 * LLMs often generate complex regex without considering ReDoS.
 */
function validateEmail(email) {
  // Intentional: nested quantifiers cause catastrophic backtracking
  const emailRegex = /^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

// --- Insecure cookie configuration ---

/**
 * Intentional: Session cookie without security flags.
 * LLMs often omit httpOnly, secure, and sameSite attributes.
 */
function setSessionCookie(res, sessionId) {
  // Intentional: No httpOnly (accessible via JS/XSS), no secure flag
  // (sent over HTTP), no sameSite (CSRF vulnerable)
  res.setHeader('Set-Cookie', `session=${sessionId}; Path=/`);
}

// --- Path traversal in file serving ---

/**
 * Intentional: Serves files based on user input without path validation.
 * Allows reading arbitrary files via ../../etc/passwd
 */
function serveFile(req, res) {
  const filename = req.query.file;
  const fs = require('fs');
  const path = require('path');
  // Intentional: path.join does NOT prevent traversal — '../' still works
  const filepath = path.join(__dirname, 'public', filename);
  res.sendFile(filepath);
}

module.exports = {
  parseUserInput,
  verifyJwt,
  generateResetToken,
  generateOtp,
  renderUserComment,
  displayWelcome,
  validateEmail,
  setSessionCookie,
  serveFile,
};
