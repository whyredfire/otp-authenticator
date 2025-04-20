import crypto from "node:crypto";
import * as b32 from "hi-base32";
import notp from "notp";

interface VerifyResult {
  delta: number;
}

// Generate a key
function generateOtpKey(): Buffer {
  // 20 cryptographically random binary bytes (160-bit key)
  return crypto.randomBytes(20);
}

// Text-encode the key as base32 (in the style of Google Authenticator)
function encodeGoogleAuthKey(bin: Buffer): string {
  // 32 ascii characters without trailing '='s
  const base32 = b32.encode(bin).replace(/=/g, "");

  // Lowercase with a space every 4 characters
  return base32
    .toLowerCase()
    .replace(/(\w{4})/g, "$1 ")
    .trim();
}

function generateKey(): string {
  const otpKey = generateOtpKey();
  return encodeGoogleAuthKey(otpKey);
}

// Binary-decode the key from base32 (Google Authenticator)
function decodeGoogleAuthKey(key: string): Buffer {
  // Decode base32 Google Auth key to binary
  const unformatted = key.replace(/\W+/g, "").toUpperCase();
  return Buffer.from(b32.decode.asBytes(unformatted));
}

// Generate a Google Auth Token
function generateToken(key: string, period: number = 30): string {
  const bin = decodeGoogleAuthKey(key);
  const timeStep = Math.floor(Date.now() / 1000 / period);
  return notp.totp.gen(bin, { time: timeStep });
}

// Verify a Google Auth Token
function verifyToken(
  key: string,
  token: string,
  period: number = 30
): VerifyResult | null {
  try {
    const bin = decodeGoogleAuthKey(key);
    token = token.replace(/\W+/g, "");

    // Correct time step
    const timeStep = Math.floor(Date.now() / 1000 / period);

    // Window is +/- 1 period
    return notp.totp.verify(token, bin, { window: 1, time: timeStep });
  } catch (error) {
    console.error("Error verifying token:", error);
    return null;
  }
}

// Generate a TOTP URI
function generateTotpUri(
  secret: string,
  accountName: string,
  issuer: string,
  algo: string = "SHA1",
  digits: number = 6,
  period: number = 30
): string {
  const formattedSecret = secret.replace(/[\s\.\_\-]+/g, "").toUpperCase();

  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(
    accountName
  )}?secret=${formattedSecret}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=${algo}&digits=${digits}&period=${period}`;
}

export { generateKey, generateToken, verifyToken, generateTotpUri };
