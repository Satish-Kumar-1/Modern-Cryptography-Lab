/**
 * CryptoGuard TypeScript Type Definitions.
 * Covers API request/response payloads, file dropzone states, and cryptographic results.
 */

export interface FilePayload {
  name: string;
  size: number;
  type: string;
  contentBase64: string;
  contentText?: string;
}

export interface VerifyRequest {
  document: string;     // Base64 encoded document bytes
  signature: string;    // Base64 encoded 64-byte signature
  publicKey: string;    // Base64 or ASCII PEM public key
}

export interface VerifyResponse {
  is_valid: boolean;
  message: string;
  details?: string | null;
  fingerprint?: string | null;
  error?: string;
}

export interface SignRequest {
  document: string;     // Base64 encoded document bytes
  privateKey: string;   // Base64 or ASCII PEM private key
  password?: string;    // Optional passphrase for encrypted key
}

export interface SignResponse {
  success: boolean;
  signature?: string;   // Base64 encoded 64-byte detached signature
  size?: number;        // Should be exactly 64 bytes
  message?: string;
  error?: string;
}

export interface KeygenRequest {
  password?: string;    // Optional passphrase to encrypt private key (PKCS#8 AES-256)
}

export interface KeygenResponse {
  success: boolean;
  private_key?: string; // PKCS#8 PEM string
  public_key?: string;  // SubjectPublicKeyInfo (SPKI) PEM string
  fingerprint?: string; // Canonical SHA-256 fingerprint
  encrypted?: boolean;
  error?: string;
}

export interface FingerprintRequest {
  publicKey: string;    // Base64 or ASCII PEM public key
  expected?: string;    // Optional trusted reference fingerprint (e.g. SHA256:xx:xx:...)
}

export interface FingerprintResponse {
  success: boolean;
  fingerprint?: string;
  matches?: boolean | null;
  message?: string;
  error?: string;
}

export interface DropzoneOptions {
  acceptExtensions?: string[];
  maxSizeMB?: number;
  onFileSelect?: (file: FilePayload) => void;
  onFileClear?: () => void;
}
