/**
 * CryptoGuard API Client.
 * Communicates with the in-memory Python cryptographic engine via JSON over HTTP.
 */

import type {
  VerifyRequest,
  VerifyResponse,
  SignRequest,
  SignResponse,
  KeygenRequest,
  KeygenResponse,
  FingerprintRequest,
  FingerprintResponse,
  FilePayload,
} from './types.js';

const API_BASE = '/api';

export class CryptoGuardApi {
  private static async post<T>(endpoint: string, body: any): Promise<T> {
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP error ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (err: any) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  }

  public static async verifyDocument(req: VerifyRequest): Promise<VerifyResponse> {
    return this.post<VerifyResponse>('/verify', req);
  }

  public static async signDocument(req: SignRequest): Promise<SignResponse> {
    return this.post<SignResponse>('/sign', req);
  }

  public static async generateKeys(req: KeygenRequest): Promise<KeygenResponse> {
    return this.post<KeygenResponse>('/keygen', req);
  }

  public static async computeFingerprint(req: FingerprintRequest): Promise<FingerprintResponse> {
    return this.post<FingerprintResponse>('/fingerprint', req);
  }

  public static async loadSampleArtifacts(): Promise<{
    document: FilePayload;
    signature: FilePayload;
    publicKey: FilePayload;
  }> {
    return this.post('/sample-artifacts', {});
  }
}
