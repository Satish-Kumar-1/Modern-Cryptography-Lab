/**
 * CryptoGuard API Client.
 * Communicates with the in-memory Python cryptographic engine via JSON over HTTP.
 */
const API_BASE = '/api';
export class CryptoGuardApi {
    static async post(endpoint, body) {
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
        }
        catch (err) {
            console.error(`API Error on ${endpoint}:`, err);
            throw err;
        }
    }
    static async verifyDocument(req) {
        return this.post('/verify', req);
    }
    static async signDocument(req) {
        return this.post('/sign', req);
    }
    static async generateKeys(req) {
        return this.post('/keygen', req);
    }
    static async computeFingerprint(req) {
        return this.post('/fingerprint', req);
    }
    static async loadSampleArtifacts() {
        return this.post('/sample-artifacts', {});
    }
}
