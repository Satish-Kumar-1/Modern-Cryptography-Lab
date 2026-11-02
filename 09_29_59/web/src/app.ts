/**
 * CryptoGuard Main Application Controller (TypeScript).
 * Orchestrates vertical tab switching, dropzone bindings, API interactions,
 * and dynamic UI rendering.
 */

import { CryptoGuardApi } from './api.js';
import { Dropzone } from './dropzone.js';
import type { FilePayload } from './types.js';

class CryptoGuardApp {
  // Dropzones
  private verifyDocDropzone!: Dropzone;
  private verifySigDropzone!: Dropzone;
  private verifyPubDropzone!: Dropzone;

  private signDocDropzone!: Dropzone;
  private signPrivDropzone!: Dropzone;

  private fpPubDropzone!: Dropzone;

  constructor() {
    this.initTheme();
    this.initTabs();
    this.initDropzones();
    this.initVerifyActions();
    this.initSignActions();
    this.initKeygenActions();
    this.initFingerprintActions();
    this.initDesktopMode();
  }

  // -------------------------------------------------------------
  // Theme Management (Dark / Light)
  // -------------------------------------------------------------
  private initDesktopMode(): void {
    const desktop = (window as any).cryptoGuardDesktop;
    if (desktop && desktop.isElectron) {
      const badge = document.getElementById('appModeBadge');
      if (badge) {
        badge.style.display = 'inline-flex';
        badge.textContent = "Electron Desktop App (v" + desktop.electronVersion + ")";
      }
    }
  }

  private initTheme(): void {
    const toggleBtn = document.getElementById('theme-toggle-btn');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const savedTheme = localStorage.getItem('cryptoguard_theme') || (prefersDark ? 'dark' : 'dark');

    document.documentElement.setAttribute('data-theme', savedTheme);
    this.updateThemeButton(savedTheme);

    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('cryptoguard_theme', next);
        this.updateThemeButton(next);
      });
    }
  }

  private updateThemeButton(theme: string): void {
    const iconEl = document.getElementById('theme-icon');
    const textEl = document.getElementById('theme-text');
    if (iconEl && textEl) {
      if (theme === 'dark') {
        iconEl.innerHTML = '&#9728;'; // Sun icon
        textEl.textContent = 'Light Mode';
      } else {
        iconEl.innerHTML = '&#9790;'; // Moon icon
        textEl.textContent = 'Dark Mode';
      }
    }
  }

  // -------------------------------------------------------------
  // Vertical Navigation Tabs
  // -------------------------------------------------------------
  private initTabs(): void {
    const navButtons = document.querySelectorAll<HTMLButtonElement>('.nav-tab-btn');
    const tabPanels = document.querySelectorAll<HTMLElement>('.tab-panel');

    navButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        if (!targetTab) return;

        navButtons.forEach((b) => b.classList.remove('active'));
        tabPanels.forEach((p) => p.classList.remove('active'));

        btn.classList.add('active');
        const panel = document.getElementById(`tab-${targetTab}`);
        if (panel) panel.classList.add('active');
      });
    });
  }

  // -------------------------------------------------------------
  // Dropzone Initializations
  // -------------------------------------------------------------
  private initDropzones(): void {
    // 1. Verify Dropzones
    this.verifyDocDropzone = new Dropzone('verify-doc-dropzone');
    this.verifySigDropzone = new Dropzone('verify-sig-dropzone', {
      acceptExtensions: ['.sig'],
    });
    this.verifyPubDropzone = new Dropzone('verify-pub-dropzone', {
      acceptExtensions: ['.pem', '.pub'],
    });

    // 2. Sign Dropzones
    this.signDocDropzone = new Dropzone('sign-doc-dropzone');
    this.signPrivDropzone = new Dropzone('sign-priv-dropzone', {
      acceptExtensions: ['.pem', '.key', '.pkcs8'],
    });

    // 3. Fingerprint Dropzone
    this.fpPubDropzone = new Dropzone('fp-pub-dropzone', {
      acceptExtensions: ['.pem', '.pub'],
      onFileSelect: () => this.computeFingerprintAuto(),
    });
  }

  // -------------------------------------------------------------
  // 1. Verify Tab Actions
  // -------------------------------------------------------------
  private initVerifyActions(): void {
    const verifyBtn = document.getElementById('btn-verify-submit');
    const loadSampleBtn = document.getElementById('btn-load-sample-artifacts');
    const clearBtn = document.getElementById('btn-verify-clear');
    const resultBox = document.getElementById('verify-result-box')!;

    if (loadSampleBtn) {
      loadSampleBtn.addEventListener('click', async () => {
        try {
          loadSampleBtn.classList.add('loading');
          const artifacts = await CryptoGuardApi.loadSampleArtifacts();
          this.verifyDocDropzone.setFile(artifacts.document);
          this.verifySigDropzone.setFile(artifacts.signature);
          this.verifyPubDropzone.setFile(artifacts.publicKey);
          resultBox.classList.add('hidden');
        } catch (err: any) {
          alert('Could not load sample artifacts: ' + err.message);
        } finally {
          loadSampleBtn.classList.remove('loading');
        }
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        this.verifyDocDropzone.clear();
        this.verifySigDropzone.clear();
        this.verifyPubDropzone.clear();
        resultBox.classList.add('hidden');
      });
    }

    if (verifyBtn) {
      verifyBtn.addEventListener('click', async () => {
        const doc = this.verifyDocDropzone.getFile();
        const sig = this.verifySigDropzone.getFile();
        const pub = this.verifyPubDropzone.getFile();

        if (!doc || !sig || !pub) {
          alert('Please provide all 3 files: Document, Detached Signature (.sig), and Signer Public Key (.pem).');
          return;
        }

        try {
          verifyBtn.classList.add('loading');
          const res = await CryptoGuardApi.verifyDocument({
            document: doc.contentBase64,
            signature: sig.contentBase64,
            publicKey: pub.contentBase64,
          });

          this.renderVerifyResult(res);
        } catch (err: any) {
          alert('Verification request failed: ' + err.message);
        } finally {
          verifyBtn.classList.remove('loading');
        }
      });
    }
  }

  private renderVerifyResult(res: any): void {
    const box = document.getElementById('verify-result-box')!;
    const titleEl = document.getElementById('verify-result-title')!;
    const msgEl = document.getElementById('verify-result-message')!;
    const detailsEl = document.getElementById('verify-result-details')!;
    const fpContainer = document.getElementById('verify-signer-fp-box')!;
    const fpValue = document.getElementById('verify-signer-fp-value')!;

    box.classList.remove('hidden', 'banner-success', 'banner-error');

    if (res.is_valid) {
      box.classList.add('banner-success');
      titleEl.textContent = 'AUTHENTIC & UNMODIFIED';
      msgEl.textContent = res.message;
      detailsEl.textContent = res.details || 'Cryptographic verification confirmed under RFC 8032 Ed25519.';

      if (res.fingerprint) {
        fpValue.textContent = res.fingerprint;
        fpContainer.classList.remove('hidden');
      } else {
        fpContainer.classList.add('hidden');
      }
    } else {
      box.classList.add('banner-error');
      titleEl.textContent = 'VERIFICATION FAILED (NOT AUTHENTIC)';
      msgEl.textContent = res.message;
      detailsEl.textContent = res.details || 'The mathematical verification failed under the provided public key.';
      fpContainer.classList.add('hidden');
    }
  }

  // -------------------------------------------------------------
  // 2. Sign Tab Actions
  // -------------------------------------------------------------
  private initSignActions(): void {
    const signBtn = document.getElementById('btn-sign-submit');
    const passInput = document.getElementById('sign-passphrase') as HTMLInputElement;
    const togglePassBtn = document.getElementById('btn-toggle-sign-pass');
    const resultBox = document.getElementById('sign-result-box')!;

    if (togglePassBtn) {
      togglePassBtn.addEventListener('click', () => {
        passInput.type = passInput.type === 'password' ? 'text' : 'password';
        togglePassBtn.textContent = passInput.type === 'password' ? 'Show' : 'Hide';
      });
    }

    if (signBtn) {
      signBtn.addEventListener('click', async () => {
        const doc = this.signDocDropzone.getFile();
        const priv = this.signPrivDropzone.getFile();

        if (!doc || !priv) {
          alert('Please select both the Document to sign and the Private Key.');
          return;
        }

        try {
          signBtn.classList.add('loading');
          const res = await CryptoGuardApi.signDocument({
            document: doc.contentBase64,
            privateKey: priv.contentBase64,
            password: passInput.value || undefined,
          });

          if (res.success && res.signature) {
            resultBox.classList.remove('hidden');
            const downloadBtn = document.getElementById('btn-download-sig')!;
            const sigFilename = `${doc.name}.sig`;

            downloadBtn.onclick = () => {
              this.downloadBase64File(res.signature!, sigFilename, 'application/octet-stream');
            };
          } else {
            alert('Signing failed: ' + (res.error || res.message));
          }
        } catch (err: any) {
          alert('Signing error: ' + err.message);
        } finally {
          signBtn.classList.remove('loading');
        }
      });
    }
  }

  // -------------------------------------------------------------
  // 3. Key Generation Tab Actions
  // -------------------------------------------------------------
  private initKeygenActions(): void {
    const keygenBtn = document.getElementById('btn-keygen-submit');
    const encCheckbox = document.getElementById('keygen-encrypt-toggle') as HTMLInputElement;
    const passContainer = document.getElementById('keygen-pass-container')!;
    const p1 = document.getElementById('keygen-pass1') as HTMLInputElement;
    const p2 = document.getElementById('keygen-pass2') as HTMLInputElement;
    const resultBox = document.getElementById('keygen-result-box')!;

    if (encCheckbox) {
      encCheckbox.addEventListener('change', () => {
        passContainer.classList.toggle('hidden', !encCheckbox.checked);
      });
    }

    if (keygenBtn) {
      keygenBtn.addEventListener('click', async () => {
        let password: string | undefined = undefined;

        if (encCheckbox.checked) {
          if (!p1.value) {
            alert('Passphrase encryption is enabled. Please enter a passphrase.');
            return;
          }
          if (p1.value !== p2.value) {
            alert('Passphrase confirmation does not match.');
            return;
          }
          password = p1.value;
        }

        try {
          keygenBtn.classList.add('loading');
          const res = await CryptoGuardApi.generateKeys({ password });

          if (res.success && res.private_key && res.public_key) {
            resultBox.classList.remove('hidden');
            const fpEl = document.getElementById('keygen-fp-value')!;
            fpEl.textContent = res.fingerprint || '';

            document.getElementById('btn-download-priv')!.onclick = () => {
              this.downloadTextFile(res.private_key!, 'ed25519_private_key.pem', 'application/x-pem-file');
            };
            document.getElementById('btn-download-pub')!.onclick = () => {
              this.downloadTextFile(res.public_key!, 'ed25519_public_key.pem', 'application/x-pem-file');
            };
          } else {
            alert('Key generation failed: ' + res.error);
          }
        } catch (err: any) {
          alert('Key generation error: ' + err.message);
        } finally {
          keygenBtn.classList.remove('loading');
        }
      });
    }
  }

  // -------------------------------------------------------------
  // 4. Fingerprint Tab Actions
  // -------------------------------------------------------------
  private initFingerprintActions(): void {
    const verifyTrustBtn = document.getElementById('btn-verify-trust');
    const expInput = document.getElementById('fp-expected-hash') as HTMLInputElement;
    const copyBtn = document.getElementById('btn-copy-fp');
    const fpResult = document.getElementById('fp-display-value')!;

    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        const text = fpResult.textContent?.trim();
        if (text) {
          navigator.clipboard.writeText(text);
          copyBtn.textContent = 'Copied!';
          setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
        }
      });
    }

    if (verifyTrustBtn) {
      verifyTrustBtn.addEventListener('click', async () => {
        const pub = this.fpPubDropzone.getFile();
        const expected = expInput.value.trim();

        if (!pub) {
          alert('Please drop or select a public key (.pem).');
          return;
        }
        if (!expected) {
          alert('Please enter an expected trusted reference fingerprint.');
          return;
        }

        try {
          verifyTrustBtn.classList.add('loading');
          const res = await CryptoGuardApi.computeFingerprint({
            publicKey: pub.contentBase64,
            expected,
          });

          const trustResultBox = document.getElementById('fp-trust-result-box')!;
          trustResultBox.classList.remove('hidden', 'banner-success', 'banner-error');

          if (res.matches === true) {
            trustResultBox.classList.add('banner-success');
            trustResultBox.innerHTML = `
              <strong>&#10004; TRUSTED ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â FINGERPRINT MATCHES</strong><br/>
              The public key matches the authenticated reference value. Public-key substitution is ruled out.
            `;
          } else {
            trustResultBox.classList.add('banner-error');
            trustResultBox.innerHTML = `
              <strong>&#9888; UNTRUSTED ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â FINGERPRINT MISMATCH</strong><br/>
              The public key does NOT match the expected reference!<br/>
              Calculated: <code>${res.fingerprint}</code><br/>
              Expected: <code>${expected}</code><br/>
              Warning: This public key may have been substituted by an attacker (Experiment 5).
            `;
          }
        } catch (err: any) {
          alert('Fingerprint error: ' + err.message);
        } finally {
          verifyTrustBtn.classList.remove('loading');
        }
      });
    }
  }

  private async computeFingerprintAuto(): Promise<void> {
    const pub = this.fpPubDropzone.getFile();
    if (!pub) return;

    try {
      const res = await CryptoGuardApi.computeFingerprint({ publicKey: pub.contentBase64 });
      if (res.success && res.fingerprint) {
        document.getElementById('fp-display-box')!.classList.remove('hidden');
        document.getElementById('fp-display-value')!.textContent = res.fingerprint;
      }
    } catch (err: any) {
      console.error('Auto fingerprint failed:', err);
    }
  }

  // -------------------------------------------------------------
  // Utility Download Functions
  // -------------------------------------------------------------
  private downloadTextFile(text: string, filename: string, mime: string): void {
    const blob = new Blob([text], { type: mime });
    this.triggerDownload(blob, filename);
  }

  private downloadBase64File(base64: string, filename: string, mime: string): void {
    const byteCharacters = atob(base64);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], { type: mime });
    this.triggerDownload(blob, filename);
  }

  private triggerDownload(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  new CryptoGuardApp();
});
