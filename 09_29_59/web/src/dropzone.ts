/**
 * Drag-and-Drop Dropzone Manager (TypeScript).
 * Provides interactive file drag-and-drop zones with hover effects,
 * file validation, and binary FileReader encoding.
 */

import type { DropzoneOptions, FilePayload } from './types.js';

export class Dropzone {
  private element: HTMLElement;
  private fileInput: HTMLInputElement;
  private previewArea: HTMLElement;
  private idleArea: HTMLElement;
  private fileNameEl: HTMLElement;
  private fileSizeEl: HTMLElement;
  private clearBtn: HTMLElement;
  private currentFile: FilePayload | null = null;
  private options: DropzoneOptions;

  constructor(containerId: string, options: DropzoneOptions = {}) {
    const el = document.getElementById(containerId);
    if (!el) {
      throw new Error(`Dropzone container with id "${containerId}" not found.`);
    }
    this.element = el;
    this.options = options;

    this.fileInput = el.querySelector<HTMLInputElement>('.dropzone-file-input')!;
    this.idleArea = el.querySelector<HTMLElement>('.dropzone-idle')!;
    this.previewArea = el.querySelector<HTMLElement>('.dropzone-preview')!;
    this.fileNameEl = el.querySelector<HTMLElement>('.dropzone-file-name')!;
    this.fileSizeEl = el.querySelector<HTMLElement>('.dropzone-file-size')!;
    this.clearBtn = el.querySelector<HTMLElement>('.dropzone-clear-btn')!;

    this.initEvents();
  }

  private initEvents(): void {
    // Click on dropzone to open file dialog
    this.element.addEventListener('click', (e) => {
      if ((e.target as HTMLElement).closest('.dropzone-clear-btn')) {
        return;
      }
      this.fileInput.click();
    });

    // File input change
    this.fileInput.addEventListener('change', () => {
      if (this.fileInput.files && this.fileInput.files.length > 0) {
        this.processFile(this.fileInput.files[0]);
      }
    });

    // Drag-and-drop event listeners
    ['dragenter', 'dragover'].forEach((eventName) => {
      this.element.addEventListener(eventName, (e: Event) => {
        e.preventDefault();
        e.stopPropagation();
        this.element.classList.add('drag-over');
      });
    });

    ['dragleave', 'dragend'].forEach((eventName) => {
      this.element.addEventListener(eventName, (e: Event) => {
        e.preventDefault();
        e.stopPropagation();
        this.element.classList.remove('drag-over');
      });
    });

    this.element.addEventListener('drop', (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      this.element.classList.remove('drag-over');

      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        this.processFile(e.dataTransfer.files[0]);
      }
    });

    // Clear button
    if (this.clearBtn) {
      this.clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.clear();
      });
    }
  }

  public async processFile(file: File): Promise<void> {
    // Validate file extensions if provided
    if (this.options.acceptExtensions && this.options.acceptExtensions.length > 0) {
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();
      const valid = this.options.acceptExtensions.some((allowed) =>
        allowed.toLowerCase() === ext || allowed === '*.*'
      );
      if (!valid) {
        alert(`Invalid file extension. Expected: ${this.options.acceptExtensions.join(', ')}`);
        return;
      }
    }

    // Read file bytes as Base64 string
    const base64Content = await this.readFileAsBase64(file);

    this.currentFile = {
      name: file.name,
      size: file.size,
      type: file.type || 'application/octet-stream',
      contentBase64: base64Content,
    };

    this.updatePreview(this.currentFile);

    if (this.options.onFileSelect) {
      this.options.onFileSelect(this.currentFile);
    }
  }

  private readFileAsBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        // Strip data:URL prefix (e.g. data:application/octet-stream;base64,...)
        const base64 = result.includes(',') ? result.split(',')[1] : result;
        resolve(base64);
      };
      reader.onerror = (error) => reject(error);
      reader.readAsDataURL(file);
    });
  }

  public setFile(file: FilePayload): void {
    this.currentFile = file;
    this.updatePreview(file);
    if (this.options.onFileSelect) {
      this.options.onFileSelect(file);
    }
  }

  private updatePreview(file: FilePayload): void {
    if (this.fileNameEl) this.fileNameEl.textContent = file.name;
    if (this.fileSizeEl) this.fileSizeEl.textContent = this.formatBytes(file.size);

    this.idleArea.classList.add('hidden');
    this.previewArea.classList.remove('hidden');
    this.element.classList.add('has-file');
  }

  public clear(): void {
    this.currentFile = null;
    this.fileInput.value = '';
    this.idleArea.classList.remove('hidden');
    this.previewArea.classList.add('hidden');
    this.element.classList.remove('has-file');

    if (this.options.onFileClear) {
      this.options.onFileClear();
    }
  }

  public getFile(): FilePayload | null {
    return this.currentFile;
  }

  private formatBytes(bytes: number, decimals: number = 2): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }
}
