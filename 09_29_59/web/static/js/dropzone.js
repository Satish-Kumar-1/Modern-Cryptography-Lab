/**
 * Drag-and-Drop Dropzone Manager (TypeScript).
 * Provides interactive file drag-and-drop zones with hover effects,
 * file validation, and binary FileReader encoding.
 */
export class Dropzone {
    element;
    fileInput;
    previewArea;
    idleArea;
    fileNameEl;
    fileSizeEl;
    clearBtn;
    currentFile = null;
    options;
    constructor(containerId, options = {}) {
        const el = document.getElementById(containerId);
        if (!el) {
            throw new Error(`Dropzone container with id "${containerId}" not found.`);
        }
        this.element = el;
        this.options = options;
        this.fileInput = el.querySelector('.dropzone-file-input');
        this.idleArea = el.querySelector('.dropzone-idle');
        this.previewArea = el.querySelector('.dropzone-preview');
        this.fileNameEl = el.querySelector('.dropzone-file-name');
        this.fileSizeEl = el.querySelector('.dropzone-file-size');
        this.clearBtn = el.querySelector('.dropzone-clear-btn');
        this.initEvents();
    }
    initEvents() {
        // Click on dropzone to open file dialog
        this.element.addEventListener('click', (e) => {
            if (e.target.closest('.dropzone-clear-btn')) {
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
            this.element.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.element.classList.add('drag-over');
            });
        });
        ['dragleave', 'dragend'].forEach((eventName) => {
            this.element.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.element.classList.remove('drag-over');
            });
        });
        this.element.addEventListener('drop', (e) => {
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
    async processFile(file) {
        // Validate file extensions if provided
        if (this.options.acceptExtensions && this.options.acceptExtensions.length > 0) {
            const ext = '.' + file.name.split('.').pop()?.toLowerCase();
            const valid = this.options.acceptExtensions.some((allowed) => allowed.toLowerCase() === ext || allowed === '*.*');
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
    readFileAsBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
                const result = reader.result;
                // Strip data:URL prefix (e.g. data:application/octet-stream;base64,...)
                const base64 = result.includes(',') ? result.split(',')[1] : result;
                resolve(base64);
            };
            reader.onerror = (error) => reject(error);
            reader.readAsDataURL(file);
        });
    }
    setFile(file) {
        this.currentFile = file;
        this.updatePreview(file);
        if (this.options.onFileSelect) {
            this.options.onFileSelect(file);
        }
    }
    updatePreview(file) {
        if (this.fileNameEl)
            this.fileNameEl.textContent = file.name;
        if (this.fileSizeEl)
            this.fileSizeEl.textContent = this.formatBytes(file.size);
        this.idleArea.classList.add('hidden');
        this.previewArea.classList.remove('hidden');
        this.element.classList.add('has-file');
    }
    clear() {
        this.currentFile = null;
        this.fileInput.value = '';
        this.idleArea.classList.remove('hidden');
        this.previewArea.classList.add('hidden');
        this.element.classList.remove('has-file');
        if (this.options.onFileClear) {
            this.options.onFileClear();
        }
    }
    getFile() {
        return this.currentFile;
    }
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0)
            return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
}
