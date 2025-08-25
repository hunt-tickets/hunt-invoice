import './style.css'
import { translations } from './translations.js'
import { getWebhookConfig, validateWebhookConfig } from './config.js'

class InvoiceForm {
  constructor() {
    this.form = document.getElementById('invoice-form')
    this.submitBtn = document.getElementById('submit-btn')
    this.fileInput = document.getElementById('invoice')
    this.fileList = document.getElementById('file-list')
    this.fileInputDisplay = document.querySelector('.file-input-display .file-text')
    this.successMessage = document.getElementById('success-message')
    this.selectedFile = null
    this.currentLang = 'es'
    this.lastSubmissionTime = 0
    this.submissionAttempts = 0
    this.maxAttemptsPerMinute = 5
    
    // Webhook configuration
    this.webhookConfig = getWebhookConfig()
    validateWebhookConfig(this.webhookConfig)
    
    // Session security
    this.sessionId = this.generateSessionId()
    
    this.init()
  }

  init() {
    this.setupEventListeners()
    this.setupFileUpload()
    this.setupLanguageToggle()
  }

  // Security: Sanitize input to prevent XSS attacks
  sanitizeInput(input) {
    if (typeof input !== 'string') return input
    
    const entityMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    }
    
    return input.replace(/[&<>"'`=\/]/g, (s) => entityMap[s])
  }

  // Security: Enhanced input validation with length limits and character whitelists
  isValidInput(value, type) {
    const maxLengths = {
      fullName: 100,
      email: 254,
      description: 1000
    }

    const patterns = {
      fullName: /^[a-zA-ZÀ-ÿ\u00C0-\u017F\s'-]{2,100}$/,
      email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
      description: /^[\s\S]{0,1000}$/
    }

    // Check length
    if (value.length > (maxLengths[type] || 500)) {
      return false
    }

    // Check pattern if exists
    if (patterns[type]) {
      return patterns[type].test(value)
    }

    return true
  }

  // Security: Log suspicious input attempts
  logSecurityEvent(field, value, reason) {
    const timestamp = new Date().toISOString()
    console.warn(`Security Alert [${timestamp}]: Suspicious input detected`, {
      field,
      reason,
      valueLength: value.length,
      userAgent: navigator.userAgent,
      url: window.location.href
    })
  }

  // Simple rate limiting for form submissions
  async checkRateLimit() {
    const now = Date.now()
    const oneMinute = 60 * 1000

    // Reset counter if more than a minute has passed
    if (now - this.lastSubmissionTime > oneMinute) {
      this.submissionAttempts = 0
    }

    // Check if too many attempts
    if (this.submissionAttempts >= this.maxAttemptsPerMinute) {
      const timeLeft = Math.ceil((oneMinute - (now - this.lastSubmissionTime)) / 1000)
      this.showError('form', `Demasiados intentos. Espere ${timeLeft} segundos.`)
      return false
    }

    return true
  }

  setupEventListeners() {
    this.form.addEventListener('submit', (e) => this.handleSubmit(e))
    
    const inputs = this.form.querySelectorAll('input[required], textarea')
    inputs.forEach(input => {
      input.addEventListener('input', () => this.clearError(input))
    })
  }

  setupFileUpload() {
    this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e))
    
    const fileInputWrapper = document.querySelector('.file-input-wrapper')
    
    fileInputWrapper.addEventListener('dragover', (e) => {
      e.preventDefault()
      fileInputWrapper.classList.add('dragover')
    })
    
    fileInputWrapper.addEventListener('dragleave', () => {
      fileInputWrapper.classList.remove('dragover')
    })
    
    fileInputWrapper.addEventListener('drop', (e) => {
      e.preventDefault()
      fileInputWrapper.classList.remove('dragover')
      this.handleFileSelect({ target: { files: e.dataTransfer.files } })
    })
  }

  async handleFileSelect(e) {
    const file = e.target.files[0]
    
    if (file && await this.validateFile(file)) {
      this.selectedFile = file
      this.updateFileDisplay()
      this.updateFileInputText()
    }
  }

  async validateFile(file) {
    const maxSize = 5 * 1024 * 1024 // 5MB
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf']
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.pdf']
    
    // Security: Sanitize filename to prevent path traversal
    const sanitizedName = this.sanitizeInput(file.name)
    const fileExtension = sanitizedName.toLowerCase().substring(sanitizedName.lastIndexOf('.'))
    
    // Security: Check for suspicious filenames
    if (file.name.includes('..') || file.name.includes('/') || file.name.includes('\\')) {
      this.logSecurityEvent('file', file.name, 'Suspicious filename with path characters')
      this.showError('invoice', `"${sanitizedName}" contiene caracteres no permitidos`)
      return false
    }
    
    // Security: Validate file size
    if (file.size > maxSize) {
      this.showError('invoice', `"${sanitizedName}" ${this.t('file-too-large')}`)
      return false
    }
    
    // Security: Double-check MIME type and extension
    if (!allowedTypes.includes(file.type) || !allowedExtensions.includes(fileExtension)) {
      this.logSecurityEvent('file', file.name, `Invalid file type: ${file.type}, extension: ${fileExtension}`)
      this.showError('invoice', `"${sanitizedName}" ${this.t('file-type-error')}`)
      return false
    }
    
    // Security: Additional checks for executable files disguised as documents
    const executableExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar', '.js', '.vbs', '.ps1']
    if (executableExtensions.some(ext => sanitizedName.toLowerCase().includes(ext))) {
      this.logSecurityEvent('file', file.name, 'Executable file detected')
      this.showError('invoice', `"${sanitizedName}" tipo de archivo no permitido por seguridad`)
      return false
    }
    
    // Security: Validate actual file content
    const isValidContent = await this.validateFileContent(file)
    if (!isValidContent) {
      this.logSecurityEvent('file', file.name, 'File content does not match declared type')
      this.showError('invoice', `"${sanitizedName}" el contenido del archivo no coincide con el formato declarado`)
      return false
    }
    
    return true
  }

  updateFileDisplay() {
    this.fileList.innerHTML = ''
    
    if (this.selectedFile) {
      const fileItem = document.createElement('div')
      fileItem.className = 'file-item'
      
      // Security: Sanitize filename before displaying
      const sanitizedFileName = this.sanitizeInput(this.selectedFile.name)
      
      fileItem.innerHTML = `
        <span class="file-name">${sanitizedFileName}</span>
        <span class="file-size">${this.formatFileSize(this.selectedFile.size)}</span>
        <button type="button" class="file-remove" data-index="0">✕</button>
      `
      
      const removeBtn = fileItem.querySelector('.file-remove')
      removeBtn.addEventListener('click', () => this.removeFile())
      
      this.fileList.appendChild(fileItem)
    }
  }

  updateFileInputText() {
    if (!this.selectedFile) {
      this.fileInputDisplay.textContent = this.t('select-invoice')
    } else {
      this.fileInputDisplay.textContent = `1 ${this.t('file-selected')}`
    }
  }

  removeFile() {
    this.selectedFile = null
    this.fileInput.value = ''
    this.updateFileDisplay()
    this.updateFileInputText()
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  validateField(field) {
    const rawValue = field.value.trim()
    const fieldName = field.name
    
    this.clearError(field)
    
    // Security: Check for suspicious input patterns
    if (rawValue.includes('<script') || rawValue.includes('javascript:') || rawValue.includes('data:text/html')) {
      this.logSecurityEvent(fieldName, rawValue, 'Potential XSS attempt')
      this.showError(fieldName, this.t('invalid-input'))
      return false
    }
    
    // Security: Sanitize the input
    const value = this.sanitizeInput(rawValue)
    
    // Security: Enhanced validation with whitelist patterns
    if (!this.isValidInput(value, fieldName)) {
      this.logSecurityEvent(fieldName, rawValue, 'Invalid input format or length')
      this.showError(fieldName, this.t('invalid-format'))
      return false
    }
    
    if (!value && field.required) {
      this.showError(fieldName, this.t('required-field'))
      return false
    }
    
    if (fieldName === 'fullName' && value.length < 2) {
      this.showError(fieldName, this.t('name-length'))
      return false
    }
    
    if (fieldName === 'email' && value) {
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
      if (!emailRegex.test(value)) {
        this.showError(fieldName, this.t('invalid-email'))
        return false
      }
    }
    
    return true
  }

  showError(fieldName, message) {
    const errorElement = document.getElementById(`${fieldName}-error`)
    const fieldElement = document.getElementById(fieldName) || document.querySelector(`[name="${fieldName}"]`)
    
    if (errorElement) {
      errorElement.textContent = message
      errorElement.classList.add('show')
    }
    
    if (fieldElement) {
      fieldElement.classList.add('error')
    }
  }

  clearError(field) {
    const fieldName = field.name || field.id
    const errorElement = document.getElementById(`${fieldName}-error`)
    
    if (errorElement) {
      errorElement.classList.remove('show')
    }
    
    field.classList.remove('error')
  }

  validateForm() {
    const requiredFields = this.form.querySelectorAll('input[required], textarea[required]')
    let isValid = true
    
    requiredFields.forEach(field => {
      if (field.type !== 'checkbox' && field.type !== 'file' && !this.validateField(field)) {
        isValid = false
      }
    })

    // Validate file
    if (!this.selectedFile) {
      this.showError('invoice', this.t('file-required'))
      isValid = false
    }

    // Validate checkboxes
    const acceptTerms = document.getElementById('acceptTerms')
    if (!acceptTerms.checked) {
      this.showError('acceptTerms', this.t('accept-terms-error'))
      isValid = false
    }
    
    return isValid
  }

  async handleSubmit(e) {
    e.preventDefault()
    
    // Check rate limit
    if (!(await this.checkRateLimit())) {
      return
    }
    
    // Update submission tracking
    this.submissionAttempts++
    this.lastSubmissionTime = Date.now()
    
    if (!this.validateForm()) {
      return
    }
    
    this.setLoading(true)
    
    try {
      let fileUploadResult = null
      
      // Upload file to storage first
      if (this.selectedFile) {
        console.info('Uploading file to storage before webhook submission')
        fileUploadResult = await this.uploadFileToStorage(this.selectedFile)
      }
      
      const formData = new FormData()
      
      // Security: Sanitize all form data before submission
      const formFields = new FormData(this.form)
      for (let [key, value] of formFields.entries()) {
        if (typeof value === 'string' && key !== 'invoice') {
          formData.append(key, this.sanitizeInput(value))
        }
      }
      
      // Add file information instead of the actual file
      if (fileUploadResult) {
        formData.append('fileInfo', JSON.stringify({
          fileName: fileUploadResult.fileName,
          url: fileUploadResult.url,
          uuid: fileUploadResult.uuid,
          extension: fileUploadResult.extension,
          originalName: fileUploadResult.originalName,
          size: fileUploadResult.size,
          type: fileUploadResult.type,
          uploadedAt: new Date().toISOString()
        }))
      }
      
      // Log submission attempt
      console.info('Invoice submission attempt', {
        timestamp: new Date().toISOString(),
        fields: Array.from(formData.keys()),
        hasFile: !!this.selectedFile,
        fileUploaded: !!fileUploadResult
      })
      
      // Submit to n8n webhook
      const result = await this.submitToWebhook(formData)
      
      this.showSuccess(result)
      this.resetForm()
      
    } catch (error) {
      console.error('Error submitting form:', error)
      
      // Handle specific errors including file upload errors
      let errorMessage = this.t('form-error')
      
      if (error.message.includes('Failed to upload file')) {
        errorMessage = 'Error al subir el archivo. Intente nuevamente.'
      } else if (error.message.includes('Storage upload failed')) {
        errorMessage = 'Error en el almacenamiento del archivo. Intente nuevamente.'
      } else if (error.message.includes('HTTP 400')) {
        errorMessage = this.t('invalid-data-error')
      } else if (error.message.includes('HTTP 401') || error.message.includes('HTTP 403')) {
        errorMessage = this.t('auth-error')
      } else if (error.message.includes('HTTP 413')) {
        errorMessage = this.t('file-too-large')
      } else if (error.message.includes('HTTP 429')) {
        errorMessage = this.t('rate-limit-error')
      } else if (error.message.includes('HTTP 5')) {
        errorMessage = this.t('server-error')
      } else if (error.message.includes('timeout') || error.name === 'AbortError') {
        errorMessage = this.t('timeout-error')
      } else if (error.message.includes('Failed to fetch') || error.message.includes('Network')) {
        errorMessage = this.t('network-error')
      }
      
      this.showError('form', errorMessage)
    } finally {
      this.setLoading(false)
    }
  }

  async submitToWebhook(formData) {
    let lastError = null
    
    for (let attempt = 0; attempt <= this.webhookConfig.retries; attempt++) {
      try {
        console.info(`Sending invoice to n8n webhook (attempt ${attempt + 1}/${this.webhookConfig.retries + 1})`)
        
        const headers = {
          'Accept': 'application/json'
        }
        
        // Add authentication if configured
        if (this.webhookConfig.authToken) {
          headers['Authorization'] = `Bearer ${this.webhookConfig.authToken}`
        }
        
        // Add metadata for n8n processing
        const metadata = {
          timestamp: new Date().toISOString(),
          language: this.currentLang,
          userAgent: navigator.userAgent,
          source: 'hunt-invoice-form',
          formVersion: '1.0.0',
          sessionId: this.sessionId,
          clientFingerprint: this.generateClientFingerprint()
        }
        
        formData.append('metadata', JSON.stringify(metadata))
        
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), this.webhookConfig.timeout)
        
        const response = await fetch(this.webhookConfig.url, {
          method: 'POST',
          headers,
          body: formData,
          signal: controller.signal
        })
        
        clearTimeout(timeoutId)
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }
        
        const result = await response.json()
        
        console.info('Invoice successfully sent to n8n:', {
          status: result.status || 'success',
          processingId: result.processingId || null,
          timestamp: new Date().toISOString()
        })
        
        return result
        
      } catch (error) {
        lastError = error
        
        if (error.name === 'AbortError') {
          console.warn(`Webhook timeout on attempt ${attempt + 1}`)
        } else {
          console.warn(`Webhook error on attempt ${attempt + 1}:`, error.message)
        }
        
        // Don't retry on client errors (4xx)
        if (error.message.includes('HTTP 4')) {
          break
        }
        
        // Wait before retry (exponential backoff)
        if (attempt < this.webhookConfig.retries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000))
        }
      }
    }
    
    // All attempts failed
    throw new Error(`Failed to submit invoice after ${this.webhookConfig.retries + 1} attempts: ${lastError.message}`)
  }

  setLoading(loading) {
    if (loading) {
      this.submitBtn.disabled = true
      this.submitBtn.classList.add('loading')
    } else {
      this.submitBtn.disabled = false
      this.submitBtn.classList.remove('loading')
    }
  }

  showSuccess(result) {
    // Update success message with processing information if available
    if (result && result.processingId) {
      const successText = this.successMessage.querySelector('p')
      const currentText = successText.getAttribute(`data-${this.currentLang}`)
      const processingInfo = this.currentLang === 'es' 
        ? ` ID de procesamiento: ${result.processingId}`
        : ` Processing ID: ${result.processingId}`
      successText.textContent = currentText + processingInfo
    }
    
    this.successMessage.style.display = 'flex'
    this.successMessage.scrollIntoView({ behavior: 'smooth' })
  }

  resetForm() {
    this.form.reset()
    this.selectedFile = null
    this.updateFileDisplay()
    this.updateFileInputText()
    
    const errorMessages = this.form.querySelectorAll('.error-message.show')
    errorMessages.forEach(error => error.classList.remove('show'))
    
    const errorFields = this.form.querySelectorAll('.error')
    errorFields.forEach(field => field.classList.remove('error'))
  }

  setupLanguageToggle() {
    const langButtons = document.querySelectorAll('.lang-btn')
    
    langButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const selectedLang = e.target.dataset.lang
        if (selectedLang !== this.currentLang) {
          this.switchLanguage(selectedLang)
        }
      })
    })
  }

  switchLanguage(lang) {
    this.currentLang = lang
    
    // Update toggle position and button states
    const toggle = document.querySelector('.language-toggle')
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.remove('active')
      if (btn.dataset.lang === lang) {
        btn.classList.add('active')
      }
    })
    
    // Update toggle class for animation
    if (lang === 'en') {
      toggle.classList.add('en')
    } else {
      toggle.classList.remove('en')
    }
    
    // Update all translatable elements
    document.querySelectorAll('[data-es][data-en]').forEach(element => {
      const text = element.getAttribute(`data-${lang}`)
      if (text) {
        element.textContent = text
      }
    })
    
    // Update placeholders
    document.querySelectorAll('[data-placeholder-es][data-placeholder-en]').forEach(element => {
      const placeholder = element.getAttribute(`data-placeholder-${lang}`)
      if (placeholder) {
        element.placeholder = placeholder
      }
    })
    
    // Update file input text
    this.updateFileInputText()
  }

  t(key) {
    return translations[this.currentLang][key] || key
  }

  // Security: Generate session ID for tracking
  generateSessionId() {
    const timestamp = Date.now().toString(36)
    const randomPart = Math.random().toString(36).substring(2)
    return `sess_${timestamp}_${randomPart}`
  }

  // Security: Generate client fingerprint for basic validation
  generateClientFingerprint() {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    ctx.textBaseline = 'top'
    ctx.font = '14px Arial'
    ctx.fillText('Client fingerprint', 2, 2)
    
    const fingerprint = {
      screen: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      platform: navigator.platform,
      canvasHash: canvas.toDataURL().slice(-50)
    }
    
    return btoa(JSON.stringify(fingerprint)).substring(0, 32)
  }

  // Generate UUID v4
  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0
      const v = c == 'x' ? r : (r & 0x3 | 0x8)
      return v.toString(16)
    })
  }

  // Get file extension from filename
  getFileExtension(filename) {
    return filename.toLowerCase().substring(filename.lastIndexOf('.'))
  }

  // Upload file to storage endpoint
  async uploadFileToStorage(file) {
    const uuid = this.generateUUID()
    const extension = this.getFileExtension(file.name)
    const fileName = `${uuid}${extension}`
    const uploadUrl = `https://db.hunt-tickets.com/storage/v1/object/sign/invoice/main/${fileName}`
    
    try {
      console.info('Uploading file to storage:', { fileName, size: file.size, type: file.type })
      
      const formData = new FormData()
      formData.append('file', file)
      
      const response = await fetch(uploadUrl, {
        method: 'POST',
        body: formData
      })
      
      if (!response.ok) {
        throw new Error(`Storage upload failed: HTTP ${response.status}: ${response.statusText}`)
      }
      
      const result = {
        success: true,
        fileName,
        url: uploadUrl,
        uuid,
        extension: extension.substring(1), // Remove the dot
        originalName: file.name,
        size: file.size,
        type: file.type
      }
      
      console.info('File successfully uploaded to storage:', result)
      return result
      
    } catch (error) {
      console.error('Error uploading file to storage:', error)
      throw new Error(`Failed to upload file: ${error.message}`)
    }
  }

  // Security: Validate file content type beyond extension
  async validateFileContent(file) {
    return new Promise((resolve) => {
      const reader = new FileReader()
      reader.onload = (e) => {
        const buffer = e.target.result
        const view = new DataView(buffer)
        
        // Check file signatures (magic numbers)
        if (buffer.byteLength < 4) {
          resolve(false)
          return
        }
        
        // PDF signature
        if (file.type === 'application/pdf') {
          const signature = String.fromCharCode(view.getUint8(0), view.getUint8(1), view.getUint8(2), view.getUint8(3))
          resolve(signature === '%PDF')
          return
        }
        
        // JPEG signatures
        if (file.type === 'image/jpeg') {
          const signature = view.getUint16(0, false)
          resolve(signature === 0xFFD8)
          return
        }
        
        // PNG signature
        if (file.type === 'image/png') {
          const signature = view.getUint32(0, false)
          resolve(signature === 0x89504E47)
          return
        }
        
        resolve(false)
      }
      
      reader.onerror = () => resolve(false)
      reader.readAsArrayBuffer(file.slice(0, 16))
    })
  }
}

document.addEventListener('DOMContentLoaded', () => {
  // Initialize form
  const invoiceForm = new InvoiceForm()
  
  // Theme toggle functionality
  const themeToggle = document.getElementById('theme-toggle')
  
  // Check for saved theme preference or default to dark mode
  const savedTheme = localStorage.getItem('theme') || 'dark'
  document.documentElement.setAttribute('data-theme', savedTheme)
  
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme')
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark'
      
      document.documentElement.setAttribute('data-theme', newTheme)
      localStorage.setItem('theme', newTheme)
    })
  }
})