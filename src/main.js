import './style.css'
import { translations } from './translations.js'
import { getWebhookConfig, validateWebhookConfig } from './config.js'
import { jsPDF } from 'jspdf'

class InvoiceForm {
  constructor() {
    this.form = document.getElementById('invoice-form')
    this.submitBtn = document.getElementById('submit-btn')
    this.fileInput = document.getElementById('invoice')
    this.fileList = document.getElementById('file-list')
    this.fileInputDisplay = document.querySelector('.file-input-display .file-text')
    this.successMessage = document.getElementById('success-message')
    this.selectedFiles = []
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
    const files = Array.from(e.target.files)
    
    this.selectedFiles = []
    
    for (const file of files) {
      if (await this.validateFile(file)) {
        this.selectedFiles.push(file)
      }
    }
    
    this.updateFileDisplay()
    this.updateFileInputText()
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
    
    this.selectedFiles.forEach((file, index) => {
      const fileItem = document.createElement('div')
      fileItem.className = 'file-item'
      
      // Security: Sanitize filename before displaying
      const sanitizedFileName = this.sanitizeInput(file.name)
      
      fileItem.innerHTML = `
        <span class="file-name">${sanitizedFileName}</span>
        <span class="file-size">${this.formatFileSize(file.size)}</span>
        <button type="button" class="file-remove" data-index="${index}">✕</button>
      `
      
      const removeBtn = fileItem.querySelector('.file-remove')
      removeBtn.addEventListener('click', () => this.removeFile(index))
      
      this.fileList.appendChild(fileItem)
    })
  }

  updateFileInputText() {
    if (this.selectedFiles.length === 0) {
      this.fileInputDisplay.textContent = this.t('select-invoice')
    } else {
      this.fileInputDisplay.textContent = `${this.selectedFiles.length} ${this.selectedFiles.length === 1 ? 'archivo seleccionado' : 'archivos seleccionados'}`
    }
  }

  removeFile(index = null) {
    if (index !== null) {
      this.selectedFiles.splice(index, 1)
    } else {
      this.selectedFiles = []
    }
    
    if (this.selectedFiles.length === 0) {
      this.fileInput.value = ''
    }
    
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

    // Validate files
    if (this.selectedFiles.length === 0) {
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
    this.showProgressSection()
    
    try {
      const results = await this.processMultipleFiles()
      const successCount = results.filter(r => r.success).length
      const totalCount = results.length
      
      if (successCount > 0) {
        this.showSuccess({ 
          status: 'success', 
          processedCount: successCount,
          totalCount: totalCount,
          hasErrors: successCount < totalCount
        })
      } else {
        throw new Error('No se pudo procesar ningún archivo correctamente')
      }
      
      // Reset form after a delay to show results
      setTimeout(() => this.resetForm(), 3000)
      
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

  showProgressSection() {
    const progressSection = document.getElementById('progress-section')
    progressSection.style.display = 'block'
    progressSection.scrollIntoView({ behavior: 'smooth' })
    
    this.updateProgressCounter(0, this.selectedFiles.length)
    this.resetSteps()
  }

  hideProgressSection() {
    const progressSection = document.getElementById('progress-section')
    progressSection.style.display = 'none'
  }

  updateProgressCounter(completed, total) {
    const progressCounter = document.getElementById('progress-counter')
    const progressFill = document.getElementById('progress-fill')
    
    const percentage = total > 0 ? (completed / total) * 100 : 0
    progressCounter.textContent = `${completed} / ${total}`
    progressFill.style.width = `${percentage}%`
  }

  resetSteps() {
    const storageStep = document.getElementById('step-storage')
    const webhookStep = document.getElementById('step-webhook')
    const currentFile = document.getElementById('current-file')
    
    storageStep.className = 'step'
    webhookStep.className = 'step'
    
    document.getElementById('storage-status').textContent = 'Preparando...'
    document.getElementById('webhook-status').textContent = 'Esperando...'
    currentFile.textContent = ''
    currentFile.className = 'current-file'
  }

  updateStepStatus(step, status, message = '') {
    const stepElement = document.getElementById(`step-${step}`)
    const statusElement = document.getElementById(`${step}-status`)
    
    if (status === 'active') {
      stepElement.className = 'step active'
      statusElement.textContent = message || 'Procesando...'
    } else if (status === 'completed') {
      stepElement.className = 'step completed'
      statusElement.textContent = message || 'Completado'
    }
  }

  showCurrentFile(fileName, action = '') {
    const currentFile = document.getElementById('current-file')
    const sanitizedFileName = this.sanitizeInput(fileName)
    
    if (action) {
      currentFile.textContent = `${action} ${sanitizedFileName}`
      currentFile.className = 'current-file processing'
    } else {
      currentFile.textContent = sanitizedFileName
      currentFile.className = 'current-file'
    }
  }

  async processMultipleFiles() {
    console.info(`🚀 Starting batch processing of ${this.selectedFiles.length} files`)
    
    let completedCount = 0
    const results = []
    let allStorageCompleted = false
    
    for (let i = 0; i < this.selectedFiles.length; i++) {
      const file = this.selectedFiles[i]
      console.info(`📄 Processing file ${i + 1}/${this.selectedFiles.length}: ${file.name}`)
      
      try {
        // Show current file being processed
        this.showCurrentFile(file.name, 'Procesando')
        
        // Step 1: Storage (Convert + Upload)
        if (!allStorageCompleted) {
          this.updateStepStatus('storage', 'active', 'Convirtiendo y subiendo...')
        }
        
        const fileToUpload = await this.convertFileIfNeeded(file)
        const uploadResult = await this.uploadFileToStorage(file)
        
        // If this is the last file, mark storage as completed
        if (i === this.selectedFiles.length - 1) {
          this.updateStepStatus('storage', 'completed', 'Todos los archivos subidos')
          allStorageCompleted = true
        }
        
        // Step 2: Webhook processing
        this.updateStepStatus('webhook', 'active', 'Enviando al sistema...')
        
        const webhookData = {
          uuid: uploadResult.uuid,
          fileUrl: uploadResult.url
        }
        
        const webhookResult = await this.submitToWebhook(webhookData)
        
        completedCount++
        
        results.push({
          file: file.name,
          uuid: uploadResult.uuid,
          url: uploadResult.url,
          success: true
        })
        
        console.info(`✅ File ${i + 1} completed successfully: ${file.name}`)
        
      } catch (error) {
        console.error(`❌ Error processing file ${i + 1} (${file.name}):`, error)
        
        results.push({
          file: file.name,
          error: error.message,
          success: false
        })
      }
      
      // Update overall progress
      this.updateProgressCounter(completedCount, this.selectedFiles.length)
      
      // Small delay between files
      if (i < this.selectedFiles.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 300))
      }
    }
    
    // Mark webhook as completed
    this.updateStepStatus('webhook', 'completed', 'Procesamiento completado')
    
    // Show final summary
    const successCount = results.filter(r => r.success).length
    this.showCurrentFile(`Procesado: ${successCount}/${results.length} archivos`, '')
    
    console.info(`🎉 Batch processing completed: ${completedCount}/${this.selectedFiles.length} files processed successfully`)
    
    return results
  }

  async convertFileIfNeeded(file) {
    const isImage = ['image/jpeg', 'image/jpg', 'image/png'].includes(file.type)
    
    if (isImage) {
      console.info('🔄 Converting image to PDF...')
      return await this.convertImageToPDF(file)
    }
    
    return file
  }

  async submitToWebhook(webhookData) {
    let lastError = null
    
    for (let attempt = 0; attempt <= this.webhookConfig.retries; attempt++) {
      try {
        console.info(`Sending invoice data to production webhook (attempt ${attempt + 1}/${this.webhookConfig.retries + 1})`)
        console.info('📡 Webhook data:', webhookData)
        
        const headers = {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
        
        // Add authentication if configured
        if (this.webhookConfig.authToken) {
          headers['Authorization'] = `Bearer ${this.webhookConfig.authToken}`
        }
        
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), this.webhookConfig.timeout)
        
        const response = await fetch(this.webhookConfig.url, {
          method: 'POST',
          headers,
          body: JSON.stringify(webhookData),
          signal: controller.signal
        })
        
        clearTimeout(timeoutId)
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }
        
        let result
        try {
          const responseText = await response.text()
          result = responseText ? JSON.parse(responseText) : { status: 'success' }
        } catch (parseError) {
          // If response is not JSON, treat as success if status is OK
          result = { status: 'success' }
        }
        
        console.info('Invoice data successfully sent to production webhook:', {
          status: result.status || 'success',
          uuid: webhookData.uuid,
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
    throw new Error(`Failed to submit invoice data to webhook after ${this.webhookConfig.retries + 1} attempts: ${lastError.message}`)
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
    // Update success message with batch processing information
    const successText = this.successMessage.querySelector('p')
    
    if (result && result.processedCount) {
      let message
      if (result.hasErrors) {
        message = this.currentLang === 'es' 
          ? `${result.processedCount} de ${result.totalCount} facturas procesadas correctamente. Algunas facturas tuvieron errores.`
          : `${result.processedCount} of ${result.totalCount} invoices processed successfully. Some invoices had errors.`
      } else {
        message = this.currentLang === 'es' 
          ? `${result.processedCount} facturas han sido procesadas y enviadas correctamente.`
          : `${result.processedCount} invoices have been processed and submitted successfully.`
      }
      successText.textContent = message
    }
    
    this.successMessage.style.display = 'flex'
    this.successMessage.scrollIntoView({ behavior: 'smooth' })
  }

  resetForm() {
    this.form.reset()
    this.selectedFiles = []
    this.updateFileDisplay()
    this.updateFileInputText()
    this.hideProgressSection()
    
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

  // Convert image to PDF
  async convertImageToPDF(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = function(event) {
        try {
          const img = new Image()
          img.onload = function() {
            const pdf = new jsPDF()
            
            // Calculate dimensions to fit the page while maintaining aspect ratio
            const pageWidth = pdf.internal.pageSize.getWidth()
            const pageHeight = pdf.internal.pageSize.getHeight()
            const margin = 10
            const maxWidth = pageWidth - (margin * 2)
            const maxHeight = pageHeight - (margin * 2)
            
            let width = img.width
            let height = img.height
            
            // Scale down if image is larger than page
            if (width > maxWidth) {
              height = (height * maxWidth) / width
              width = maxWidth
            }
            
            if (height > maxHeight) {
              width = (width * maxHeight) / height
              height = maxHeight
            }
            
            // Center the image
            const x = (pageWidth - width) / 2
            const y = (pageHeight - height) / 2
            
            pdf.addImage(event.target.result, 'JPEG', x, y, width, height)
            
            // Convert PDF to blob
            const pdfBlob = pdf.output('blob')
            resolve(pdfBlob)
          }
          
          img.onerror = function() {
            reject(new Error('Failed to load image'))
          }
          
          img.src = event.target.result
        } catch (error) {
          reject(error)
        }
      }
      
      reader.onerror = function() {
        reject(new Error('Failed to read file'))
      }
      
      reader.readAsDataURL(file)
    })
  }

  // Upload file to storage endpoint
  async uploadFileToStorage(file) {
    const uuid = this.generateUUID()
    
    // Check if file is an image that should be converted to PDF
    const isImage = ['image/jpeg', 'image/jpg', 'image/png'].includes(file.type)
    let fileToUpload = file
    let fileName = `${uuid}.pdf`  // Always save as PDF now
    
    try {
      if (isImage) {
        console.info('🔄 Converting image to PDF...')
        fileToUpload = await this.convertImageToPDF(file)
        console.info('✅ Image converted to PDF successfully')
      } else {
        // If it's already a PDF, keep original extension
        const extension = this.getFileExtension(file.name)
        fileName = `${uuid}${extension}`
      }
      
      const uploadUrl = `https://db.hunt-tickets.com/storage/v1/object/invoice/main/${fileName}`
      
      console.info('🔄 Starting upload to Supabase Storage')
      console.info('📁 File details:', { 
        fileName, 
        size: fileToUpload.size, 
        type: fileToUpload.type || 'application/pdf', 
        originalName: file.name,
        converted: isImage ? 'Image converted to PDF' : 'Original file'
      })
      console.info('🌐 Upload URL:', uploadUrl)
      console.info('🔑 Headers:', {
        'Authorization': 'Bearer sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
        'apikey': 'sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
        'Content-Type': fileToUpload.type || 'application/pdf'
      })
      
      const response = await fetch(uploadUrl, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
          'apikey': 'sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
          'Content-Type': fileToUpload.type || 'application/pdf'
        },
        body: fileToUpload
      })
      
      console.info('📡 Response status:', response.status)
      console.info('📡 Response headers:', Object.fromEntries(response.headers.entries()))
      
      // Get response text to see the actual error message
      const responseText = await response.text()
      console.info('📡 Response body:', responseText)
      
      if (!response.ok) {
        let errorMessage
        try {
          const errorData = JSON.parse(responseText)
          errorMessage = errorData.message || errorData.error || responseText
        } catch {
          errorMessage = responseText
        }
        throw new Error(`Storage upload failed: HTTP ${response.status}: ${errorMessage}`)
      }
      
      // Generate signed URL for the uploaded file
      const signedUrl = await this.generateSignedUrl(fileName)
      
      const result = {
        success: true,
        fileName,
        url: signedUrl || `https://db.hunt-tickets.com/storage/v1/object/public/invoice/main/${fileName}`,
        uuid,
        extension: isImage ? 'pdf' : this.getFileExtension(file.name).substring(1),
        originalName: file.name,
        size: fileToUpload.size,
        type: fileToUpload.type || 'application/pdf',
        converted: isImage
      }
      
      console.info('✅ File successfully uploaded to storage:', result)
      return result
      
    } catch (error) {
      console.error('❌ Error uploading file to storage:', error)
      throw new Error(`Failed to upload file: ${error.message}`)
    }
  }

  // Generate signed URL for file access
  async generateSignedUrl(fileName, expiresIn = 3600) {
    try {
      console.info('🔐 Generating signed URL for:', fileName)
      
      // Supabase Storage REST API endpoint for signed URLs
      const signedUrlEndpoint = `https://db.hunt-tickets.com/storage/v1/object/sign/invoice/main/${fileName}`
      
      const response = await fetch(signedUrlEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
          'apikey': 'sb_secret_XMfnljgPzNU8hx8eyCFquQ_qKivQI3j',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          expiresIn: expiresIn
        })
      })
      
      console.info('📡 Signed URL response status:', response.status)
      
      if (!response.ok) {
        const errorText = await response.text()
        console.warn('⚠️ Failed to generate signed URL:', errorText)
        return null
      }
      
      const data = await response.json()
      console.info('📡 Signed URL response data:', data)
      
      const signedUrl = data.signedURL || data.signedUrl || data.url
      
      if (signedUrl) {
        console.info('✅ Signed URL generated successfully')
        return signedUrl
      } else {
        console.warn('⚠️ No signed URL in response, falling back to public URL')
        return null
      }
      
    } catch (error) {
      console.error('❌ Error generating signed URL:', error)
      return null
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