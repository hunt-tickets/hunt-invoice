import './style.css'
import { translations } from './translations.js'

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

  handleFileSelect(e) {
    const file = e.target.files[0]
    
    if (file && this.validateFile(file)) {
      this.selectedFile = file
      this.updateFileDisplay()
      this.updateFileInputText()
    }
  }

  validateFile(file) {
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
      const formData = new FormData()
      
      // Security: Sanitize all form data before submission
      const formFields = new FormData(this.form)
      for (let [key, value] of formFields.entries()) {
        if (typeof value === 'string') {
          formData.append(key, this.sanitizeInput(value))
        } else {
          formData.append(key, value)
        }
      }
      
      // Add the selected file
      if (this.selectedFile) {
        formData.append('invoice', this.selectedFile)
      }
      
      // Log submission attempt
      console.info('Invoice submission attempt', {
        timestamp: new Date().toISOString(),
        fields: Array.from(formData.keys()),
        hasFile: !!this.selectedFile
      })
      
      // Simulate form submission
      await this.simulateSubmission(formData)
      
      this.showSuccess()
      this.resetForm()
      
    } catch (error) {
      console.error('Error submitting form:', error)
      this.showError('form', this.t('form-error'))
    } finally {
      this.setLoading(false)
    }
  }

  async simulateSubmission(formData) {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log('Invoice submission data:')
        for (let [key, value] of formData.entries()) {
          if (value instanceof File) {
            console.log(`${key}:`, `File: ${value.name} (${value.size} bytes)`)
          } else {
            console.log(`${key}:`, value)
          }
        }
        resolve()
      }, 2000)
    })
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

  showSuccess() {
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