import './style.css'

document.addEventListener('DOMContentLoaded', () => {
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

  // Language toggle functionality
  const langButtons = document.querySelectorAll('.lang-btn')
  let currentLang = 'es'
  
  langButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const selectedLang = e.target.dataset.lang
      if (selectedLang !== currentLang) {
        switchLanguage(selectedLang)
        currentLang = selectedLang
      }
    })
  })

  function switchLanguage(lang) {
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
  }
})