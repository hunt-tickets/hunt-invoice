// Webhook configuration for n8n integration
export const webhookConfig = {
  // Production webhook URL
  url: import.meta.env.VITE_N8N_WEBHOOK_URL || 'https://automations.hunt-tickets.com/webhook-test/add-invoice',
  
  // Request timeout in milliseconds
  timeout: 30000,
  
  // Number of retry attempts
  retries: 2,
  
  // Authentication token (optional)
  authToken: import.meta.env.VITE_N8N_AUTH_TOKEN || null,
  
  // Development mode settings
  development: {
    url: 'http://localhost:5678/webhook/invoice-processing',
    timeout: 10000,
    retries: 1,
    authToken: null
  }
}

// Get appropriate config based on environment
export function getWebhookConfig() {
  const isDev = import.meta.env.DEV || import.meta.env.MODE === 'development'
  
  if (isDev && webhookConfig.development.url !== 'http://localhost:5678/webhook/invoice-processing') {
    return webhookConfig.development
  }
  
  return {
    url: webhookConfig.url,
    timeout: webhookConfig.timeout,
    retries: webhookConfig.retries,
    authToken: webhookConfig.authToken
  }
}

// Validate webhook configuration
export function validateWebhookConfig(config) {
  if (!config.url || !config.url.startsWith('http')) {
    throw new Error('Invalid webhook URL configuration')
  }
  
  if (config.timeout < 5000 || config.timeout > 60000) {
    console.warn('Webhook timeout should be between 5-60 seconds')
  }
  
  if (config.retries < 0 || config.retries > 5) {
    console.warn('Webhook retries should be between 0-5')
  }
  
  return true
}