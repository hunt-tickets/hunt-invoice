# Configuración del Webhook n8n para Procesamiento de Facturas con AI

## Configuración Inicial

### 1. Variables de Entorno
Crea un archivo `.env` basado en `.env.example`:

```bash
cp .env.example .env
```

Edita `.env` con tus valores:
```
VITE_N8N_WEBHOOK_URL=https://your-n8n-instance.com/webhook/invoice-processing
VITE_N8N_AUTH_TOKEN=your-secure-auth-token
```

### 2. Configuración del Webhook en n8n

#### Paso 1: Crear Workflow
1. Ve a n8n y crea un nuevo workflow
2. Agrega un nodo **Webhook** como trigger
3. Configura el webhook:
   - **HTTP Method**: POST
   - **Path**: `/invoice-processing`
   - **Binary Data**: ✅ Habilitado (para recibir archivos)
   - **Response**: JSON

#### Paso 2: Configurar Autenticación (Opcional pero recomendado)
Si usas `VITE_N8N_AUTH_TOKEN`, agrega validación:
1. Agrega un nodo **IF** después del webhook
2. Condición: `{{ $node["Webhook"].json["headers"]["authorization"] === "Bearer YOUR_TOKEN" }}`
3. Si falla, retorna error 401

#### Paso 3: Procesamiento de Datos
El webhook recibe los siguientes datos:

**Archivos (Binary Data):**
- `invoice`: El archivo de factura (PDF/JPG/PNG)

**Form Data:**
- `acceptTerms`: boolean
- `metadata`: JSON con información de sesión

**Estructura del metadata:**
```json
{
  "timestamp": "2025-01-XX:XX:XX.XXXZ",
  "language": "es|en",
  "userAgent": "...",
  "source": "hunt-invoice-form",
  "formVersion": "1.0.0",
  "sessionId": "sess_...",
  "clientFingerprint": "..."
}
```

## Ejemplo de Workflow n8n

### Nodos Recomendados:

1. **Webhook** (Trigger)
2. **IF** (Validación de auth - opcional)
3. **Move Binary Data** (Separar archivo)
4. **OpenAI/Claude/AI Provider** (Procesamiento)
5. **Database** (Guardar resultados)
6. **Email** (Confirmación)
7. **Webhook Response** (Respuesta al cliente)

### Configuración del Nodo AI (OpenAI ejemplo):

```json
{
  "model": "gpt-4-vision-preview",
  "messages": [
    {
      "role": "system",
      "content": "Eres un asistente que extrae datos de facturas. Devuelve un JSON con: empresa, fecha, total, items[]"
    },
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "Extrae los datos de esta factura:"
        },
        {
          "type": "image_url",
          "image_url": {
            "url": "data:{{ $node[\"Move Binary Data\"].binary.data.mimeType }};base64,{{ $node[\"Move Binary Data\"].binary.data.data }}"
          }
        }
      ]
    }
  ]
}
```

### Respuesta del Webhook:
Siempre retorna un JSON:

**Éxito:**
```json
{
  "status": "success",
  "processingId": "proc_123456789",
  "message": "Invoice received and processing started"
}
```

**Error:**
```json
{
  "status": "error",
  "code": "INVALID_FILE",
  "message": "File format not supported"
}
```

## Flujo Completo de Procesamiento

1. **Recepción**: Webhook recibe FormData con archivo
2. **Validación**: Verifica autenticación y formato
3. **Extracción**: AI procesa la imagen/PDF
4. **Estructuración**: Convierte a JSON estructurado
5. **Almacenamiento**: Guarda en base de datos
6. **Notificación**: Envía email de confirmación
7. **Respuesta**: Confirma recepción al cliente

## Estructura de Datos Extraídos (Sugerida)

```json
{
  "invoice": {
    "number": "FAC-2025-001",
    "date": "2025-01-15",
    "dueDate": "2025-02-15",
    "company": {
      "name": "Empresa ABC",
      "tax_id": "12345678-9",
      "address": "Dirección completa"
    },
    "client": {
      "name": "Cliente XYZ",
      "tax_id": "98765432-1"
    },
    "items": [
      {
        "description": "Producto/Servicio",
        "quantity": 1,
        "unitPrice": 100.00,
        "total": 100.00
      }
    ],
    "totals": {
      "subtotal": 100.00,
      "tax": 19.00,
      "total": 119.00
    }
  },
  "metadata": {
    "processingId": "proc_123456789",
    "confidence": 0.95,
    "processingTime": 2.3,
    "model": "gpt-4-vision"
  }
}
```

## Configuración de Desarrollo

Para desarrollo local, usa:
```
VITE_N8N_WEBHOOK_URL=http://localhost:5678/webhook/invoice-processing
```

Y configura n8n local o usa ngrok para exponer el puerto:
```bash
ngrok http 5678
```

## Seguridad

El formulario incluye:
- ✅ Rate limiting (5 intentos por minuto)
- ✅ Validación de tipos de archivo
- ✅ Verificación de contenido (magic numbers)
- ✅ Sanitización de inputs
- ✅ Session ID y fingerprinting
- ✅ Autenticación con token Bearer
- ✅ Timeouts y reintentos

## Troubleshooting

### Error: Network/Connection
- Verifica que la URL del webhook sea correcta
- Confirma que n8n esté ejecutándose
- Revisa configuración CORS si aplica

### Error: 401 Authentication
- Verifica que `VITE_N8N_AUTH_TOKEN` coincida
- Confirma configuración de autenticación en n8n

### Error: 413 File Too Large
- Reduce el tamaño del archivo (máx. 5MB)
- Ajusta límites en n8n si es necesario

### Error: Timeout
- Aumenta `timeout` en `config.js`
- Optimiza el workflow de n8n para mayor velocidad