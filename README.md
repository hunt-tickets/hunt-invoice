# Hunt Invoice

Formulario elegante y simplificado para el envío de facturas, basado en la estética profesional de Hunt Tickets.

## Características

- **Diseño moderno**: Interfaz limpia con tema dual (oscuro/claro)
- **Bilingüe**: Soporte completo para español e inglés
- **Upload seguro**: Validación robusta de archivos (JPG, PNG, PDF - máx 5MB)
- **Responsivo**: Optimizado para desktop y móvil
- **Seguridad**: Sanitización de inputs, rate limiting, validaciones avanzadas

## Tecnologías

- Vite (build tool)
- Vanilla JavaScript (ES6+)
- CSS3 con variables personalizadas
- Google Fonts (Source Sans 3)

## Desarrollo

```bash
# Instalar dependencias
npm install

# Servidor de desarrollo
npm run dev

# Build para producción
npm run build

# Preview del build
npm run preview
```

## Estructura

```
src/
├── main.js          # Lógica principal del formulario
├── style.css        # Estilos globales
├── translations.js  # Sistema de traducciones
├── confirmation.js  # Página de éxito
├── error.js         # Página de error
└── wavy-background.js # Efectos visuales

public/
└── vite.svg         # Assets estáticos

*.html               # Páginas (index, accept, error)
```

## Funcionalidades

### Formulario Principal
- Nombre completo (requerido)
- Email (requerido)  
- Descripción (opcional)
- Upload de factura (requerido - JPG/PNG/PDF)
- Aceptación de términos (requerido)

### Validaciones
- Sanitización XSS
- Rate limiting (5 intentos por minuto)
- Validación de tipos de archivo
- Límite de tamaño (5MB)
- Patrones regex para campos de texto

### UX/UI
- Drag & drop para archivos
- Estados de loading
- Mensajes de error contextuales
- Animaciones suaves
- Feedback visual inmediato

## Páginas

- **index.html**: Formulario principal
- **accept.html**: Confirmación de envío exitoso
- **error.html**: Página de error

## Deploy

El proyecto está configurado para deploy en servicios como Railway, Vercel o Netlify con las siguientes rutas:

- `/` - Formulario principal
- `/accept.html` - Página de éxito  
- `/error.html` - Página de error

## Licencia

Desarrollado para Hunt Tickets.