# Proyecto OWASP Top 10: Desarrollo Seguro

Este proyecto es un sitio web educativo enfocado en la sensibilización y formación sobre seguridad en el desarrollo de software. Presenta información detallada sobre las principales vulnerabilidades según OWASP (Open Web Application Security Project) para diferentes dominios como APIs, Aplicaciones Web, Dispositivos Móviles y la Nube. Además, incluye una sección dedicada a la Criptografía Aplicada y una recopilación de Herramientas y Recursos útiles para desarrolladores.

## ✨ Características Principales

*   **Contenido Educativo Detallado:** Explicaciones claras y ejemplos prácticos de las vulnerabilidades más comunes.
*   **Múltiples Secciones Temáticas:**
    *   **API Security:** Top 10 riesgos para APIs (Basado en OWASP API Security Top 10).
    *   **Web Security:** Top 10 riesgos para Aplicaciones Web (Basado en OWASP Top 10).
    *   **Mobile Security:** Principales vulnerabilidades en aplicaciones móviles.
    *   **Cloud Security:** Riesgos comunes en arquitecturas en la nube.
    *   **Criptografía Aplicada:** Conceptos fundamentales y ejemplos de algoritmos criptográficos.
    *   **Recursos:** Herramientas y enlaces útiles para el desarrollo seguro.
*   **Ejemplos de Código:** Muestra de código vulnerable y seguro para ilustrar cada vulnerabilidad.
*   **Interfaz Moderna y Responsiva:** Desarrollada con Next.js y Tailwind CSS para una experiencia de usuario óptima en cualquier dispositivo.
*   **Navegación Intuitiva:** Fácil acceso a todas las secciones del sitio.

## 🛠️ Tecnologías Utilizadas

*   **Framework Frontend:** [Next.js](https://nextjs.org/) (v15.2.4) - Framework de React para producción.
*   **Librería UI:** [React](https://reactjs.org/) (v19) - Biblioteca de JavaScript para construir interfaces de usuario.
*   **Lenguaje:** [TypeScript](https://www.typescriptlang.org/) (v5) - Superset de JavaScript que añade tipado estático.
*   **Estilos:** [Tailwind CSS](https://tailwindcss.com/) (v3.4.17) - Framework de CSS "utility-first".
*   **Animaciones:** [Framer Motion](https://www.framer.com/motion/) - Librería de animación para React.
*   **Iconos:** [Lucide React](https://lucide.dev/) - Colección de iconos SVG.
*   **Resaltado de Sintaxis:** [PrismJS](https://prismjs.com/) - Para mostrar bloques de código.

## 📂 Estructura de Carpetas

El proyecto sigue una estructura organizada para facilitar el desarrollo y mantenimiento:

```
owasp-api-top10/
├── app/                      # Directorio principal de la aplicación Next.js (App Router)
│   ├── globals.css           # Estilos globales
│   ├── layout.tsx            # Layout principal de la aplicación
│   ├── not-found.tsx         # Página para rutas no encontradas (404)
│   ├── page.tsx              # Página de inicio (Home)
│   ├── api/                  # Sección de Seguridad en APIs
│   │   └── page.tsx
│   ├── cloud/                # Sección de Seguridad en la Nube
│   │   └── page.tsx
│   ├── criptografia/         # Sección de Criptografía
│   │   └── page.tsx
│   ├── movil/                # Sección de Seguridad Móvil
│   │   └── page.tsx
│   ├── recursos/             # Sección de Herramientas y Recursos
│   │   └── page.tsx
│   └── web/                  # Sección de Seguridad Web
│       └── page.tsx
├── components/               # Componentes reutilizables de React
│   ├── api/                  # Componentes específicos para la sección API
│   │   ├── api-header.tsx
│   │   ├── api-introduction.tsx
│   │   ├── api-resources.tsx
│   │   └── api-statistics.tsx
│   ├── basic/                # Componentes básicos y genéricos
│   │   ├── accordion.tsx
│   │   ├── card.tsx
│   │   ├── code-block.tsx
│   │   ├── footer.tsx
│   │   ├── header-nav.tsx
│   │   └── scroll-to-top.tsx
│   │   └── background-effect.tsx
│   ├── cloud/                # Componentes específicos para la sección Cloud
│   │   └── ...
│   ├── criptografia/         # Componentes específicos para la sección Criptografía
│   │   └── ...
│   ├── movil/                # Componentes específicos para la sección Móvil
│   │   └── ...
│   ├── recursos/             # Componentes específicos para la sección Recursos
│   │   └── ...
│   └── web/                  # Componentes específicos para la sección Web
│       └── ...
├── data/                     # Datos estáticos para las diferentes secciones
│   ├── api.ts
│   ├── cloud.ts
│   ├── criptografia.ts
│   ├── movil.ts
│   └── web.ts
├── public/                   # Archivos estáticos (imágenes, fuentes, etc.) - No presente en la estructura actual, pero es estándar en Next.js
├── LICENSE                   # Archivo de licencia del proyecto
├── next-env.d.ts             # Definiciones de tipos para Next.js
├── next.config.mjs           # Configuración de Next.js
├── package.json              # Metadatos del proyecto y dependencias
├── pnpm-lock.yaml            # Lockfile de PNPM (gestor de paquetes)
├── postcss.config.mjs        # Configuración de PostCSS
├── README.md                 # Este archivo
├── tailwind.config.ts        # Configuración de Tailwind CSS
└── tsconfig.json             # Configuración de TypeScript
```

## 🚀 Cómo Empezar

Sigue estos pasos para configurar y ejecutar el proyecto en tu entorno local.

### Pre-requisitos

Asegúrate de tener instalado lo siguiente:

*   [Node.js](https://nodejs.org/) (v18 o superior recomendado)
*   [pnpm](https://pnpm.io/installation) (o puedes usar `npm` o `yarn` ajustando los comandos)

### Instalación

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/MatiasWettstein/owaspweb.git
    cd owaspweb
    ```

2.  **Instala las dependencias:**
    Si usas `pnpm`:
    ```bash
    pnpm install
    ```
    Si usas `npm`:
    ```bash
    npm install
    ```
    Si usas `yarn`:
    ```bash
    yarn install
    ```

### Ejecutar en Modo Desarrollo

Para iniciar el servidor de desarrollo local:

```bash
pnpm dev
```
O con `npm`/`yarn`:
```bash
npm run dev
# o
yarn dev
```
Abre [http://localhost:3000](http://localhost:3000) en tu navegador para ver el sitio. La aplicación se recargará automáticamente si editas algún archivo fuente.

### Construir para Producción

Para generar una versión optimizada para producción:

```bash
pnpm build
```
O con `npm`/`yarn`:
```bash
npm run build
# o
yarn build
```
Esto generará una carpeta `out` (debido a `output: 'export'` en `next.config.mjs`) con los archivos estáticos listos para el despliegue.

### Iniciar el Servidor de Producción (si no es exportación estática)

Si no estuvieras usando `output: 'export'`, podrías iniciar un servidor de producción con:
```bash
pnpm start
```
O con `npm`/`yarn`:
```bash
npm run start
# o
yarn start
```

## 🌐 Despliegue

Este proyecto está configurado para generar un sitio estático (`output: 'export'` en `next.config.mjs`), lo que lo hace ideal para desplegar en plataformas como:

*   **Cloudflare Pages:** El script `deploy` en `package.json` (`npx wrangler pages deploy ./out`) sugiere que está preparado para Cloudflare Pages.
*   **Vercel:** Plataforma nativa para Next.js.
*   **Netlify:** Otra excelente opción para sitios estáticos.
*   **GitHub Pages:** También compatible con sitios estáticos.

Para desplegar en **Cloudflare Pages**:

1.  Asegúrate de tener [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/get-started/) instalado y configurado.
2.  Ejecuta el comando de despliegue:
    ```bash
    pnpm deploy
    ```
    O con `npm`/`yarn`:
    ```bash
    npm run deploy
    # o
    yarn deploy
    ```

Esto construirá el proyecto y desplegará el contenido de la carpeta `./out` a Cloudflare Pages.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Si deseas mejorar el proyecto, por favor sigue estos pasos:

1.  Haz un Fork del proyecto.
2.  Crea una nueva rama para tu feature (`git checkout -b feature/AmazingFeature`).
3.  Realiza tus cambios y haz commit (`git commit -m 'Add some AmazingFeature'`).
4.  Empuja tus cambios a la rama (`git push origin feature/AmazingFeature`).
5.  Abre un Pull Request.

## 📄 Licencia

Este proyecto se distribuye bajo la Licencia CC0 1.0 Universal. Consulta el archivo `LICENSE` para más detalles.

---

¡Gracias por visitar y utilizar este recurso para aprender sobre desarrollo seguro!
