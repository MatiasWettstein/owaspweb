const apiData = {
    risk1: {
        title: "Broken Object Level Authorization (BOLA)",
        attackVector: "Modificación de identificadores en la URL o cuerpo para acceder a objetos ajenos.",
        weakness: "Falta de verificación de permisos a nivel de objeto.",
        impact: "Acceso no autorizado a datos de otros usuarios.",
        mitigationStrategies: [
            "Validar siempre que el usuario autenticado tenga acceso al recurso.",
            "Implementar lógica de autorización robusta basada en el usuario.",
            "Evitar confiar en los identificadores enviados por el cliente."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "// API permite acceder a cualquier recurso por ID sin verificación\napp.get('/api/users/:id', async (req, res) => {\n  const user = await db.findUserById(req.params.id);\n  res.json(user);\n});",
            secure: "app.get('/api/users/:id', async (req, res) => {\n  const requestedId = req.params.id;\n  const authenticatedId = req.user.id; // obtenido del token/session\n\n  if (requestedId !== authenticatedId) {\n    return res.status(403).json({ message: 'Unauthorized access' });\n  }\n\n  const user = await db.findUserById(requestedId);\n  res.json(user);\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "app.put('/api/orders/:orderId', async (req, res) => {\n  const order = await db.findOrderById(req.params.orderId);\n  order.status = req.body.status;\n  await db.save(order);\n  res.send(\"Order updated\");\n});",
            secure: "app.put('/api/orders/:orderId', async (req, res) => {\n  const order = await db.findOrderById(req.params.orderId);\n\n  if (order.userId !== req.user.id) {\n    return res.status(403).send(\"Unauthorized to modify this order\");\n  }\n\n  order.status = req.body.status;\n  await db.save(order);\n  res.send(\"Order updated\");\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// Devuelve detalles de todos los reportes relacionados a un proyecto\napp.get('/api/projects/:projectId/reports', async (req, res) => {\n  const reports = await db.getReportsByProject(req.params.projectId);\n  res.json(reports);\n});",
            secure: "app.get('/api/projects/:projectId/reports', async (req, res) => {\n  const project = await db.getProjectById(req.params.projectId);\n\n  if (!project || project.ownerId !== req.user.id) {\n    return res.status(403).send(\"Access denied\");\n  }\n\n  const reports = await db.getReportsByProject(project.id);\n  res.json(reports);\n});"
        }
    },
    risk2: {
        title: "Broken Authentication",
        attackVector: "Reutilización de credenciales, tokens mal gestionados, sesiones inseguras.",
        weakness: "Implementación débil del sistema de autenticación.",
        impact: "Suplantación de identidad y acceso completo a la cuenta de un usuario.",
        mitigationStrategies: [
            "Utilizar bibliotecas seguras como Passport.js.",
            "Aplicar expiración de tokens y rotación periódica.",
            "Usar autenticación multifactor (2FA)."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "app.post('/login', async (req, res) => {\n  const { username } = req.body;\n  const user = await db.findUserByUsername(username);\n\n  if (!user) return res.status(401).send(\"Invalid user\");\n  \n  // ❌ No hay validación de contraseña\n  req.session.userId = user.id;\n  res.send(\"Logged in\");\n});",
            secure: "const bcrypt = require('bcrypt');\n\napp.post('/login', async (req, res) => {\n  const { username, password } = req.body;\n  const user = await db.findUserByUsername(username);\n\n  if (!user || !await bcrypt.compare(password, user.passwordHash)) {\n    return res.status(401).send(\"Invalid credentials\");\n  }\n\n  req.session.userId = user.id;\n  res.send(\"Logged in\");\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "// Login\napp.post('/login', async (req, res) => {\n  const user = await db.findUserByUsername(req.body.username);\n  req.session.userId = user.id;\n  res.send(\"Logged in\");\n});\n\n// Logout\napp.post('/logout', (req, res) => {\n  // ❌ No se destruye la sesión\n  res.send(\"Logged out\");\n});",
            secure: "// Login con sesión segura y duración limitada\napp.post('/login', async (req, res) => {\n  const user = await db.findUserByUsername(req.body.username);\n  if (!user) return res.status(401).send(\"Unauthorized\");\n\n  req.session.regenerate((err) => {\n    if (err) return res.status(500).send(\"Error\");\n    req.session.userId = user.id;\n    req.session.cookie.maxAge = 15 * 60 * 1000; // 15 minutos\n    res.send(\"Logged in\");\n  });\n});\n\n// Logout\napp.post('/logout', (req, res) => {\n  req.session.destroy(err => {\n    if (err) return res.status(500).send(\"Logout failed\");\n    res.clearCookie('connect.sid');\n    res.send(\"Logged out\");\n  });\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "const jwt = require('jsonwebtoken');\n\napp.get('/profile', (req, res) => {\n  const token = req.headers.authorization?.split(' ')[1];\n  const payload = jwt.decode(token); // ❌ decode sin verificación\n  res.send(`Welcome ${payload.username}`);\n});",
            secure: "const jwt = require('jsonwebtoken');\n\napp.get('/profile', (req, res) => {\n  const token = req.headers.authorization?.split(' ')[1];\n  try {\n    const payload = jwt.verify(token, process.env.JWT_SECRET);\n    res.send(`Welcome ${payload.username}`);\n  } catch (err) {\n    res.status(401).send(\"Invalid or expired token\");\n  }\n});"
        }
    },
    risk3: {
        title: "Broken Object Property Level Authorization",
        attackVector: "Manipulación del payload para modificar propiedades no autorizadas.",
        weakness: "No se controla qué campos pueden ser escritos por el cliente.",
        impact: "Escalada de privilegios o alteración de información crítica.",
        mitigationStrategies: [
            "Validar y filtrar los campos permitidos (whitelisting).",
            "Descartar cualquier propiedad no esperada en el servidor."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "app.put('/api/users/:id', async (req, res) => {\n  const updatedUser = await db.updateUser(req.params.id, req.body);\n  res.json(updatedUser);\n});\n\n//El usuario puede enviar un cuerpo como: { \"email\": \"nuevo@mail.com\", \"role\": \"admin\" }",
            secure: "app.put('/api/users/:id', async (req, res) => {\n  const updates = { email: req.body.email }; // solo campos permitidos\n\n  if (req.body.role) {\n    // No permitir cambios de rol por usuarios normales\n    return res.status(403).send(\"Cannot change role\");\n  }\n\n  const updatedUser = await db.updateUser(req.params.id, updates);\n  res.json(updatedUser);\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "app.put('/api/orders/:id', async (req, res) => {\n  const order = await db.findOrderById(req.params.id);\n  Object.assign(order, req.body);\n  await db.save(order);\n  res.json(order);\n});\n\n//Un cliente podría cambiar el estado de su pedido a \"shipped\" o \"paid\".",
            secure: "app.put('/api/orders/:id', async (req, res) => {\n  const order = await db.findOrderById(req.params.id);\n\n  // Solo permitir cambiar dirección si es el propietario\n  if (order.userId !== req.user.id) {\n    return res.status(403).send(\"Unauthorized\");\n  }\n\n  const allowedUpdates = {\n    shippingAddress: req.body.shippingAddress\n  };\n\n  Object.assign(order, allowedUpdates);\n  await db.save(order);\n  res.json(order);\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// Actualiza configuración del usuario (incluye propiedades anidadas)\napp.patch('/api/users/:id/settings', async (req, res) => {\n  const user = await db.findUserById(req.params.id);\n  Object.assign(user.settings, req.body);\n  await db.save(user);\n  res.send(\"Settings updated\");\n});\n\n//El usuario podría enviar: { \"2FAEnabled\": false, \"adminPanelAccess\": true }",
            secure: "app.patch('/api/users/:id/settings', async (req, res) => {\n  const user = await db.findUserById(req.params.id);\n\n  if (user.id !== req.user.id) {\n    return res.status(403).send(\"Forbidden\");\n  }\n\n  // Definir propiedades seguras a modificar\n  const allowed = [\"theme\", \"language\", \"notifications\"];\n  for (const key of Object.keys(req.body)) {\n    if (!allowed.includes(key)) {\n      return res.status(400).send(`Property '${key}' not allowed`);\n    }\n    user.settings[key] = req.body[key];\n  }\n\n  await db.save(user);\n  res.send(\"Settings updated\");\n});"
        }
    },
    risk4: {
        title: "Unrestricted Resource Consumption",
        attackVector: "Peticiones masivas o envío de datos muy grandes.",
        weakness: "Falta de límites en uso de CPU, RAM, ancho de banda, etc.",
        impact: "Denegación de servicio (DoS) o agotamiento de recursos.",
        mitigationStrategies: [
            "Aplicar rate limiting y control de tamaño en payloads.",
            "Validar tamaños máximos en cargas y consultas."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "app.get('/download', (req, res) => {\n  const filePath = path.join(__dirname, 'uploads', req.query.file);\n  res.download(filePath);\n});",
            secure: "const MAX_FILE_SIZE_MB = 50;\n\napp.get('/download', (req, res) => {\n  const filePath = path.join(__dirname, 'uploads', req.query.file);\n\n  fs.stat(filePath, (err, stats) => {\n    if (err || stats.size > MAX_FILE_SIZE_MB * 1024 * 1024) {\n      return res.status(400).send('File too large or not found');\n    }\n\n    res.download(filePath);\n  });\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "app.get('/api/products', async (req, res) => {\n  const products = await db.getAllProducts(); // puede ser miles\n  res.json(products);\n});",
            secure: "app.get('/api/products', async (req, res) => {\n  const page = parseInt(req.query.page || '1');\n  const limit = Math.min(parseInt(req.query.limit || '10'), 100); // máximo 100\n\n  const products = await db.getProducts({ page, limit });\n  res.json(products);\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "app.post('/generate-pdf', async (req, res) => {\n  const { htmlContent } = req.body;\n\n  const pdfBuffer = await generatePDF(htmlContent); // sin límite\n  res.setHeader('Content-Type', 'application/pdf');\n  res.send(pdfBuffer);\n});",
            secure: "app.post('/generate-pdf', async (req, res) => {\n  const { htmlContent } = req.body;\n\n  if (!htmlContent || htmlContent.length > 50000) {\n    return res.status(400).send(\"Content too large\");\n  }\n\n  try {\n    const pdfBuffer = await generatePDF(htmlContent);\n    res.setHeader('Content-Type', 'application/pdf');\n    res.send(pdfBuffer);\n  } catch (e) {\n    res.status(500).send(\"Error generating PDF\");\n  }\n});"
        }
    },
    risk5: {
        title: "Broken Function Level Authorization",
        attackVector: "Acceso a funciones restringidas sin verificar permisos de rol.",
        weakness: "No se verifica el nivel de privilegio requerido por función.",
        impact: "Usuarios no autorizados pueden realizar acciones administrativas.",
        mitigationStrategies: [
            "Verificar explícitamente los roles/autorizaciones por función.",
            "Seguir el principio de mínimo privilegio."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "app.delete('/admin/users/:id', async (req, res) => {\n  await db.deleteUser(req.params.id);\n  res.send(\"User deleted\");\n});",
            secure: "app.delete('/admin/users/:id', async (req, res) => {\n  if (req.user.role !== 'admin') {\n    return res.status(403).send(\"Forbidden\");\n  }\n\n  await db.deleteUser(req.params.id);\n  res.send(\"User deleted\");\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "app.get('/reports/monthly', async (req, res) => {\n  const report = await db.getMonthlyFinancialReport();\n  res.json(report);\n});",
            secure: "app.get('/reports/monthly', async (req, res) => {\n  if (!req.user.permissions.includes('VIEW_FINANCIAL_REPORTS')) {\n    return res.status(403).send(\"Access denied\");\n  }\n\n  const report = await db.getMonthlyFinancialReport();\n  res.json(report);\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// Endpoint de sistema pensado para tareas internas\napp.post('/internal/reset-system', async (req, res) => {\n  await system.resetAll();\n  res.send(\"System reset\");\n});",
            secure: "app.post('/internal/reset-system', async (req, res) => {\n  if (!req.user || req.user.role !== 'sysadmin') {\n    return res.status(403).send(\"Unauthorized\");\n  }\n\n  await system.resetAll();\n  res.send(\"System reset\");\n});"
        }
    },
    risk6: {
        title: "Unrestricted Access to Sensitive Business Flows",
        attackVector: "Automatización de flujos como compra rápida, scraping o abusos lógicos.",
        weakness: "Falta de validaciones contra abuso de lógica del negocio.",
        impact: "Impacto económico, saturación del sistema o fraude.",
        mitigationStrategies: [
            "Monitorear patrones de uso anómalos.",
            "Limitar acciones repetidas por usuario/IP.",
            "Aplicar CAPTCHA u otros mecanismos de fricción."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "app.post('/generate-coupon', (req, res) => {\n  const coupon = generateCoupon();\n  db.saveCoupon(req.user.id, coupon);\n  res.json({ coupon });\n});",
            secure: "const rateLimit = require(\"express-rate-limit\");\n\nconst couponLimiter = rateLimit({\n  windowMs: 10 * 60 * 1000, // 10 minutos\n  max: 1, // 1 intento cada 10 minutos por IP\n  message: \"Too many coupon requests. Try later.\",\n});\n\napp.post('/generate-coupon', couponLimiter, (req, res) => {\n  const coupon = generateCoupon();\n  db.saveCoupon(req.user.id, coupon);\n  res.json({ coupon });\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "app.post('/register', async (req, res) => {\n  await db.createUser(req.body);\n  res.send(\"User created\");\n});",
            secure: "const captchaValidator = require('./captchaValidator');\n\napp.post('/register', async (req, res) => {\n  const validCaptcha = await captchaValidator.verify(req.body.captchaToken);\n  if (!validCaptcha) return res.status(400).send(\"Invalid CAPTCHA\");\n\n  await db.createUser(req.body);\n  res.send(\"User created\");\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "app.post('/transfer', async (req, res) => {\n  await transferFunds(req.user.id, req.body.to, req.body.amount);\n  res.send(\"Transfer completed\");\n});",
            secure: "app.post('/transfer', async (req, res) => {\n  const recentTransfers = await db.countUserTransfers(req.user.id, { withinMinutes: 10 });\n\n  if (recentTransfers >= 3) {\n    logAnomaly(req.user.id, 'Too many transfers');\n    return res.status(429).send(\"Too many transfer attempts\");\n  }\n\n  await transferFunds(req.user.id, req.body.to, req.body.amount);\n  res.send(\"Transfer completed\");\n});"
        }
    },
    risk7: {
        title: "Server-Side Request Forgery (SSRF)",
        attackVector: "Manipulación del servidor para que realice solicitudes HTTP a destinos arbitrarios.",
        weakness: "Falta de validación de URLs proporcionadas por el usuario antes de que el servidor realice solicitudes.",
        impact: "Escaneo de puertos internos, acceso a servicios internos, exfiltración de datos o ejecución de código remoto.",
        mitigationStrategies: [
            "Sanitizar y validar todas las entradas de datos del cliente.",
            "Implementar listas blancas de dominios/IPs permitidos.",
            "Bloquear tráfico a direcciones IP privadas y localhost.",
            "Implementar políticas de firewall para bloquear conexiones no esenciales.",
            "No enviar respuestas en bruto al cliente."
        ],
        exampleTitle: "Ejemplo de mitigación de SSRF",
        example1: {
            language: "javascript",
            vulnerable: "// El usuario puede hacer que el servidor haga peticiones arbitrarias\napp.post('/fetch', async (req, res) => {\n  const { url } = req.body;\n  const response = await fetch(url); // ❌ SSRF posible\n  const data = await response.text();\n  res.send(data);\n});",
            secure: "const allowedDomains = ['https://api.example.com', 'https://docs.example.com'];\n          \napp.post('/fetch', async (req, res) => {\n  const { url } = req.body;\n\n  if (!allowedDomains.some(domain => url.startsWith(domain))) {\n    return res.status(403).send(\"URL not allowed\");\n  }\n\n  const response = await fetch(url); // ✅ acceso limitado\n  const data = await response.text();\n  res.send(data);\n});"
        },
        example2: {
            language: "javascript",
            vulnerable: "// Permite acceder a URLs internas como http://localhost/admin o 169.254.x.x\napp.get('/image-proxy', async (req, res) => {\n  const { imageUrl } = req.query;\n  const response = await fetch(imageUrl);\n  const buffer = await response.arrayBuffer();\n  res.setHeader('Content-Type', 'image/jpeg');\n  res.send(Buffer.from(buffer));\n});",
            secure: "const dns = require('dns').promises;\nconst { URL } = require('url');\n\nasync function isPrivateIp(urlString) {\n  try {\n    const url = new URL(urlString);\n    const addresses = await dns.lookup(url.hostname, { all: true });\n\n    return addresses.some(addr => {\n      return /^127\\./.test(addr.address) || // localhost\n             /^10\\./.test(addr.address) ||  // red privada\n             /^192\\.168\\./.test(addr.address) ||\n             /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(addr.address);\n    });\n  } catch (e) {\n    return true; // fallback a denegar\n  }\n}\n\napp.get('/image-proxy', async (req, res) => {\n  const { imageUrl } = req.query;\n\n  if (await isPrivateIp(imageUrl)) {\n    return res.status(403).send(\"Access to internal resources denied\");\n  }\n\n  const response = await fetch(imageUrl);\n  const buffer = await response.arrayBuffer();\n  res.setHeader('Content-Type', 'image/jpeg');\n  res.send(Buffer.from(buffer));\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// Recibe una URL de webhook sin validación\napp.post('/register-webhook', async (req, res) => {\n  const { url } = req.body;\n  db.saveWebhook(url); // ❌ el servidor luego enviará datos a cualquier URL\n  res.send(\"Webhook saved\");\n});",
            secure: "const validWebhookDomain = /^https:\\/\\/hooks\\.example\\.com\\/.*/;\n          \napp.post('/register-webhook', async (req, res) => {\n  const { url } = req.body;\n\n  if (!validWebhookDomain.test(url)) {\n    return res.status(400).send(\"Invalid webhook URL\");\n  }\n\n  db.saveWebhook(url); // ✅ solo dominios específicos permitidos\n  res.send(\"Webhook saved\");\n});"
        }
    },
    risk8: {
        title: "Security Misconfiguration",
        attackVector: "Explotación de sistemas mal configurados, incompletos o con configuraciones por defecto.",
        weakness: "Configuraciones de seguridad incorrectas, servicios innecesarios habilitados, permisos incorrectos, etc.",
        impact: "Acceso no autorizado a datos o funcionalidades del sistema, hasta compromiso completo del servidor.",
        mitigationStrategies: [
            "Implementar un proceso de endurecimiento de seguridad para todos los entornos.",
            "Eliminar o no instalar características, componentes o servicios no utilizados.",
            "Revisar y actualizar configuraciones como parte del proceso de gestión de parches.",
            "Implementar una arquitectura de segmentación con separación entre componentes.",
            "Enviar directivas de seguridad a los clientes (headers de seguridad)."
        ],
        exampleTitle: "Ejemplo de configuración segura",
        example1: {
            language: "javascript",
            vulnerable: "// Express sin ningún header de seguridad\nconst express = require('express');\nconst app = express();\n\napp.get('/', (req, res) => {\n  res.send(\"Hello world\");\n});\n\napp.listen(3000);",
            secure: "// Express usando helmet para agregar headers seguros\nconst express = require('express');\nconst helmet = require('helmet');\n\nconst app = express();\napp.use(helmet()); // ✅ Activa varios headers de seguridad\n\napp.get('/', (req, res) => {\n  res.send(\"Hello world\");\n});\n\napp.listen(3000);"
        },
        example2: {
            language: "javascript",
            vulnerable: "// Express con stack traces en producción\napp.use((err, req, res, next) => {\n  // ❌ Devuelve detalles del error al cliente\n  res.status(500).send(err.stack);\n});",
            secure: "// Manejo de errores controlado\napp.use((err, req, res, next) => {\n  // ✅ No revela información sensible en producción\n  console.error(err); // log interno\n  res.status(500).send(\"Something went wrong\");\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// Rutas administrativas sin protección\napp.use('/admin', require('./adminRoutes'));\n\n// adminRoutes.js\nrouter.get('/dashboard', (req, res) => {\n  res.send(\"Admin Panel\");\n});\n\n// ⚠️ Si un atacante descubre /admin, puede acceder libremente.",
            secure: "// Middleware de autenticación para rutas de admin\nfunction isAdmin(req, res, next) {\n  if (req.user && req.user.role === 'admin') return next();\n  return res.status(403).send(\"Forbidden\");\n}\n\napp.use('/admin', isAdmin, require('./adminRoutes'));"
        }
    },
    risk9: {
        title: "Improper Inventory Management",
        attackVector: "Acceso a APIs antiguas, no documentadas o desactivadas.",
        weakness: "Falta de visibilidad del ciclo de vida de las APIs.",
        impact: "Exposición de endpoints obsoletos y vulnerables.",
        mitigationStrategies: [
            "Mantener inventario y control de versiones.",
            "Aplicar procesos de ciclo de vida (API lifecycle management)."
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: "// ⚠️ Este endpoint fue usado para pruebas internas y quedó accesible en producción\napp.get('/test-delete-all-users', async (req, res) => {\n  await db.deleteAllUsers();\n  res.send('All users deleted');\n});",
            secure: "// ✅ Eliminar endpoints no documentados y que no pertenecen al flujo oficial de la aplicación\n\n// Esta ruta se elimina completamente del código antes del despliegue\n// Alternativamente, puede protegerse con autorización y limitarse al entorno de staging"
        },
        example2: {
            language: "javascript",
            vulnerable: "// ⚠️ Ruta antigua que sigue funcionando sin autenticación ni control\napp.get('/api/v1/user-data', (req, res) => {\n  res.send(db.getUserById(req.query.id));\n});",
            secure: "// ✅ Control de versiones y desactivación explícita de APIs antiguas\napp.use('/api/v1/*', (req, res) => {\n  res.status(410).send(\"Esta versión de la API está obsoleta\");\n});\n\n// Solo permitir acceso a /api/v2 con autenticación y control adecuado\napp.get('/api/v2/user-data', authenticate, (req, res) => {\n  res.send(db.getUserById(req.user.id));\n});"
        },
        example3: {
            language: "javascript",
            vulnerable: "// ⚠️ Ruta de administración visible por convención\napp.get('/admin/feature-flags', (req, res) => {\n  res.json(db.getFeatureFlags());\n});",
            secure: "const express = require('express');\nconst helmet = require('helmet');\nconst rateLimit = require('express-rate-limit');\nconst app = express();\n\napp.use(helmet()); // 🛡️ Protege cabeceras comunes\n\n// ✅ Middleware de autenticación de administradores\nfunction authenticateAdmin(req, res, next) {\n  const user = req.user; // Suponiendo que viene desde JWT o sesión\n\n  if (!user || !user.roles.includes('admin')) {\n    return res.status(403).send('Acceso denegado');\n  }\n\n  next();\n}\n\n// ✅ Usar rutas menos triviales y fuera de patrones comunes\napp.get('/internal/v2/settings/flags', authenticateAdmin, async (req, res) => {\n  try {\n    const flags = await db.getFeatureFlags();\n\n    res.json({\n      flags,\n      accessedAt: new Date().toISOString()\n    });\n  } catch (error) {\n    res.status(500).send('Error al recuperar los flags');\n  }\n});"
        }
    },
    risk10: {
        title: "Unsafe Consumption of APIs",
        attackVector: "Consumo de APIs externas sin validar sus datos.",
        weakness: "Confianza ciega en terceros sin validación de entrada.",
        impact: "Inyección de datos maliciosos o ejecución de código no seguro.",
        mitigationStrategies: [
            "Validar siempre la respuesta de servicios externos.",
            "Aplicar filtrado y sanitización antes de usar datos de terceros.",
        ],
        exampleTitle: "Ejemplo en Express",
        example1: {
            language: "javascript",
            vulnerable: `const axios = require('axios');\n\napp.get('/api/currency-exchange', async (req, res) => {\n  const { from, to } = req.query;\n\n  // ⚠️ No validamos la respuesta del servicio externo, lo que puede llevar a datos no deseados o incorrectos\n  const result = await axios.get(\`https://external-api.com/exchange?from=\${from}&to=\${to}\`);\n\n  res.send(result.data);  // Se asume que la respuesta es siempre correcta\n});`,
            secure: `const axios = require('axios');\n\n// Función para validar la respuesta de la API externa\nfunction isValidExchangeRateResponse(data) {\n  return data && typeof data.rate === 'number';  // Validación simple de que existe la propiedad 'rate' y es un número\n}\n\napp.get('/api/currency-exchange', async (req, res) => {\n  const { from, to } = req.query;\n\n  try {\n    const result = await axios.get(\`https://external-api.com/exchange?from=\${from}&to=\${to}\`);\n\n    // ✅ Validar la respuesta antes de usarla\n    if (!isValidExchangeRateResponse(result.data)) {\n      return res.status(500).send('Error en la respuesta de la API externa');\n    }\n\n    res.send(result.data);\n  } catch (error) {\n    res.status(500).send('Error al obtener datos de cambio de divisas');\n  }\n});`
        },
        example2: {
            language: "javascript",
            vulnerable: `app.get('/api/data', async (req, res) => {\n  const { userId } = req.query;\n\n  // ⚠️ Llamada a API externa sin ningún tipo de autenticación o verificación\n  const response = await axios.get(\`https://external-api.com/data/\${userId}\`);\n\n  res.send(response.data);\n});`,
            secure: `app.get('/api/data', authenticateUser, async (req, res) => {\n  const { userId } = req.query;\n\n  // ✅ Verificar que el usuario autenticado tenga acceso a los datos solicitados\n  if (req.user.id !== userId) {\n    return res.status(403).send('Acceso no autorizado');\n  }\n\n  try {\n    const response = await axios.get(\`https://external-api.com/data/\${userId}\`, {\n      headers: { Authorization: \`Bearer \${req.user.token}\` } // Usar autenticación de API\n    });\n    res.send(response.data);\n  } catch (error) {\n    res.status(500).send('Error al recuperar los datos');\n  }\n});`
        },
        example3: {
            language: "javascript",
            vulnerable: `const axios = require('axios');\n\napp.get('/api/product-info', async (req, res) => {\n  const { productId } = req.query;\n\n  // ⚠️ Llamada a API externa sin validación ni filtrado de la respuesta\n  const response = await axios.get(\`https://external-api.com/product/\${productId}\`);\n\n  // La respuesta es directamente pasada sin ningún control\n  res.send(response.data);\n});`,
            secure: `const axios = require('axios');\nconst { body, validationResult } = require('express-validator');  // Usando express-validator para la validación\n\n// Función para validar la respuesta de un producto\nfunction isValidProductResponse(data) {\n  return data && data.id && data.name && typeof data.price === 'number';  // Asegurarse de que la respuesta tiene todos los campos necesarios\n}\n\napp.get('/api/product-info', [\n  body('productId').isInt().withMessage('El productId debe ser un número entero'),  // Validar productId\n], async (req, res) => {\n  // Validar la entrada del usuario\n  const errors = validationResult(req);\n  if (!errors.isEmpty()) {\n    return res.status(400).json({ errors: errors.array() });\n  }\n\n  const { productId } = req.query;\n\n  try {\n    const response = await axios.get(\`https://external-api.com/product/\${productId}\`);\n\n    // ✅ Validación de la respuesta\n    if (!isValidProductResponse(response.data)) {\n      return res.status(500).send('Datos inválidos recibidos de la API');\n    }\n\n    // ✅ Filtrado de la respuesta para evitar posibles scripts maliciosos\n    const sanitizedProductData = {\n      ...response.data,\n      name: xss(response.data.name),  // Sanitizar el nombre del producto\n      description: xss(response.data.description),  // Sanitizar la descripción\n    };\n\n    res.send(sanitizedProductData);\n  } catch (error) {\n    res.status(500).send('Error al obtener los datos del producto');\n  }\n});`
        }
    }
}

export default apiData
