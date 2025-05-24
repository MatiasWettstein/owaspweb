const webData = {
  risk1: {
    title: "Broken Access Control",
    attackVector: "Explotación de fallos en la implementación de restricciones sobre lo que los usuarios autenticados pueden hacer.",
    weakness: "Controles de acceso mal implementados o ausentes que permiten a los atacantes acceder, modificar o eliminar datos no autorizados.",
    impact: "Acceso no autorizado a funcionalidades, datos sensibles o cuentas de otros usuarios.",
    mitigationStrategies: [
      "Implementar un modelo de control de acceso consistente con denegación por defecto.",
      "Validar permisos en cada solicitud, no solo en el frontend.",
      "Desactivar el listado de directorios y asegurar que los metadatos de archivos no sean accesibles.",
      "Registrar fallos de control de acceso y alertar a los administradores cuando sea apropiado.",
    ],
    exampleTitle: "Ejemplo de código vulnerable",
    example1: {
      language: 'javascript',
      vulnerable: `// GET /user/:id\napp.get('/user/:id', (req, res) => {\n  const userId = req.params.id;\n  const user = db.getUserById(userId);\n  if (!user) return res.status(404).send("User not found");\n\n  // ❌ Devuelve cualquier usuario, sin validar si el solicitante tiene acceso\n  res.json(user);\n});`,
      secure: `// GET /user/:id\napp.get('/user/:id', (req, res) => {\n  const requestedId = parseInt(req.params.id);\n  const authenticatedId = req.user.id;\n\n  if (requestedId !== authenticatedId && req.user.role !== 'admin') {\n    return res.status(403).send("Access denied");\n  }\n\n  const user = db.getUserById(requestedId);\n  if (!user) return res.status(404).send("User not found");\n\n  res.json(user);\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// Frontend (React o HTML/JS)\nif (user.role === 'admin') {\n  document.getElementById("adminPanel").style.display = "block";\n}\n\n// Backend sin verificación\napp.get('/admin/data', (req, res) => {\n  // ❌ No valida el rol del usuario\n  res.send("Admin info: user list, settings...");\n});`,
      secure: `app.get('/admin/data', (req, res) => {\n  if (req.user.role !== 'admin') {\n    return res.status(403).send("Forbidden");\n  }\n\n  res.send("Admin info: user list, settings...");\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// DELETE /comment/:id\napp.delete('/comment/:id', (req, res) => {\n  const comment = db.getCommentById(req.params.id);\n  if (!comment) return res.status(404).send("Not found");\n\n  // ❌ Cualquiera puede borrar cualquier comentario\n  db.deleteComment(comment.id);\n  res.send("Comment deleted");\n});`,
      secure: `// DELETE /comment/:id\napp.delete('/comment/:id', (req, res) => {\n  const comment = db.getCommentById(req.params.id);\n  if (!comment) return res.status(404).send("Not found");\n\n  if (comment.ownerId !== req.user.id && req.user.role !== 'admin') {\n    return res.status(403).send("Unauthorized");\n  }\n\n  db.deleteComment(comment.id);\n  res.send("Comment deleted");\n});`
    }
  },
  risk2: {
    title: "Cryptographic Failures",
    attackVector: "Explotación de fallos en la implementación de cifrado o ausencia del mismo para acceder a datos sensibles.",
    weakness: "Datos sensibles transmitidos o almacenados sin cifrado adecuado, uso de algoritmos obsoletos o claves débiles.",
    impact: "Exposición de información sensible como credenciales, datos personales, tarjetas de crédito o información médica.",
    mitigationStrategies: [
      "Clasificar los datos procesados, almacenados o transmitidos por la aplicación.",
      "Cifrar todos los datos sensibles en reposo y en tránsito.",
      "Utilizar algoritmos de cifrado fuertes y actualizados.",
      "Almacenar contraseñas usando funciones de hashing seguras (bcrypt, Argon2).",
      "Deshabilitar el almacenamiento en caché para respuestas que contengan datos sensibles.",
    ],
    exampleTitle: "Ejemplo de código vulnerable",
    example1: {
      language: 'javascript',
      vulnerable: `// Registro de usuario (guarda la contraseña en texto plano)\napp.post('/register', (req, res) => {\n  const { username, password } = req.body;\n\n  // ❌ ¡Contraseña almacenada directamente!\n  db.saveUser({ username, password });\n\n  res.send("User registered");\n});`,
      secure: `const bcrypt = require('bcrypt');\n\n// Registro de usuario con hash\napp.post('/register', async (req, res) => {\n  const { username, password } = req.body;\n\n  const hashedPassword = await bcrypt.hash(password, 10);\n  db.saveUser({ username, password: hashedPassword });\n\n  res.send("User registered securely");\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `const crypto = require('crypto');\n\n// Cifrado usando algoritmo obsoleto (DES)\nfunction encrypt(text) {\n  const cipher = crypto.createCipher('des', 'secret-key');\n  let encrypted = cipher.update(text, 'utf8', 'hex');\n  encrypted += cipher.final('hex');\n  return encrypted;\n}`,
      secure: `const crypto = require('crypto');\n\n// Cifrado fuerte usando AES-256-GCM\nfunction encrypt(text, key, iv) {\n  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);\n  const tag = cipher.getAuthTag();\n  return { encrypted, iv, tag };\n}`
    },
    example3: {
      language: 'javascript',
      vulnerable: `const jwt = require('jsonwebtoken');\n\n// Verifica el token pero acepta cualquier algoritmo\nfunction verifyToken(token) {\n  // ❌ No especifica algoritmo, acepta "none"\n  return jwt.verify(token, 'secret');\n}`,
      secure: `const jwt = require('jsonwebtoken');\n\n// Verifica el token especificando algoritmo seguro\nfunction verifyToken(token) {\n  return jwt.verify(token, 'secret', { algorithms: ['HS256'] });\n}`
    }
  },
  risk3: {
    title: "Injection",
    attackVector: "Envío de datos hostiles a un intérprete como parte de un comando o consulta.",
    weakness: "Falta de validación, sanitización o parametrización de entradas del usuario en consultas SQL, comandos OS, XML, etc.",
    impact: "Pérdida o corrupción de datos, divulgación de información sensible, denegación de acceso o incluso control completo del servidor.",
    mitigationStrategies: [
      "Usar consultas parametrizadas o preparadas.",
      "Validar todas las entradas del lado del servidor.",
      "Utilizar ORM (Object Relational Mapping) con parámetros vinculados.",
      "Implementar listas blancas para validación de entradas.",
      "Limitar los privilegios de las cuentas de base de datos utilizadas por las aplicaciones.",
    ],
    exampleTitle: "Ejemplo de código vulnerable",
    example1: {
      language: 'javascript',
      vulnerable: `// GET /user?username=admin\napp.get('/user', (req, res) => {\n  const username = req.query.username;\n\n  // ❌ Consulta construida con interpolación directa\n  const query = \`SELECT * FROM users WHERE username = '\${username}'\`;\n  db.query(query, (err, results) => {\n    res.json(results);\n  });\n});`,
      secure: `// ✅ Consulta parametrizada\napp.get('/user', (req, res) => {\n  const username = req.query.username;\n\n  const query = \`SELECT * FROM users WHERE username = ?\`;\n  db.query(query, [username], (err, results) => {\n    res.json(results);\n  });\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `const { exec } = require('child_process');\n\n// Ejecuta ping a un host ingresado por el usuario\napp.get('/ping', (req, res) => {\n  const host = req.query.host;\n\n  // ❌ Vulnerable a command injection (ej: ?host=google.com;rm -rf /)\n  exec(\`ping -c 1 \${host}\`, (err, stdout, stderr) => {\n    res.send(stdout || stderr);\n  });\n});`,
      secure: `const { spawn } = require('child_process');\n\n// Usa spawn con argumentos separados y validación\napp.get('/ping', (req, res) => {\n  const host = req.query.host;\n\n  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) {\n    return res.status(400).send("Invalid host");\n  }\n\n  const ping = spawn('ping', ['-c', '1', host]);\n\n  let output = '';\n  ping.stdout.on('data', (data) => output += data);\n  ping.on('close', () => res.send(output));\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// MongoDB - inicio de sesión\napp.post('/login', async (req, res) => {\n  const { username, password } = req.body;\n\n  // ❌ Un atacante puede enviar: { "username": { "$ne": null }, "password": { "$ne": null } }\n  const user = await db.collection('users').findOne({ username, password });\n\n  if (!user) return res.status(401).send("Invalid credentials");\n  res.send("Welcome!");\n});`,
      secure: `app.post('/login', async (req, res) => {\n  const { username, password } = req.body;\n\n  if (typeof username !== 'string' || typeof password !== 'string') {\n    return res.status(400).send("Invalid input");\n  }\n\n  const user = await db.collection('users').findOne({ username, password });\n\n  if (!user) return res.status(401).send("Invalid credentials");\n  res.send("Welcome!");\n});`
    }
  },
  risk4: {
    title: "Insecure Design",
    attackVector: "Explotación de fallos en el diseño y la arquitectura de seguridad de la aplicación.",
    weakness: "Ausencia de controles de seguridad desde la fase de diseño, falta de modelado de amenazas o diseño que no considera casos de abuso.",
    impact: "Amplia gama de vulnerabilidades que pueden afectar todo el sistema, desde pérdida de datos hasta compromiso completo.",
    mitigationStrategies: [
      "Establecer un ciclo de vida de desarrollo seguro (SDLC).",
      "Utilizar bibliotecas y herramientas seguras por diseño.",
      "Modelar amenazas para flujos críticos en la aplicación.",
      "Integrar consideraciones de seguridad en historias de usuario y casos de prueba.",
      "Implementar límites de recursos y controles a nivel de arquitectura.",
    ],
    exampleTitle: "Ejemplo de diseño inseguro",
    example1: {
      language: 'javascript',
      vulnerable: `// Frontend (HTML o React)\n<button id="transferButton">Transferir $100</button>\n\n// Backend (acepta cualquier monto)\napp.post('/transfer', (req, res) => {\n  const { toUserId, amount } = req.body;\n\n  // ❌ No se valida si el usuario tiene saldo suficiente\n  db.transfer(req.user.id, toUserId, amount);\n  res.send("Transfer completed");\n});`,
      secure: `app.post('/transfer', async (req, res) => {\n  const { toUserId, amount } = req.body;\n  const balance = await db.getUserBalance(req.user.id);\n\n  if (amount > balance) {\n    return res.status(400).send("Insufficient funds");\n  }\n\n  await db.transfer(req.user.id, toUserId, amount);\n  res.send("Transfer completed");\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// El usuario puede modificar productos desde el frontend\n// PATCH /product/:id\napp.patch('/product/:id', async (req, res) => {\n  const productId = req.params.id;\n\n  // ❌ No valida si el usuario es el dueño o tiene permisos\n  await db.updateProduct(productId, req.body);\n  res.send("Product updated");\n});`,
      secure: `app.patch('/product/:id', async (req, res) => {\n  const productId = req.params.id;\n  const product = await db.getProductById(productId);\n\n  if (!product || product.ownerId !== req.user.id) {\n    return res.status(403).send("Forbidden");\n  }\n\n  await db.updateProduct(productId, req.body);\n  res.send("Product updated");\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// Recuperación de contraseña por pregunta secreta\napp.post('/recover', async (req, res) => {\n  const { username, answer } = req.body;\n  const user = await db.findUserByUsername(username);\n\n  // ❌ Usa una pregunta predecible, sin límite de intentos\n  if (user.securityAnswer === answer) {\n    res.send(\`Tu contraseña es: \${user.password}\`);\n  } else {\n    res.status(401).send("Incorrect answer");\n  }\n});`,
      secure: `// Envío de link de recuperación temporal con token\napp.post('/recover', async (req, res) => {\n  const { email } = req.body;\n  const user = await db.findUserByEmail(email);\n  if (!user) return res.send("If this email exists, a link was sent");\n\n  const token = generateSecureToken(); // con expiración\n  await db.saveRecoveryToken(user.id, token);\n\n  await sendEmail(email, \`Recover your account: https://app.com/reset?token=\${token}\`);\n  res.send("If this email exists, a link was sent");\n});`
    }
  },
  risk5: {
    title: "Security Misconfiguration",
    attackVector: "Explotación de sistemas mal configurados, incompletos o con configuraciones por defecto.",
    weakness: "Configuraciones de seguridad incorrectas, servicios innecesarios habilitados, permisos incorrectos, etc.",
    impact: "Acceso no autorizado a datos o funcionalidades del sistema, hasta compromiso completo del servidor.",
    mitigationStrategies: [
      "Implementar un proceso de endurecimiento de seguridad para todos los entornos.",
      "Eliminar o no instalar características, componentes o servicios no utilizados.",
      "Revisar y actualizar configuraciones como parte del proceso de gestión de parches.",
      "Implementar una arquitectura de segmentación con separación entre componentes.",
      "Enviar directivas de seguridad a los clientes (headers de seguridad).",
    ],
    exampleTitle: "Ejemplo de configuración segura",
    example1: {
      language: 'javascript',
      vulnerable: `// Express sin ningún header de seguridad\nconst express = require('express');\nconst app = express();\n\napp.get('/', (req, res) => {\n  res.send("Hello world");\n});\n\napp.listen(3000);`,
      secure: `// Express usando helmet para agregar headers seguros\nconst express = require('express');\nconst helmet = require('helmet');\n\nconst app = express();\napp.use(helmet()); // ✅ Activa varios headers de seguridad\n\napp.get('/', (req, res) => {\n  res.send("Hello world");\n});\n\napp.listen(3000);`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// Express con stack traces en producción\napp.use((err, req, res, next) => {\n  // ❌ Devuelve detalles del error al cliente\n  res.status(500).send(err.stack);\n});`,
      secure: `// Manejo de errores controlado\napp.use((err, req, res, next) => {\n  // ✅ No revela información sensible en producción\n  console.error(err); // log interno\n  res.status(500).send("Something went wrong");\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// Rutas administrativas sin protección\napp.use('/admin', require('./adminRoutes'));\n\n// adminRoutes.js\nrouter.get('/dashboard', (req, res) => {\n  res.send("Admin Panel");\n});\n\n// ⚠️ Si un atacante descubre /admin, puede acceder libremente.`,
      secure: `// Middleware de autenticación para rutas de admin\nfunction isAdmin(req, res, next) {\n  if (req.user && req.user.role === 'admin') return next();\n  return res.status(403).send("Forbidden");\n}\n\napp.use('/admin', isAdmin, require('./adminRoutes'));`
    }
  },
  risk6: {
    title: "Vulnerable and Outdated Components",
    attackVector: "Explotación de vulnerabilidades conocidas en componentes desactualizados o sin parches.",
    weakness: "Uso de bibliotecas, frameworks o componentes con vulnerabilidades conocidas o sin soporte.",
    impact: "Desde pérdida de datos hasta compromiso completo del servidor, dependiendo de la vulnerabilidad explotada.",
    mitigationStrategies: [
      "Eliminar dependencias, características y archivos no utilizados.",
      "Mantener un inventario de componentes y sus versiones.",
      "Monitorear fuentes como CVE y boletines de seguridad.",
      "Utilizar herramientas de análisis de composición de software.",
      "Obtener componentes únicamente de fuentes oficiales y verificar su integridad.",
    ],
    exampleTitle: "Ejemplo de gestión de dependencias",
    example1: {
      language: 'html',
      vulnerable: `<!-- jQuery 1.6.2 contiene vulnerabilidades XSS conocidas -->\n<script src="https://code.jquery.com/jquery-1.6.2.min.js"></script>\n<script>\n  const param = new URLSearchParams(window.location.search).get("msg");\n  $('#output').html(param); // ❌ vulnerable a XSS\n</script>`,
      secure: `<!-- jQuery actualizado -->\n<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>\n<script>\n  const param = new URLSearchParams(window.location.search).get("msg");\n  $('#output').text(param); // ✅ evita ejecución de HTML\n</script>`
    },
    example2: {
      language: 'json',
      vulnerable: `{\n  "dependencies": {\n    "lodash": "4.17.20" // La versión 4.17.20 tiene vulnerabilidades de prototype pollution (CVE-2020-8203)\n  }\n}`,
      secure: `{\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}\n// Además, escanear con npm audit`
    },
    example3: {
      language: 'docker',
      vulnerable: `# Imagen base desactualizada con múltiples CVEs\nFROM node:14\n\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD ["node", "server.js"]`,
      secure: `# Imagen base actualizada y escaneada\nFROM node:18-alpine\n\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "server.js"]\n\n# Puedes escanear con herramientas como Trivy, Docker Scout o Snyk`
    }
  },
  risk7: {
    title: "Identification and Authentication Failures",
    attackVector: "Explotación de fallos en la autenticación para asumir la identidad de otros usuarios.",
    weakness: "Implementación incorrecta de la autenticación, permitiendo ataques de fuerza bruta, reutilización de credenciales, etc.",
    impact: "Compromiso de cuentas de usuario, desde usuarios normales hasta administradores, permitiendo robo de identidad.",
    mitigationStrategies: [
      "Implementar autenticación multifactor cuando sea posible.",
      "No desplegar con credenciales por defecto.",
      "Implementar controles contra ataques de fuerza bruta.",
      "Validar la fortaleza de las contraseñas.",
      "Utilizar un gestor de sesiones seguro del lado del servidor.",
    ],
    exampleTitle: "Ejemplo de autenticación segura",
    example1: {
      language: 'javascript',
      vulnerable: `// Ruta de login sin protección contra fuerza bruta\napp.post('/login', async (req, res) => {\n  const { username, password } = req.body;\n  const user = await db.findUser(username);\n\n  if (user && user.password === password) {\n    return res.send("Login successful");\n  }\n\n  res.status(401).send("Invalid credentials");\n});`,
      secure: `// Ruta protegida con limitador de intentos (usando express-rate-limit)\nconst rateLimit = require('express-rate-limit');\n\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutos\n  max: 5, // máximo 5 intentos\n  message: "Too many login attempts, please try again later"\n});\n\napp.post('/login', loginLimiter, async (req, res) => {\n  // lógica de login\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// Guardar contraseña sin hash (inseguro)\napp.post('/register', async (req, res) => {\n  const { username, password } = req.body;\n  await db.createUser({ username, password }); // ❌ texto plano\n  res.send("User created");\n});`,
      secure: `// Usar bcrypt para hash de contraseñas\nconst bcrypt = require('bcrypt');\n\napp.post('/register', async (req, res) => {\n  const { username, password } = req.body;\n  const hash = await bcrypt.hash(password, 12); // ✅ hash seguro\n  await db.createUser({ username, password: hash });\n  res.send("User created");\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// Crea un token simple y persistente\napp.post('/login', async (req, res) => {\n  const { username } = req.body;\n  const token = Buffer.from(username).toString('base64'); // ❌ predecible\n  res.cookie('session', token);\n  res.send("Logged in");\n});`,
      secure: `// Usar JWT firmado, con expiración\nconst jwt = require('jsonwebtoken');\nconst SECRET = process.env.JWT_SECRET;\n\napp.post('/login', async (req, res) => {\n  const { username } = req.body;\n  const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' }); // ✅ seguro\n  res.cookie('token', token, {\n    httpOnly: true,\n    secure: true,\n    sameSite: 'Strict'\n  });\n  res.send("Logged in");\n});`
    }
  },
  risk8: {
    title: "Software and Data Integrity Failures",
    attackVector: "Explotación de fallos en la verificación de integridad de software y datos.",
    weakness: "Falta de verificación de integridad de software y datos, permitiendo actualizaciones no verificadas o manipulación de datos.",
    impact: "Desde pérdida de integridad de datos hasta ejecución de código malicioso en servidores o clientes.",
    mitigationStrategies: [
      "Utilizar firmas digitales para verificar la integridad de software.",
      "Asegurar que las dependencias se obtienen de repositorios confiables.",
      "Implementar revisión de código y aprobaciones múltiples para cambios.",
      "Asegurar que CI/CD tiene una adecuada segregación, configuración y control de acceso.",
      "Verificar la integridad de datos críticos mediante firmas o hashes.",
    ],
    exampleTitle: "Ejemplo de verificación de integridad",
    example1: {
      language: 'html',
      vulnerable: `<!-- Script externo sin verificación de integridad -->\n<script src="https://cdn.example.com/library.js"></script>`,
      secure: `<!-- Script con hash de integridad y CORS -->\n<script \n  src="https://cdn.example.com/library.js"\n  integrity="sha384-AbCd123..." \n  crossorigin="anonymous">\n</script>`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// Descarga de código externo sin verificar fuente o firma\nconst https = require('https');\nhttps.get("https://updates.example.com/update.js", res => {\n  res.pipe(fs.createWriteStream("update.js"));\n});`,
      secure: `// Verifica firma digital del archivo descargado\nconst crypto = require('crypto');\nconst fs = require('fs');\n\n// Simulación: hashear y verificar la firma antes de usar\nconst expectedHash = "abcdef1234567890...";\nconst fileBuffer = fs.readFileSync("update.js");\nconst hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');\n\nif (hash === expectedHash) {\n  require('./update.js'); // ✅ solo si la integridad es válida\n} else {\n  console.error("Update file is invalid or has been tampered with.");\n}`
    },
    example3: {
      language: 'yaml',
      vulnerable: `# .github/workflows/deploy.yml\nsteps:\n  - name: Checkout repo\n    uses: actions/checkout@master # ❌ uso de branch mutable\n  - name: Deploy\n    run: ./deploy.sh`,
      secure: `# Uso de un tag o commit específico, y firma de acción verificada\nsteps:\n  - name: Checkout repo\n    uses: actions/checkout@v3 # ✅ versión fija\n    with:\n      token: \${{ secrets.GITHUB_TOKEN }}\n  - name: Verify deployment artifact\n    run: |\n      gpg --verify app.sig app.tar.gz # ✅ verifica la integridad antes de desplegar\n  - name: Deploy\n    run: ./deploy.sh`
    }
  },
  risk9: {
    title: "Security Logging and Monitoring Failures",
    attackVector: "Explotación de la falta de detección y respuesta a brechas de seguridad.",
    weakness: "Registros insuficientes, falta de monitoreo o integración con sistemas de respuesta a incidentes.",
    impact: "Incapacidad para detectar, responder o recuperarse de brechas activas, permitiendo ataques prolongados.",
    mitigationStrategies: [
      "Implementar registro de eventos de seguridad relevantes.",
      "Asegurar que los registros incluyan suficiente contexto para análisis forense.",
      "Establecer monitoreo efectivo y alertas para actividades sospechosas.",
      "Crear un plan de respuesta a incidentes y recuperación.",
      "Utilizar herramientas SIEM (Security Information and Event Management).",
    ],
    exampleTitle: "Ejemplo de logging seguro",
    example1: {
      language: 'javascript',
      vulnerable: `app.post('/login', async (req, res) => {\n  const user = await db.findUser(req.body.username);\n  if (!user || user.password !== req.body.password) {\n    return res.status(401).send("Invalid credentials");\n  }\n  res.send("Logged in");\n});`,
      secure: `const logger = require('./logger'); // supongamos que hay un logger configurado\n\napp.post('/login', async (req, res) => {\n  const user = await db.findUser(req.body.username);\n  if (!user || user.password !== req.body.password) {\n    logger.warn(\`Failed login attempt for user: \${req.body.username}\`);\n    return res.status(401).send("Invalid credentials");\n  }\n  logger.info(\`User \${req.body.username} logged in\`);\n  res.send("Logged in");\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// El sistema registra internamente errores críticos pero nadie los revisa\nlogger.error("Too many failed login attempts");`,
      secure: `// Envío de alertas y monitoreo proactivo\nlogger.error("Too many failed login attempts");\nnotifySecurityTeam("Multiple login failures detected from IP: " + req.ip);\n\n// Ejemplo de integración con un sistema SIEM o notificación\nfunction notifySecurityTeam(message) {\n  // Enviar a Slack, SIEM, correo, etc.\n  sendToMonitoringService({ level: "critical", message });\n}`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// Logs escritos directamente en archivos sin control de acceso\nfs.appendFileSync('app.log', \`User \${username} failed login\`);`,
      secure: `const winston = require('winston');\nconst fs = require('fs');\n\n// Asegurarse de que los archivos tengan permisos restringidos\nfs.chmodSync('secure.log', 0o600); // ✅ solo lectura/escritura para el dueño\n\nconst logger = winston.createLogger({\n  level: 'info',\n  format: winston.format.json(),\n  transports: [\n    new winston.transports.File({ filename: 'secure.log' })\n  ]\n});\n\nlogger.warn("Login attempt failed", {\n  username: req.body.username,\n  ip: req.ip,\n  timestamp: new Date().toISOString()\n});`
    }
  },
  risk10: {
    title: "Server-Side Request Forgery (SSRF)",
    attackVector: "Manipulación del servidor para que realice solicitudes HTTP a destinos arbitrarios.",
    weakness: "Falta de validación de URLs proporcionadas por el usuario antes de que el servidor realice solicitudes.",
    impact: "Escaneo de puertos internos, acceso a servicios internos, exfiltración de datos o ejecución de código remoto.",
    mitigationStrategies: [
      "Sanitizar y validar todas las entradas de datos del cliente.",
      "Implementar listas blancas de dominios/IPs permitidos.",
      "Bloquear tráfico a direcciones IP privadas y localhost.",
      "Implementar políticas de firewall para bloquear conexiones no esenciales.",
      "No enviar respuestas en bruto al cliente.",
    ],
    exampleTitle: "Ejemplo de mitigación de SSRF",
    example1: {
      language: 'javascript',
      vulnerable: `// El usuario puede hacer que el servidor haga peticiones arbitrarias\napp.post('/fetch', async (req, res) => {\n  const { url } = req.body;\n  const response = await fetch(url); // ❌ SSRF posible\n  const data = await response.text();\n  res.send(data);\n});`,
      secure: `const allowedDomains = ['https://api.example.com', 'https://docs.example.com'];\n\napp.post('/fetch', async (req, res) => {\n  const { url } = req.body;\n\n  if (!allowedDomains.some(domain => url.startsWith(domain))) {\n    return res.status(403).send("URL not allowed");\n  }\n\n  const response = await fetch(url); // ✅ acceso limitado\n  const data = await response.text();\n  res.send(data);\n});`
    },
    example2: {
      language: 'javascript',
      vulnerable: `// Permite acceder a URLs internas como http://localhost/admin o 169.254.x.x\napp.get('/image-proxy', async (req, res) => {\n  const { imageUrl } = req.query;\n  const response = await fetch(imageUrl);\n  const buffer = await response.arrayBuffer();\n  res.setHeader('Content-Type', 'image/jpeg');\n  res.send(Buffer.from(buffer));\n});`,
      secure: `const dns = require('dns').promises;\nconst { URL } = require('url');\n\nasync function isPrivateIp(urlString) {\n  try {\n    const url = new URL(urlString);\n    const addresses = await dns.lookup(url.hostname, { all: true });\n\n    return addresses.some(addr => {\n      return /^127\./.test(addr.address) || // localhost\n             /^10\./.test(addr.address) ||  // red privada\n             /^192\.168\./.test(addr.address) ||\n             /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(addr.address);\n    });\n  } catch (e) {\n    return true; // fallback a denegar\n  }\n}\n\napp.get('/image-proxy', async (req, res) => {\n  const { imageUrl } = req.query;\n\n  if (await isPrivateIp(imageUrl)) {\n    return res.status(403).send("Access to internal resources denied");\n  }\n\n  const response = await fetch(imageUrl);\n  const buffer = await response.arrayBuffer();\n  res.setHeader('Content-Type', 'image/jpeg');\n  res.send(Buffer.from(buffer));\n});`
    },
    example3: {
      language: 'javascript',
      vulnerable: `// Recibe una URL de webhook sin validación\napp.post('/register-webhook', async (req, res) => {\n  const { url } = req.body;\n  db.saveWebhook(url); // ❌ el servidor luego enviará datos a cualquier URL\n  res.send("Webhook saved");\n});`,
      secure: `const validWebhookDomain = /^https:\/\/hooks\.example\.com\/.*/;\n\napp.post('/register-webhook', async (req, res) => {\n  const { url } = req.body;\n\n  if (!validWebhookDomain.test(url)) {\n    return res.status(400).send("Invalid webhook URL");\n  }\n\n  db.saveWebhook(url); // ✅ solo dominios específicos permitidos\n  res.send("Webhook saved");\n});`
    }
  },
}

export default webData