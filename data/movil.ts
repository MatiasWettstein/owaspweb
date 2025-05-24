const movilData = {
    "risk1": {
        "title": "Uso Incorrecto de Credenciales",
        "attackVector": "Acceso a datos de autenticación mal almacenados o expuestos en el dispositivo.",
        "weakness": "Credenciales almacenadas sin cifrado o dentro del código fuente.",
        "impact": "Puede permitir que un atacante acceda a cuentas o funcionalidades restringidas.",
        "mitigationStrategies": [
            "Almacenar credenciales en lugares seguros como Keystore o Keychain.",
            "Evitar insertar claves en el código fuente.",
            "Usar autenticación basada en tokens temporales."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Guardar datos sensibles sin cifrar en UserDefaults \nlet username = \"admin\"\nlet password = \"123456\"\nUserDefaults.standard.set(username, forKey: \"username\")\nUserDefaults.standard.set(password, forKey: \"password\")",
                "secure": "// ✅ Usar Keychain para almacenar datos sensibles de forma cifrada\nimport Security\nlet passwordData = \"123456\".data(using: .utf8)!\nlet query: [String: Any] = [\n    kSecClass as String: kSecClassGenericPassword,\n    kSecAttrAccount as String: \"userPassword\",\n    kSecValueData as String: passwordData\n]\nSecItemAdd(query as CFDictionary, nil)"
            },
            "kotlin": {
                "vulnerable": "// ❌ Guardar usuario y contraseña sin cifrar en SharedPreferences\nval prefs = getSharedPreferences(\"creds\", MODE_PRIVATE)\nprefs.edit().putString(\"username\", \"admin\").apply()\nprefs.edit().putString(\"password\", \"123456\").apply()",
                "secure": "// ✅ Usar EncryptedSharedPreferences para cifrar valores almacenados\nval masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)\nval encryptedPrefs = EncryptedSharedPreferences.create(\n    \"secure_prefs\",\n    masterKeyAlias,\n    context,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nencryptedPrefs.edit().putString(\"password\", \"123456\").apply()"
            },
            "reactnative": {
                "vulnerable": "// ❌ Guardar datos sensibles sin cifrar en AsyncStorage\nimport { AsyncStorage } from 'react-native';\nAsyncStorage.setItem('username', 'admin');\nAsyncStorage.setItem('password', '123456');",
                "secure": "// ✅ Usar react-native-keychain para almacenamiento seguro cifrado\nimport * as Keychain from 'react-native-keychain';\nawait Keychain.setGenericPassword('admin', '123456');"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Se usa la contraseña directamente sin obtenerla de un lugar seguro\nfunc login() {\n  let credentials = [\"user\": \"admin\", \"pass\": \"123456\"]\n  sendLogin(credentials: credentials)\n}",
                "secure": "// ✅ Se recupera la contraseña desde el Keychain antes de usarlafunc loginSecure() {\n  let password = getPasswordFromKeychain()\n  let credentials = [\"user\": \"admin\", \"pass\": password]\n  sendLogin(credentials: credentials)\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Contraseña codificada directamente en la app\nfun login() {\n  val credentials = mapOf(\"user\" to \"admin\", \"pass\" to \"123456\")\n  sendToServer(credentials)\n}",
                "secure": "// ✅ Recupera la contraseña desde almacenamiento seguro\nfun loginSecure() {\n  val password = getPasswordFromSecureStorage()\n  val credentials = mapOf(\"user\" to \"admin\", \"pass\" to password)\n  sendToServer(credentials)\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Contraseña en texto plano dentro del código\nfunction login() {\n  const creds = { user: 'admin', pass: '123456' };\n  sendLogin(creds);\n}",
                "secure": "// ✅ Recupera datos desde el sistema seguro de almacenamiento\nimport * as Keychain from 'react-native-keychain';\nasync function loginSecure() {\n  const creds = await Keychain.getGenericPassword();\n  if (creds) {\n    sendLogin({ user: creds.username, pass: creds.password });\n  }\n}"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ Credenciales codificadas en base64 visibles si se intercepta la petición\nlet credentials = \"admin:123456\"\nlet base64 = Data(credentials.utf8).base64EncodedString()\nrequest.setValue(\"Basic \\(base64)\", forHTTPHeaderField: \"Authorization\")",
                "secure": "// ✅ Uso de token (ej. JWT) obtenido y guardado de forma segura\nlet token = retrieveSecureToken()\nrequest.setValue(\"Bearer \\(token)\", forHTTPHeaderField: \"Authorization\")"
            },
            "kotlin": {
                "vulnerable": "// ❌ Codifica credenciales directamente, sin cifrado ni token\nval creds = \"admin:123456\"\nval base64 = Base64.encodeToString(creds.toByteArray(), Base64.NO_WRAP)\nrequest.setHeader(\"Authorization\", \"Basic $base64\")",
                "secure": "// ✅ Utiliza token de autenticación seguro\nval token = secureTokenProvider.getToken()\nrequest.setHeader(\"Authorization\", \"Bearer $token\")"
            },
            "reactnative": {
                "vulnerable": "// ❌ Envía usuario y contraseña en base64 en cada request\nconst credentials = 'admin:123456';\nconst base64 = Buffer.from(credentials).toString('base64');\nfetch(url, { headers: { Authorization: `Basic ${base64}` } });",
                "secure": "// ✅ Se usa un token JWT guardado de forma segura\nconst token = await getAuthTokenSecurely();\nfetch(url, { headers: { Authorization: `Bearer ${token}` } });"
            }
        }
    },
    "risk2": {
        "title": "Seguridad Inadecuada en la Cadena de Suministro",
        "attackVector": "Inclusión de librerías o SDKs de terceros vulnerables o maliciosos.",
        "weakness": "Dependencias con código no verificado o con permisos excesivos.",
        "impact": "Puede introducir puertas traseras o facilitar ataques indirectos.",
        "mitigationStrategies": [
            "Revisar la seguridad de cada librería o SDK antes de incluirlos.",
            "Actualizar dependencias con regularidad.",
            "Usar herramientas de análisis de composición de software (SCA)."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Uso de librería externa de GitHub sin verificar integridad\n// Podría haber sido comprometida si el repositorio fue atacado\n.package(url: \"https://github.com/usuario-desconocido/crypto-lib.git\", from: \"1.0.0\")",
                "secure": "// ✅ Validación de integridad con Package.resolved + revisión manual\n// Uso de repositorio oficial y revisión de cambios\n.package(url: \"https://github.com/apple/swift-crypto.git\", from: \"2.0.0\")"
            },
            "kotlin": {
                "vulnerable": "// Agregando dependencia directa desde un repositorio privado no verificado\nimplementation(\"com.untrusted.sdk:tracking-lib:1.0.0\")",
                "secure": "// ✅ Uso de librería de repositorio oficial y verificación de checksum\nimplementation(\"com.google.firebase:firebase-analytics:21.3.0\")\n// Además, usar Gradle Dependency Verification con archivo checksum"
            },
            "reactnative": {
                "vulnerable": "// ❌ Instalación de paquete sin revisar su procedencia\nnpm install react-native-unknown-tracker",
                "secure": "// ✅ Uso de paquete con autor verificado y revisión de código abierto\nnpm install react-native-device-info\n// Además, revisar el contenido del package-lock.json y usar 'npm audit'"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Inclusión de binario precompilado desde fuente no oficial\nbinaryTarget(name: \"AdTracker\", url: \"https://malicioso.com/AdTracker.xcframework.zip\", checksum: \"\")",
                "secure": "// ✅ Validación con checksum y uso de origen confiable\nbinaryTarget(name: \"FirebaseAnalytics\", url: \"https://dl.google.com/.../FirebaseAnalytics.xcframework.zip\", checksum: \"abc123...\" )"
            },
            "kotlin": {
                "vulnerable": "// ❌ Dependencia con código ofuscado sin auditoría previa\nimplementation(\"org.unknown:lib-obfuscated:1.1.0\")",
                "secure": "// ✅ Uso de librería auditada de código abierto con versión mantenida\nimplementation(\"org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4\")"
            },
            "reactnative": {
                "vulnerable": "// ❌ Clonación de paquete de fuente desconocida y uso directo\nnpm install git+https://github.com/alguien-random/rn-payments.git",
                "secure": "// ✅ Uso de librería oficial mantenida\nnpm install react-native-payments\n// Revisión de dependencias con 'npm audit fix' y GitHub Dependabot"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ SDK de publicidad de proveedor desconocido sin política de actualizaciones\n.package(url: \"https://github.com/desconocido/ads-sdk.git\", from: \"0.1.0\")",
                "secure": "// ✅ Evaluación de terceros, revisión del código y monitoreo de actualizaciones\n.package(url: \"https://github.com/facebook/facebook-ios-sdk.git\", from: \"15.0.0\")"
            },
            "kotlin": {
                "vulnerable": "// ❌ No se usa verificación de firma en el artefacto descargado\nimplementation(\"com.malicious.analytics:core:3.2.0\")",
                "secure": "// ✅ Aplicación de firma PGP o checksum para verificar la integridad\ndependencies {\n  implementation(\"com.segment.analytics.android:analytics:4.10.4\")\n}\n// Verificado desde Maven Central"
            },
            "reactnative": {
                "vulnerable": "// ❌ Instalación de paquete deprecated sin revisión de issues\nnpm install react-native-old-auth",
                "secure": "// ✅ Instalación solo desde npm oficial y con revisión de actividad reciente\nnpm install @react-native-firebase/auth\n// Uso de herramientas como snyk y dependabot"
            }
        }
    },
    "risk3": {
        "title": "Autenticación/Autorización Insegura",
        "attackVector": "Manipulación del flujo de autenticación o reutilización de tokens.",
        "weakness": "Mecanismos de control de acceso mal implementados o débiles.",
        "impact": "Permite a usuarios no autorizados realizar acciones restringidas.",
        "mitigationStrategies": [
            "Implementar autenticación multifactor.",
            "Verificar tokens del lado del servidor en cada solicitud.",
            "Evitar confiar únicamente en validaciones del lado cliente."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Token guardado en UserDefaults\nUserDefaults.standard.set(\"eyJhbGciOiJIUzI1NiIsInR5cCI6...\", forKey: \"authToken\")",
                "secure": "// ✅ Token almacenado de forma segura en Keychain\nimport Security\nlet tokenData = \"eyJhbGciOiJIUzI1NiIsInR5cCI6...\".data(using: .utf8)!\nlet query: [String: Any] = [\n  kSecClass as String: kSecClassGenericPassword,\n  kSecAttrAccount as String: \"authToken\",\n  kSecValueData as String: tokenData\n]\nSecItemAdd(query as CFDictionary, nil)"
            },
            "kotlin": {
                "vulnerable": "// ❌ Guardar token en preferencias sin cifrado\nval prefs = getSharedPreferences(\"prefs\", MODE_PRIVATE)\nprefs.edit().putString(\"authToken\", token).apply()",
                "secure": "// ✅ Guardar token usando EncryptedSharedPreferences\nval securePrefs = EncryptedSharedPreferences.create(\n  context,\n  \"secure_prefs\",\n  masterKey,\n  EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n  EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nsecurePrefs.edit().putString(\"authToken\", token).apply()"
            },
            "reactnative": {
                "vulnerable": "// ❌ Almacenar token en AsyncStorage\nimport AsyncStorage from '@react-native-async-storage/async-storage';\nAsyncStorage.setItem('authToken', token);",
                "secure": "// ✅ Usar Keychain para guardar el token de forma segura\nimport * as Keychain from 'react-native-keychain';\nawait Keychain.setGenericPassword('user', token);"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Autenticación por nombre de usuario sin protección adicional\nif usernameField.text == \"admin\" && passwordField.text == \"1234\" {\n  login()\n}",
                "secure": "// ✅ Uso de autenticación segura con verificación backend y 2FA\nfunc loginUser(username: String, password: String) {\n  authenticateViaAPI(username: username, password: password) {\n    if $0.success { promptFor2FA() }\n  }\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Validación local insegura\nif (username == \"admin\" && password == \"1234\") {\n  login()\n}",
                "secure": "// ✅ Validación a través del backend con token JWT y posible MFA\napi.login(username, password).enqueue {\n  if (response.isSuccessful) {\n    prompt2FA()\n  }\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Autenticación dura en frontend\nif (username === 'admin' && password === '1234') {\n  navigateToHome();\n}",
                "secure": "// ✅ Solicitud segura al backend + 2FA\nfetch('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) })\n  .then(res => res.json())\n  .then(data => verify2FA(data.token));"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ Ruta protegida accesible sin validación\nfunc goToProfile() {\n  self.navigationController?.pushViewController(ProfileVC(), animated: true)\n}",
                "secure": "// ✅ Verificación de sesión antes de mostrar vista protegida\nif AuthManager.shared.isUserAuthenticated {\n  self.navigationController?.pushViewController(ProfileVC(), animated: true)\n} else {\n  showLogin()\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Acceso a actividad sin comprobar autenticación\nstartActivity(Intent(this, ProfileActivity::class.java))",
                "secure": "// ✅ Comprobar autenticación antes de abrir actividad\nif (sessionManager.isAuthenticated()) {\n  startActivity(Intent(this, ProfileActivity::class.java))\n} else {\n  showLoginPrompt()\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Redirección directa sin verificar sesión\nnavigation.navigate('Dashboard');",
                "secure": "// ✅ Comprobar autenticación antes de navegar\nif (await isAuthenticated()) {\n  navigation.navigate('Dashboard');\n} else {\n  navigation.navigate('Login');\n}"
            }
        }
    },
    "risk4": {
        "title": "Validación Insuficiente de Entrada/Salida",
        "attackVector": "Inyección de datos maliciosos a través de formularios o parámetros.",
        "weakness": "Falta de sanitización o validación de datos de entrada.",
        "impact": "Puede dar lugar a inyecciones SQL, XSS o corrupción de datos.",
        "mitigationStrategies": [
            "Validar y sanear todos los datos del usuario.",
            "Utilizar listas blancas de entrada permitida.",
            "Aplicar encoding de salida al presentar datos."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ No se valida si el email es válido\nlet email = emailTextField.text!\nsendToServer(email: email)",
                "secure": "// ✅ Validación usando NSPredicate\nlet email = emailTextField.text!\nlet emailRegex = \"[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{2,}\"\nlet predicate = NSPredicate(format: \"SELF MATCHES %@\", emailRegex)\nif predicate.evaluate(with: email) {\n  sendToServer(email: email)\n} else {\n  showError(\"Email inválido\")\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Uso del email sin validarlo\nval email = emailInput.text.toString()\nsendToServer(email)",
                "secure": "// ✅ Validación con expresión regular\nval email = emailInput.text.toString()\nval regex = Regex(\"[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\")\nif (regex.matches(email)) {\n  sendToServer(email)\n} else {\n  showToast(\"Email inválido\")\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ No se valida el email antes de enviarlo\nconst email = emailInput;\nsendToServer(email);",
                "secure": "// ✅ Validación simple con RegExp\nconst email = emailInput;\nconst emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;\nif (emailRegex.test(email)) {\n  sendToServer(email);\n} else {\n  Alert.alert('Email inválido');\n}"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Inserción directa en base de datos SQLite\nlet query = \"INSERT INTO users (name) VALUES ('\\(userInput)')\"\nexecuteSQL(query)",
                "secure": "// ✅ Uso de consultas preparadas con SQLite\nlet db: OpaquePointer? = openDatabase()\nlet insertQuery = \"INSERT INTO users (name) VALUES (?)\"\nvar stmt: OpaquePointer?\nif sqlite3_prepare_v2(db, insertQuery, -1, &stmt, nil) == SQLITE_OK {\n  sqlite3_bind_text(stmt, 1, userInput, -1, nil)\n  sqlite3_step(stmt)\n  sqlite3_finalize(stmt)\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ SQL sin validación de entrada\nval query = \"INSERT INTO users (name) VALUES ('$userInput')\"\ndatabase.execSQL(query)",
                "secure": "// ✅ Uso de SQLiteStatement preparado\nval stmt = database.compileStatement(\"INSERT INTO users (name) VALUES (?)\")\nstmt.bindString(1, userInput)\nstmt.execute()"
            },
            "reactnative": {
                "vulnerable": "// ❌ Consulta SQL con interpolación directa\nconst query = `INSERT INTO users (name) VALUES ('${userInput}')`;\ndb.transaction(tx => tx.executeSql(query));",
                "secure": "// ✅ Consulta con parámetros preparados\nconst query = 'INSERT INTO users (name) VALUES (?)';\ndb.transaction(tx => tx.executeSql(query, [userInput]));"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ Uso directo del JSON sin verificar campos\nlet user = try! JSONDecoder().decode(User.self, from: data)\nshowProfile(user)",
                "secure": "// ✅ Validar manualmente los campos antes de usar\nif let user = try? JSONDecoder().decode(User.self, from: data), !user.username.isEmpty, user.id > 0 {\n  showProfile(user)\n} else {\n  showError(\"Datos corruptos\")\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Parseo de JSON sin validación\nval user = gson.fromJson(response, User::class.java)\nshowUser(user)",
                "secure": "// ✅ Verificar campos requeridos después del parsing\nval user = gson.fromJson(response, User::class.java)\nif (!user.username.isNullOrEmpty() && user.id > 0) {\n  showUser(user)\n} else {\n  showError()\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Acceder directamente al objeto recibido\nconst user = await fetchUser();\nsetProfile(user);",
                "secure": "// ✅ Validar estructura y tipos del JSON antes de usarlo\nconst user = await fetchUser();\nif (user && typeof user.username === 'string' && user.username.length > 0 && Number.isInteger(user.id)) {\n  setProfile(user);\n} else {\n  Alert.alert('Datos inválidos');\n}"
            }
        }

    },
    "risk5": {
        "title": "Comunicación Insegura",
        "attackVector": "Intercepción de tráfico entre la app y el servidor a través de redes públicas.",
        "weakness": "Transmisión de datos sin cifrado o sin validación de certificados.",
        "impact": "Permite a atacantes espiar o modificar información sensible.",
        "mitigationStrategies": [
            "Usar HTTPS con certificados válidos y verificados.",
            "Implementar pinning de certificados.",
            "Evitar el uso de redes públicas para operaciones críticas."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Permitir tráfico HTTP en Info.plist\n<key>NSAppTransportSecurity</key>\n<dict>\n  <key>NSAllowsArbitraryLoads</key>\n  <true/>\n</dict>",
                "secure": "// ✅ Configuración segura en Info.plist (solo HTTPS)\n<key>NSAppTransportSecurity</key>\n<dict>\n  <key>NSAllowsArbitraryLoads</key>\n  <false/>\n</dict>\n\n// ✅ Implementación de Certificate Pinning\nclass CertificatePinningDelegate: NSObject, URLSessionDelegate {\n  // ✅ Lista de hashes de certificados confiables\n  private let pinnedCertificateHashes = [\"HASH1\", \"HASH2\"]\n  \n  func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, \n                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n    // ✅ Verificar certificado del servidor contra los hashes confiables\n    // ... implementación de la verificación ...\n  }\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Permitir tráfico HTTP en AndroidManifest.xml\n<application\n  android:usesCleartextTraffic=\"true\"\n  ...>\n</application>\n\n// ❌ Cliente HTTP sin validación de certificados\nval client = OkHttpClient.Builder()\n  .hostnameVerifier { hostname, session -> true } // ❌ Acepta cualquier certificado\n  .build()",
                "secure": "// ✅ Bloquear tráfico HTTP en AndroidManifest.xml\n<application\n  android:usesCleartextTraffic=\"false\"\n  ...>\n</application>\n\n// ✅ Implementación de Certificate Pinning con OkHttp\nval certificatePinner = CertificatePinner.Builder()\n  .add(\"api.example.com\", \"sha256/HASH_DEL_CERTIFICADO=\")\n  .build()\n\nval client = OkHttpClient.Builder()\n  .certificatePinner(certificatePinner)\n  .build()"
            },
            "reactnative": {
                "vulnerable": "// ❌ Solicitud HTTP sin validación\nfetch('http://api.example.com/data')\n  .then(response => response.json())\n\n// ❌ Configuración insegura en AndroidManifest.xml e Info.plist\n// ... (como se mostró en los ejemplos anteriores)",
                "secure": "// ✅ Implementación de Certificate Pinning\nimport { fetch as fetchWithPinning } from 'react-native-ssl-pinning';\n\n// ✅ Función para realizar solicitudes seguras\nasync function secureApiRequest(endpoint, options = {}) {\n  return fetchWithPinning(\n    \`https://api.example.com/\${endpoint}\`,\n    {\n      // ... opciones de la solicitud ...\n      sslPinning: {\n        certs: ['cert1', 'cert2'] // Certificados en assets\n      }\n    }\n  );\n}"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Envío de datos sensibles sin cifrado adicional\nfunc sendPaymentInfo(cardNumber: String, cvv: String, expiry: String) {\n  let paymentData: [String: Any] = [\n    \"cardNumber\": cardNumber, // ❌ Datos sensibles en texto plano\n    \"cvv\": cvv,\n    \"expiry\": expiry\n  ]\n  \n  // ❌ Aunque use HTTPS, los datos van en texto plano en el cuerpo\n  apiService.processPayment(paymentData)\n}",
                "secure": "// ✅ Cifrado adicional de datos sensibles (end-to-end encryption)\nfunc sendPaymentInfo(cardNumber: String, cvv: String, expiry: String) {\n  // ✅ Obtener clave pública del servidor\n  getServerPublicKey { publicKey in\n    // ✅ Añadir timestamp y nonce para prevenir ataques de replay\n    let paymentData: [String: Any] = [\n      \"cardNumber\": cardNumber,\n      \"cvv\": cvv,\n      \"expiry\": expiry,\n      \"timestamp\": Int(Date().timeIntervalSince1970 * 1000),\n      \"nonce\": UUID().uuidString\n    ]\n    \n    // ✅ Cifrar datos con la clave pública del servidor\n    let encryptedData = encryptWithRsa(data: paymentData, publicKey: publicKey)\n    \n    // ✅ Enviar solo datos cifrados\n    apiService.processEncryptedPayment(encryptedData)\n  }\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Envío de datos sensibles sin cifrado adicional\nfun sendPaymentInfo(cardNumber: String, cvv: String, expiry: String) {\n  val paymentData = JSONObject().apply {\n    put(\"cardNumber\", cardNumber) // ❌ Datos sensibles en texto plano\n    put(\"cvv\", cvv)\n    put(\"expiry\", expiry)\n  }\n  \n  // ❌ Aunque use HTTPS, los datos van en texto plano en el cuerpo\n  apiService.processPayment(paymentData)\n}",
                "secure": "// ✅ Cifrado adicional de datos sensibles (end-to-end encryption)\nfun sendPaymentInfo(cardNumber: String, cvv: String, expiry: String) {\n  // ✅ Obtener clave pública del servidor\n  val serverPublicKey = getServerPublicKey()\n  \n  // ✅ Añadir timestamp y nonce para prevenir ataques de replay\n  val paymentData = JSONObject().apply {\n    put(\"cardNumber\", cardNumber)\n    put(\"cvv\", cvv)\n    put(\"expiry\", expiry)\n    put(\"timestamp\", System.currentTimeMillis())\n    put(\"nonce\", UUID.randomUUID().toString())\n  }\n  \n  // ✅ Cifrar datos con la clave pública del servidor\n  val encryptedData = encryptWithRsa(paymentData.toString(), serverPublicKey)\n  \n  // ✅ Enviar solo datos cifrados\n  apiService.processEncryptedPayment(encryptedData)\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Envío de datos sensibles sin cifrado adicional\nfunction sendPaymentInfo(cardNumber, cvv, expiry) {\n  const paymentData = {\n    cardNumber, // ❌ Datos sensibles en texto plano\n    cvv,\n    expiry\n  };\n  \n  // ❌ Aunque use HTTPS, los datos van en texto plano en el cuerpo\n  fetch('https://api.example.com/payment', {\n    method: 'POST',\n    body: JSON.stringify(paymentData)\n  });\n}",
                "secure": "// ✅ Cifrado adicional de datos sensibles (end-to-end encryption)\nasync function sendPaymentInfo(cardNumber, cvv, expiry) {\n  // ✅ Obtener clave pública del servidor\n  const publicKey = await getServerPublicKey();\n  \n  // ✅ Añadir timestamp y nonce para prevenir ataques de replay\n  const paymentData = {\n    cardNumber,\n    cvv,\n    expiry,\n    timestamp: Date.now(),\n    nonce: Math.random().toString(36).substring(2)\n  };\n  \n  // ✅ Cifrar datos con la clave pública del servidor\n  const encryptedData = await RSA.encrypt(JSON.stringify(paymentData), publicKey);\n  \n  // ✅ Enviar solo datos cifrados\n  fetch('https://api.example.com/payment', {\n    method: 'POST',\n    body: JSON.stringify({ encryptedPayment: encryptedData })\n  });\n}"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// Transmisión de datos sensibles en texto plano sin encriptar\nlet json = [\"card\": \"1234-5678-9876-5432\", \"cvv\": \"123\"]\nrequest.httpBody = try? JSONSerialization.data(withJSONObject: json)",
                "secure": "// Encriptación del payload antes de transmitir\nlet encrypted = encryptPayload(json)\nrequest.httpBody = encrypted"
            },
            "kotlin": {
                "vulnerable": "// ❌ Falta de validación de respuestas del servidor\nsuspend fun getUserProfile(userId: String): UserProfile {\n  val response = apiService.getUserProfile(userId)\n  \n  // ❌ No se valida la respuesta ni se manejan errores adecuadamente\n  val userProfile = response.body()\n  \n  // ❌ Se asume que la respuesta es válida y contiene datos\n  return userProfile!!\n}",
                "secure": "// ✅ Validación adecuada de respuestas del servidor\nsuspend fun getUserProfile(userId: String): Result<UserProfile> {\n  return try {\n    val response = apiService.getUserProfile(userId)\n    \n    // ✅ Verificar código de respuesta HTTP\n    if (!response.isSuccessful) {\n      return Result.failure(HttpException(response.code(), response.message()))\n    }\n    \n    // ✅ Verificar que el cuerpo de la respuesta no sea nulo\n    val userProfile = response.body() ?: return Result.failure(\n      ApiException(\"Respuesta vacía del servidor\")\n    )\n    \n    // ✅ Verificar firma digital de la respuesta (si está disponible)\n    val signature = response.headers()[\"X-Signature\"]\n    if (signature != null && !verifySignature(userProfile, signature)) {\n      return Result.failure(SecurityException(\"Firma inválida\"))\n    }\n    \n    // ✅ Validar estructura y contenido de la respuesta\n    validateUserProfile(userProfile)\n    \n    Result.success(userProfile)\n  } catch (e: Exception) {\n    Result.failure(e)\n  }\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Falta de validación de respuestas del servidor\nfunc getUserProfile(userId: String, completion: @escaping (UserProfile?) -> Void) {\n  apiService.getUserProfile(userId) { data, response, error in\n    guard let data = data else {\n      completion(nil)\n      return\n    }\n    \n    // ❌ No se valida la respuesta HTTP ni se manejan errores adecuadamente\n    do {\n      let userProfile = try JSONDecoder().decode(UserProfile.self, from: data)\n      completion(userProfile)\n    } catch {\n      completion(nil)\n    }\n  }\n}",
                "secure": "// ✅ Validación adecuada de respuestas del servidor\nfunc getUserProfile(userId: String, completion: @escaping (Result<UserProfile, Error>) -> Void) {\n  apiService.getUserProfile(userId) { data, response, error in\n    // ✅ Verificar errores de red\n    if let error = error {\n      completion(.failure(error))\n      return\n    }\n    \n    // ✅ Verificar código de respuesta HTTP\n    guard let httpResponse = response as? HTTPURLResponse,\n          (200...299).contains(httpResponse.statusCode) else {\n      completion(.failure(APIError.httpError))\n      return\n    }\n    \n    // ✅ Verificar que hay datos en la respuesta\n    guard let data = data, !data.isEmpty else {\n      completion(.failure(APIError.emptyResponse))\n      return\n    }\n    \n    // ✅ Verificar firma digital (si está disponible)\n    if let signature = httpResponse.value(forHTTPHeaderField: \"X-Signature\"),\n       !self.verifySignature(data: data, signature: signature) {\n      completion(.failure(APIError.invalidSignature))\n      return\n    }\n    \n    // ✅ Decodificar y validar respuesta\n    do {\n      let userProfile = try JSONDecoder().decode(UserProfile.self, from: data)\n      try self.validateUserProfile(userProfile)\n      completion(.success(userProfile))\n    } catch {\n      completion(.failure(error))\n    }\n  }\n}"
            }
        }

    },
    "risk6": {
        "title": "Controles de Privacidad Inadecuados",
        "attackVector": "Acceso o compartición de datos personales sin consentimiento explícito.",
        "weakness": "Recolección excesiva de información o sin justificación técnica.",
        "impact": "Compromete la privacidad del usuario y viola regulaciones legales.",
        "mitigationStrategies": [
            "Solicitar permisos solo cuando sean necesarios.",
            "Aplicar el principio de minimización de datos.",
            "Incluir avisos de privacidad claros y comprensibles."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Acceso innecesario a la ubicación sin justificación\nCLLocationManager().requestWhenInUseAuthorization()",
                "secure": "// ✅ Solicita permiso solo cuando se necesita y con justificación\n// Mostrar mensaje explicativo al usuario antes de solicitar permiso\nlet locationManager = CLLocationManager()\nlocationManager.requestWhenInUseAuthorization() // solo si es estrictamente necesario"
            },
            "kotlin": {
                "vulnerable": "// ❌ Solicita permiso de ubicación sin justificación al iniciar la app\nActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)",
                "secure": "// ✅ Solicita el permiso en el momento de uso y con aviso previo\nif (shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_FINE_LOCATION)) {\n  // Mostrar mensaje explicativo al usuario\n}\nrequestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)"
            },
            "reactnative": {
                "vulnerable": "// ❌ Solicita acceso a la ubicación directamente sin verificar necesidad\nPermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION)",
                "secure": "// ✅ Solicita solo si la funcionalidad lo requiere y se explica al usuario\nif (featureNeedsLocation) {\n  Alert.alert(\"Necesitamos tu ubicación para mostrar tiendas cercanas\")\n  PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION)\n}"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ Registro de datos sensibles en logs\nprint(\"Token de acceso: \\(token)\")",
                "secure": "// ✅ Nunca registrar datos sensibles en logs\n// print(\"Token recibido\") // sin mostrar su valor"
            },
            "kotlin": {
                "vulnerable": "// ❌ Registro de información sensible\nLog.d(\"DEBUG\", \"Access Token: \$token\")",
                "secure": "// ✅ Evitar mostrar información sensible en logs\nLog.d(\"DEBUG\", \"Token recibido correctamente\")"
            },
            "reactnative": {
                "vulnerable": "// ❌ Log de información sensible en consola\nconsole.log(\"User password is: \", password)",
                "secure": "// ✅ No mostrar información privada\nconsole.log(\"Login completado\")"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ Almacenamiento de datos sensibles sin cifrar\nUserDefaults.standard.set(\"123456\", forKey: \"user_password\")",
                "secure": "// ✅ Uso del llavero (Keychain) para almacenar información sensible\n// Usar KeychainWrapper o librerías similares\nKeychainWrapper.standard.set(\"123456\", forKey: \"user_password\")"
            },
            "kotlin": {
                "vulnerable": "// ❌ Guardar datos sensibles sin cifrado en SharedPreferences\nval prefs = getSharedPreferences(\"prefs\", Context.MODE_PRIVATE)\nprefs.edit().putString(\"password\", \"123456\").apply()",
                "secure": "// ✅ Uso de EncryptedSharedPreferences\nval masterKey = MasterKey.Builder(this)\n  .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()\nval securePrefs = EncryptedSharedPreferences.create(\n  this, \"secure_prefs\", masterKey,\n  EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n  EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nsecurePrefs.edit().putString(\"password\", \"123456\").apply()"
            },
            "reactnative": {
                "vulnerable": "// ❌ Guardar datos sensibles en AsyncStorage\nawait AsyncStorage.setItem('password', '123456')",
                "secure": "// ✅ Uso de librerías seguras como react-native-keychain\nimport * as Keychain from 'react-native-keychain';\nawait Keychain.setGenericPassword('user', '123456')"
            }
        }
    },
    "risk7": {
        "title": "Protecciones Binarias Insuficientes",
        "attackVector": "Análisis estático del binario o ingeniería inversa por parte del atacante.",
        "weakness": "Código fácilmente descompilable o sin protección contra modificaciones.",
        "impact": "Permite la creación de versiones maliciosas o piratería de la app.",
        "mitigationStrategies": [
            "Ofuscar el código antes de su compilación.",
            "Usar detección de debugging y hooking.",
            "Aplicar firmas digitales a los binarios."
        ],
        "example1": {
            "swift": {
                "vulnerable": "// ❌ Código compilado en modo debug con logs visibles\nprint(\"[DEBUG] Usuario autenticado\")",
                "secure": "// ✅ Compilar en modo release y controlar logs\n#if DEBUG\nprint(\"[DEBUG] Usuario autenticado\")\n#endif"
            },
            "kotlin": {
                "vulnerable": "// ❌ Logging en producción\nLog.d(\"DEBUG\", \"Token: \$token\")",
                "secure": "// ✅ Evitar logs en producción\nif (BuildConfig.DEBUG) {\n  Log.d(\"DEBUG\", \"Token presente\")\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Logging sin restricción\nconsole.log(\"Credenciales: \", credentials)",
                "secure": "// ✅ Eliminar logs en producción\nif (__DEV__) {\n  console.log(\"Login exitoso\")\n}"
            }
        },
        "example2": {
            "swift": {
                "vulnerable": "// ❌ No se verifica integridad del binario\nfunc appLaunched() {\n  print(\"App iniciada\")\n}",
                "secure": "// ✅ Verificación básica de integridad del binario\nimport CryptoKit\nfunc verifyBinary() -> Bool {\n  let expectedHash = \"abc123...\" // Hash esperado del ejecutable\n  guard let path = Bundle.main.executablePath,\n     let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {\n       return false\n     }\n\n  let hash = SHA256.hash(data: data)\n\n  return hash.description == expectedHash\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ APK no validado\nfun startApp() {\n  println(\"App iniciada\")\n}",
                "secure": "// ✅ Validación de firma del APK\nval info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)\nval signatures = info.signingInfo.apkContentsSigners\nval valid = signatures.any { \n  it.toCharsString().contains(\"MIIBIjAN...\") // Parte del certificado esperado \n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ Sin verificación del código JS\nAppRegistry.registerComponent('App', () => App);",
                "secure": "// ✅ Verificar integridad del JS bundle\nimport { readFile } from 'react-native-fs';\nimport sha256 from 'crypto-js/sha256';\n\nconst bundlePath = '/path/to/index.android.bundle'; // o iOS path\nconst EXPECTED_HASH = 'd41d8cd98f00b204e9800998ecf8427e';\n\nreadFile(bundlePath).then(content => {\n  const hash = sha256(content).toString();\n  if (hash !== EXPECTED_HASH) {\n    Alert.alert(\"Integridad comprometida\");\n  }\n});"
            }
        },
        "example3": {
            "swift": {
                "vulnerable": "// ❌ No se detecta jailbreak\nfunc startApp() {\n  print(\"App sin verificación de seguridad\")\n}",
                "secure": "// ✅ Detección básica de jailbreak\nfunc isJailbroken() -> Bool {\n  let paths = [\"/Applications/Cydia.app\", \"/bin/bash\"]\n  return paths.contains { FileManager.default.fileExists(atPath: $0) }\n}"
            },
            "kotlin": {
                "vulnerable": "// ❌ Sin detección de root\nfun isSecure() = true",
                "secure": "// ✅ Detección básica de root\nfun isDeviceRooted(): Boolean {\n  val rootPaths = arrayOf(\"/system/app/Superuser.apk\", \"/system/xbin/su\")\n  return rootPaths.any { File(it).exists() }\n}"
            },
            "reactnative": {
                "vulnerable": "// ❌ No se verifica root/jailbreak\nconst startApp = () => {\n  console.log(\"App iniciada\")\n}",
                "secure": "// ✅ Uso de librería para detección de dispositivos comprometidos\nimport JailbreakDetector from 'react-native-jailbreak-root-detect';\nconst checkDevice = async () => {\n  const jailbroken = await JailbreakDetector.isJailBroken();\n  if (jailbroken) {\n    Alert.alert(\"❌ Dispositivo comprometido detectado\");\n  }\n};"
            }
        }

    },
    "risk8": {
        "title": "Configuración de Seguridad Incorrecta",
        "attackVector": "Explotación de configuraciones por defecto o mal aplicadas en el entorno de la app.",
        "weakness": "Permisos mal definidos, errores de despliegue o configuración por defecto.",
        "impact": "Puede abrir puertas a accesos no autorizados o filtraciones de información.",
        "mitigationStrategies": [
            "Revisar y limitar permisos solicitados.",
            "Eliminar configuraciones y archivos de prueba en producción.",
            "Desactivar funcionalidades de debugging en versiones finales."
        ],
        "example1": {
            "swift": {
                "vulnerable": "/* ❌ Info.plist contiene:\n<key>NSLocationAlwaysUsageDescription</key>\n<string>Necesitamos tu ubicación siempre</string>\nIncluso si no se necesita la ubicación en segundo plano */\nprint(\"App iniciada\")",
                "secure": "/* ✅ Info.plist contiene solo lo necesario:\n<key>NSLocationWhenInUseUsageDescription</key>\n<string>Necesitamos tu ubicación mientras usas la app</string> */\nprint(\"App iniciada con permisos limitados\")"
            },
            "kotlin": {
                "vulnerable": "/* ❌ AndroidManifest.xml:\n<uses-permission android:name=\"android.permission.READ_SMS\" />\nNo se usa este permiso en la app */\nfun main() {\n    println(\"App iniciada con permisos innecesarios\")\n}",
                "secure": "/* ✅ AndroidManifest.xml:\n<uses-permission android:name=\"android.permission.CAMERA\" />\nSolo se solicita lo que realmente se necesita */\nfun main() {\n    println(\"App iniciada con permisos mínimos\")\n}"
            },
            "reactnative": {
                "vulnerable": "import { PermissionsAndroid } from 'react-native';\n\n// ❌ Solicita permiso de contactos innecesariamente\nPermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.READ_CONTACTS);\nconsole.log(\"❌ Permiso solicitado sin uso\")",
                "secure": "import { PermissionsAndroid } from 'react-native';\n\n// ✅ Solo solicita permiso de ubicación si se requiere\nPermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION);\nconsole.log(\"✅ Permiso solicitado justificado\")"
            }
        },

        "example2": {
            "swift": {
                "vulnerable": "import Foundation\n\n// ❌ Endpoint apuntando a entorno de testing\nlet url = URL(string: \"https://staging.api.miapp.com/data\")!\nprint(\"❌ Conectando a entorno de prueba en producción\")",
                "secure": "import Foundation\n\n// ✅ Endpoint correcto para producción\nlet url = URL(string: \"https://api.miapp.com/data\")!\nprint(\"✅ Conectando a entorno de producción\")"
            },
            "kotlin": {
                "vulnerable": "val baseUrl = \"https://dev.api.miapp.com\" // ❌ entorno de desarrollo\nprintln(\"❌ Usando entorno de prueba\")",
                "secure": "val baseUrl = \"https://api.miapp.com\" // ✅ entorno de producción\nprintln(\"✅ Entorno correcto en producción\")"
            },
            "reactnative": {
                "vulnerable": "const BASE_URL = 'https://dev.api.miapp.com'; // ❌ URL de pruebas\nfetch(BASE_URL + '/user');",
                "secure": "const BASE_URL = 'https://api.miapp.com'; // ✅ URL de producción\nfetch(BASE_URL + '/user');"
            }
        },

        "example3": {
            "swift": {
                "vulnerable": "import UIKit\n\nprint(\"❌ Debug activo: info sensible visible\")\n",
                "secure": "import UIKit\n\n#if DEBUG\nprint(\"Solo visible durante desarrollo\")\n#else\nprint(\"✅ Modo producción sin logs sensibles\")\n#endif"
            },
            "kotlin": {
                "vulnerable": "println(\"❌ Log de debugging activo en producción\")",
                "secure": "if (!BuildConfig.DEBUG) {\n    println(\"✅ Producción sin logs de debug\")\n}"
            },
            "reactnative": {
                "vulnerable": "console.log(\"❌ Debug activo: muestra tokens y errores sensibles\");\n",
                "secure": "if (__DEV__) {\n  console.log(\"✅ Solo logs en modo desarrollo\");\n}"
            }
        }
    },
    "risk9": {
        "title": "Almacenamiento de Datos Inseguro",
        "attackVector": "Acceso físico al dispositivo o uso de malware para leer datos locales.",
        "weakness": "Guardar datos sensibles sin cifrado o en ubicaciones accesibles.",
        "impact": "Permite la extracción de información privada en caso de pérdida o robo del equipo.",
        "mitigationStrategies": [
            "Cifrar todos los datos sensibles almacenados localmente.",
            "Utilizar mecanismos de almacenamiento seguros del sistema operativo.",
            "Evitar almacenar información sensible innecesaria."
        ],
        "example1": {
            "swift": {
                "vulnerable": "let password = \"usuario123\"\nUserDefaults.standard.set(password, forKey: \"user_password\") // ❌ Guardado sin cifrado",
                "secure": "import Security\n\n// ✅ Uso de Keychain\nlet password = \"usuario123\"\nlet query: [String: Any] = [\n    kSecClass as String: kSecClassGenericPassword,\n    kSecAttrAccount as String: \"user_password\",\n    kSecValueData as String: password.data(using: .utf8)!\n]\nSecItemAdd(query as CFDictionary, nil)"
            },
            "kotlin": {
                "vulnerable": "val prefs = context.getSharedPreferences(\"prefs\", Context.MODE_PRIVATE)\nprefs.edit().putString(\"user_password\", \"usuario123\").apply() // ❌ Guardado sin cifrado",
                "secure": "val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()\nval securePrefs = EncryptedSharedPreferences.create(\n  context, \"secure_prefs\", masterKey,\n  EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n  EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nsecurePrefs.edit().putString(\"user_password\", \"usuario123\").apply() // ✅ Almacenamiento cifrado"
            },
            "reactnative": {
                "vulnerable": "import AsyncStorage from '@react-native-async-storage/async-storage';\nawait AsyncStorage.setItem('user_password', 'usuario123'); // ❌ Guardado sin cifrado",
                "secure": "import * as Keychain from 'react-native-keychain';\nawait Keychain.setGenericPassword('user', 'usuario123'); // ✅ Uso de almacenamiento seguro"
            }
        },

        "example2": {
            "swift": {
                "vulnerable": "let token = \"jwt-token-aqui\"\nUserDefaults.standard.set(token, forKey: \"auth_token\") // ❌ Token innecesariamente persistente",
                "secure": "let token = \"jwt-token-aqui\"\n// ✅ Uso solo en memoria o almacenamiento efímero\ndispatchQueue.async {\n    let sessionToken = token // Solo en RAM mientras dura la sesión\n}"
            },
            "kotlin": {
                "vulnerable": "val token = \"jwt-token-aqui\"\nval prefs = context.getSharedPreferences(\"prefs\", Context.MODE_PRIVATE)\nprefs.edit().putString(\"auth_token\", token).apply() // ❌ Persistencia innecesaria",
                "secure": "val token = \"jwt-token-aqui\"\n// ✅ Mantener en memoria mientras dure la sesión\nval sessionManager = SessionManager()\nsessionManager.setToken(token)"
            },
            "reactnative": {
                "vulnerable": "import AsyncStorage from '@react-native-async-storage/async-storage';\nawait AsyncStorage.setItem('auth_token', 'jwt-token-aqui'); // ❌ Persistencia innecesaria",
                "secure": "// ✅ Mantener token solo en estado de la app o contexto\nconst [token, setToken] = useState('jwt-token-aqui');"
            }
        },

        "example3": {
            "swift": {
                "vulnerable": "let data = \"nombre: Juan, DNI: 12345678\"\nlet path = FileManager.default.temporaryDirectory.appendingPathComponent(\"datos.txt\")\ntry? data.write(to: path, atomically: true, encoding: .utf8) // ❌ Datos sin cifrar",
                "secure": "import CryptoKit\n\nlet data = \"nombre: Juan, DNI: 12345678\".data(using: .utf8)!\nlet key = SymmetricKey(size: .bits256)\nlet sealedBox = try! AES.GCM.seal(data, using: key)\nlet encryptedData = sealedBox.combined!\nlet path = FileManager.default.temporaryDirectory.appendingPathComponent(\"datos.enc\")\ntry? encryptedData.write(to: path) // ✅ Datos cifrados antes de guardar"
            },
            "kotlin": {
                "vulnerable": "val file = File(context.filesDir, \"datos.txt\")\nfile.writeText(\"nombre: Juan, DNI: 12345678\") // ❌ Datos sensibles sin cifrar",
                "secure": "val plainText = \"nombre: Juan, DNI: 12345678\"\nval secretKey = SecretKeySpec(keyBytes, \"AES\")\nval cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")\ncipher.init(Cipher.ENCRYPT_MODE, secretKey)\nval encrypted = cipher.doFinal(plainText.toByteArray())\nFile(context.filesDir, \"datos.enc\").writeBytes(encrypted) // ✅ Cifrado antes de guardar"
            },
            "reactnative": {
                "vulnerable": "import RNFS from 'react-native-fs';\nconst path = RNFS.DocumentDirectoryPath + '/datos.txt';\nawait RNFS.writeFile(path, 'nombre: Juan, DNI: 12345678', 'utf8'); // ❌ Guardado sin cifrado",
                "secure": "import CryptoJS from 'crypto-js';\nconst encrypted = CryptoJS.AES.encrypt('nombre: Juan, DNI: 12345678', 'clave_segura').toString();\nconst path = RNFS.DocumentDirectoryPath + '/datos.enc';\nawait RNFS.writeFile(path, encrypted, 'utf8'); // ✅ Guardado con cifrado AES"
            }
        }
    },
    "risk10": {
        "title": "Criptografía Insuficiente",
        "attackVector": "Uso de algoritmos débiles o implementación incorrecta de funciones criptográficas.",
        "weakness": "Uso de claves mal generadas, algoritmos obsoletos o bibliotecas caseras.",
        "impact": "Permite a un atacante descifrar información o falsificar datos.",
        "mitigationStrategies": [
            "Utilizar algoritmos criptográficos aprobados por estándares actuales.",
            "Nunca implementar criptografía propia.",
            "Actualizar regularmente las bibliotecas criptográficas utilizadas."
        ],
        "example1": {
            "swift": {
                "vulnerable": "import CommonCrypto\n\n// ❌ Uso de MD5 (inseguro)\nlet input = \"password\"\nlet data = input.data(using: .utf8)!\nvar digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))\ndata.withUnsafeBytes {\n    _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest)\n}\nprint(\"❌ Hash MD5: \\(digest.map { String(format: \"%02x\", $0) }.joined())\")",
                "secure": "import CryptoKit\n\n// ✅ Uso de SHA256 (más seguro)\nlet input = \"password\"\nlet digest = SHA256.hash(data: input.data(using: .utf8)!)\nprint(\"✅ Hash SHA256: \\(digest.map { String(format: \"%02x\", $0) }.joined())\")"
            },
            "kotlin": {
                "vulnerable": "import java.security.MessageDigest\n\n// ❌ Uso de MD5\nval input = \"password\"\nval md = MessageDigest.getInstance(\"MD5\")\nval digest = md.digest(input.toByteArray())\nprintln(\"❌ Hash MD5: ${digest.joinToString(\"\") { \"%02x\".format(it) }}\")",
                "secure": "import java.security.MessageDigest\n\n// ✅ Uso de SHA-256\nval input = \"password\"\nval md = MessageDigest.getInstance(\"SHA-256\")\nval digest = md.digest(input.toByteArray())\nprintln(\"✅ Hash SHA256: ${digest.joinToString(\"\") { \"%02x\".format(it) }}\")"
            },
            "reactnative": {
                "vulnerable": "import md5 from 'md5';\n\n// ❌ Uso de MD5\nconst hash = md5('password');\nconsole.log(`❌ Hash MD5: ${hash}`);",
                "secure": "import { sha256 } from 'js-sha256';\n\n// ✅ Uso de SHA256\nconst hash = sha256('password');\nconsole.log(`✅ Hash SHA256: ${hash}`);"
            }
        },

        "example2": {
            "swift": {
                "vulnerable": "let apiKey = \"123456-SECRET\" // ❌ Clave expuesta en código\nprint(\"❌ Usando clave en código fuente: \\(apiKey)\")",
                "secure": "let apiKey = Bundle.main.object(forInfoDictionaryKey: \"API_KEY\") as? String // ✅ Recuperado de entorno seguro\nprint(\"✅ Clave cargada desde entorno seguro\")"
            },
            "kotlin": {
                "vulnerable": "val secretKey = \"HARDCODED_SECRET\" // ❌ Clave embebida\nprintln(\"❌ Usando clave embebida: $secretKey\")",
                "secure": "val secretKey = BuildConfig.API_SECRET // ✅ Clave configurada por buildConfigField\nprintln(\"✅ Clave segura desde configuración\")"
            },
            "reactnative": {
                "vulnerable": "const secret = 'HARDCODED_SECRET'; // ❌ Clave expuesta\nconsole.log(`❌ Clave expuesta: ${secret}`);",
                "secure": "import Config from 'react-native-config';\n\nconst secret = Config.API_SECRET; // ✅ Clave desde .env\nconsole.log(`✅ Clave segura: ${secret}`);"
            }
        },

        "example3": {
            "swift": {
                "vulnerable": "UserDefaults.standard.set(\"token123\", forKey: \"auth_token\") // ❌ Guardado inseguro\nprint(\"❌ Token guardado en UserDefaults\")",
                "secure": "import Security\n\n// ✅ Uso de Keychain\nlet query: [String: Any] = [\n    kSecClass as String: kSecClassGenericPassword,\n    kSecAttrAccount as String: \"auth_token\",\n    kSecValueData as String: \"token123\".data(using: .utf8)!\n]\nSecItemAdd(query as CFDictionary, nil)\nprint(\"✅ Token guardado en Keychain\")"
            },
            "kotlin": {
                "vulnerable": "val sharedPref = context.getSharedPreferences(\"prefs\", Context.MODE_PRIVATE)\nsharedPref.edit().putString(\"auth_token\", \"token123\").apply() // ❌ Guardado inseguro\nprintln(\"❌ Token en SharedPreferences\")",
                "secure": "val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()\nval encPrefs = EncryptedSharedPreferences.create(\n    context, \"secure_prefs\", masterKey,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)\nencPrefs.edit().putString(\"auth_token\", \"token123\").apply()\nprintln(\"✅ Token cifrado en almacenamiento seguro\")"
            },
            "reactnative": {
                "vulnerable": "import AsyncStorage from '@react-native-async-storage/async-storage';\n\nawait AsyncStorage.setItem('auth_token', 'token123'); // ❌ Almacenamiento inseguro\nconsole.log('❌ Token guardado sin cifrado');",
                "secure": "import * as Keychain from 'react-native-keychain';\n\nawait Keychain.setGenericPassword('user', 'token123'); // ✅ Almacenado de forma segura\nconsole.log('✅ Token guardado en Keychain');"
            }
        }
    }
}

export default movilData