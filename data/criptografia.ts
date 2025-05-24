// Estructura de datos para ejemplos de código de criptografía
export interface CodeExample {
    language: string
    code: string
    caption?: string
    isVulnerable?: boolean
}

export interface CryptoSection {
    title: string
    iconName: string,
    subsections: {
        [key: string]: {
            title: string
            description: string
            characteristics?: {
                left: {
                    title: string
                    items: string[]
                }
                right: {
                    title: string
                    items: string[]
                }
            }
            examples?: CodeExample[]
            securityPoints?: string[]
        }
    }
}

const criptografiaData: { [key: string]: CryptoSection } = {
    fundamentos: {
        title: "Fundamentos de Criptografía",
        iconName: "shield",
        subsections: {
            cifradoSimetrico: {
                title: "Cifrado Simétrico",
                description:
                    "El cifrado simétrico utiliza la misma clave para cifrar y descifrar datos. Es rápido y eficiente para grandes volúmenes de información, pero presenta el desafío de compartir la clave de forma segura.",
                characteristics: {
                    left: {
                        title: "Algoritmos comunes",
                        items: [
                            "AES (Advanced Encryption Standard) - 128, 192, 256 bits",
                            "ChaCha20 - Alternativa moderna a AES",
                            "3DES (Triple DES) - Menos usado actualmente",
                        ],
                    },
                    right: {
                        title: "Características",
                        items: [
                            "Alta velocidad de procesamiento",
                            "Eficiente para grandes volúmenes de datos",
                            "Requiere un canal seguro para intercambiar claves",
                        ],
                    },
                },
                examples: [
                    {
                        language: "javascript",
                        code: `const crypto = require('crypto');

// Función para cifrar datos con AES-256-GCM
function encryptData(plaintext, key) {
  // Generar un IV aleatorio
  const iv = crypto.randomBytes(12);
  
  // Crear cipher con AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  // Cifrar los datos
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  // Obtener el tag de autenticación
  const authTag = cipher.getAuthTag();
  
  // Devolver IV, datos cifrados y tag de autenticación
  return {
    iv: iv.toString('base64'),
    encryptedData: encrypted,
    authTag: authTag.toString('base64')
  };
}

// Función para descifrar datos con AES-256-GCM
function decryptData(encryptedObj, key) {
  // Convertir IV y authTag de base64 a Buffer
  const iv = Buffer.from(encryptedObj.iv, 'base64');
  const authTag = Buffer.from(encryptedObj.authTag, 'base64');
  
  // Crear decipher
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  
  // Establecer el tag de autenticación
  decipher.setAuthTag(authTag);
  
  // Descifrar los datos
  let decrypted = decipher.update(encryptedObj.encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Ejemplo de uso
const key = crypto.randomBytes(32); // Clave de 256 bits
const plaintext = 'Información confidencial que necesita protección';

const encrypted = encryptData(plaintext, key);
console.log('Datos cifrados:', encrypted);

const decrypted = decryptData(encrypted, key);
console.log('Datos descifrados:', decrypted);`,
                    },
                ],
                securityPoints: [
                    "<strong>Nunca reutilizar</strong> la misma combinación de clave e IV (vector de inicialización)",
                    "Utilizar modos de operación seguros como <strong>GCM</strong> o <strong>CBC</strong> con HMAC",
                    "Generar claves con suficiente <strong>entropía</strong> (usando generadores de números aleatorios criptográficamente seguros)",
                    "Proteger las claves en reposo usando <strong>almacenamiento seguro de claves</strong>",
                ],
            },
            cifradoAsimetrico: {
                title: "Cifrado Asimétrico",
                description:
                    "El cifrado asimétrico utiliza un par de claves matemáticamente relacionadas: una pública para cifrar y una privada para descifrar. Resuelve el problema de intercambio de claves, pero es computacionalmente más costoso que el cifrado simétrico.",
                characteristics: {
                    left: {
                        title: "Algoritmos comunes",
                        items: ["RSA (Rivest-Shamir-Adleman)", "ECC (Criptografía de Curva Elíptica)", "ElGamal"],
                    },
                    right: {
                        title: "Aplicaciones",
                        items: [
                            "Firmas digitales",
                            "Intercambio seguro de claves",
                            "Certificados digitales",
                            "Infraestructura de clave pública (PKI)",
                        ],
                    },
                },
                examples: [
                    {
                        language: "python",
                        code: `from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generar par de claves RSA
def generate_rsa_keys():
    # Generar clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Derivar clave pública
    public_key = private_key.public_key()
    
    # Serializar clave privada en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serializar clave pública en formato PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem, private_key, public_key

# Cifrar datos con clave pública
def encrypt_with_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Descifrar datos con clave privada
def decrypt_with_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# Ejemplo de uso
private_pem, public_pem, private_key, public_key = generate_rsa_keys()

# Mensaje a cifrar
message = "Mensaje confidencial para cifrado asimétrico"

# Cifrar con clave pública
encrypted = encrypt_with_rsa(public_key, message)
print(f"Mensaje cifrado: {encrypted.hex()}")

# Descifrar con clave privada
decrypted = decrypt_with_rsa(private_key, encrypted)
print(f"Mensaje descifrado: {decrypted}")`,
                    },
                ],
                securityPoints: [
                    "Usar <strong>tamaños de clave adecuados</strong>: mínimo 2048 bits para RSA, 256 bits para ECC",
                    "Implementar <strong>padding seguro</strong> como OAEP para RSA",
                    "<strong>Proteger las claves privadas</strong> con medidas adicionales de seguridad",
                    "Utilizar <strong>bibliotecas criptográficas probadas</strong> en lugar de implementaciones propias",
                ],
            },
            funcionesHash: {
                title: "Funciones Hash Criptográficas",
                description:
                    "Las funciones hash criptográficas transforman datos de entrada de cualquier tamaño en una cadena de salida de longitud fija. Son fundamentales para verificar la integridad de los datos y almacenar contraseñas de forma segura.",
                characteristics: {
                    left: {
                        title: "Algoritmos comunes",
                        items: [
                            "SHA-256, SHA-384, SHA-512 (familia SHA-2)",
                            "SHA3-256, SHA3-512 (familia SHA-3)",
                            "BLAKE2, BLAKE3",
                            '<span class="line-through text-red-400">MD5, SHA-1</span> (obsoletos, no usar)',
                        ],
                    },
                    right: {
                        title: "Propiedades",
                        items: [
                            "<strong>Unidireccionalidad</strong>: imposible recuperar la entrada desde el hash",
                            "<strong>Determinismo</strong>: la misma entrada siempre produce el mismo hash",
                            "<strong>Efecto avalancha</strong>: pequeños cambios en la entrada producen hashes completamente diferentes",
                            "<strong>Resistencia a colisiones</strong>: difícil encontrar dos entradas con el mismo hash",
                        ],
                    },
                },
                examples: [
                    {
                        language: "javascript",
                        code: `const argon2 = require('argon2');

// Función para hashear una contraseña con Argon2id
async function hashPassword(password) {
  try {
    // Configuración recomendada para Argon2id
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,      // Variante más segura
      memoryCost: 65536,          // 64 MiB en KB
      timeCost: 3,                // Número de iteraciones
      parallelism: 4,             // Grado de paralelismo
      hashLength: 32,             // Longitud del hash en bytes
    });
    
    return hash;
  } catch (error) {
    console.error('Error al hashear la contraseña:', error);
    throw error;
  }
}

// Función para verificar una contraseña contra un hash almacenado
async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    console.error('Error al verificar la contraseña:', error);
    return false;
  }
}

// Ejemplo de uso
async function main() {
  const password = 'Contraseña.Segura.123';
  
  // Hashear la contraseña para almacenarla
  const hash = await hashPassword(password);
  console.log('Hash generado:', hash);
  
  // Verificar contraseña correcta
  const isValid = await verifyPassword(hash, password);
  console.log('¿Contraseña válida?', isValid); // true
  
  // Verificar contraseña incorrecta
  const isInvalid = await verifyPassword(hash, 'ContraseñaIncorrecta');
  console.log('¿Contraseña incorrecta válida?', isInvalid); // false
}

main();`,
                    },
                ],
                securityPoints: [
                    "<strong>Nunca almacenar contraseñas en texto plano</strong> o con hashes simples (MD5, SHA-1)",
                    "Usar <strong>funciones de derivación de claves</strong> como Argon2, bcrypt o PBKDF2 para contraseñas",
                    "Añadir un <strong>salt único</strong> para cada contraseña (las funciones modernas lo hacen automáticamente)",
                    "Ajustar los <strong>factores de coste</strong> (tiempo, memoria) según las necesidades de seguridad",
                ],
            },
        },
    },
    protocolosCriptograficos: {
        title: "Protocolos Criptográficos",
        iconName: "globe",
        subsections: {
            TLSSSLyHTTPS: {
                title: "TLS/SSL y HTTPS",
                description: "TLS (Transport Layer Security) y su predecesor SSL (Secure Sockets Layer) son protocolos que proporcionan comunicaciones seguras en Internet. HTTPS es HTTP sobre TLS/SSL, asegurando que todas las comunicaciones entre el navegador y el servidor web estén cifradas.",
                characteristics: {
                    left: {
                        title: "Componentes clave",
                        items: [
                            "Certificados X.509",
                            "Intercambio de claves (RSA, DH, ECDHE)",
                            "Cifrado simétrico para datos (AES, ChaCha20)",
                            "Funciones hash para integridad (SHA-256, SHA-384)",
                        ]
                    },
                    right: {
                        title: "Beneficios",
                        items: [
                            "Confidencialidad de datos transmitidos",
                            "Integridad de datos",
                            "Autenticación del servidor (y opcionalmente del cliente)",
                            "Protección contra ataques de intermediario (MitM)"
                        ]
                    }
                },
                examples: [{
                    language: 'javascript',
                    code: `const https = require('https');\nconst fs = require('fs');\nconst express = require('express');\n\nconst app = express();\n\n// Middleware y rutas\napp.get('/', (req, res) => {\n  res.send('¡Servidor HTTPS seguro funcionando!');\n});\n\n// Opciones de TLS con configuración segura\nconst options = {\n  key: fs.readFileSync('ruta/a/clave-privada.key'),\n  cert: fs.readFileSync('ruta/a/certificado.crt'),\n  // Configuración moderna y segura de TLS\n  minVersion: 'TLSv1.2',\n  // Cifrados recomendados (orden de preferencia)\n  ciphers: [\n    'TLS_AES_256_GCM_SHA384',\n    'TLS_CHACHA20_POLY1305_SHA256',\n    'TLS_AES_128_GCM_SHA256',\n    'ECDHE-RSA-AES256-GCM-SHA384',\n    'ECDHE-RSA-AES128-GCM-SHA256',\n    'ECDHE-RSA-CHACHA20-POLY1305'\n  ].join(':'),\n  // Habilitar Perfect Forward Secrecy\n  honorCipherOrder: true,\n  // Opciones HSTS\n  maxAge: 31536000, // 1 año en segundos\n  includeSubDomains: true,\n  preload: true\n};\n\n// Crear servidor HTTPS\nconst server = https.createServer(options, app);\n\n// Iniciar servidor\nserver.listen(443, () => {\n  console.log('Servidor HTTPS ejecutándose en el puerto 443');\n});\n\n// Redirigir HTTP a HTTPS\nconst http = require('http');\nhttp.createServer((req, res) => {\n  res.writeHead(301, { 'Location': 'https://' + req.headers.host + req.url });\n  res.end();\n}).listen(80);`
                }],
                securityPoints: [
                    "Usar <strong>TLS 1.2 o superior</strong> (TLS 1.0 y 1.1 están obsoletos)",
                    "Configurar <strong>cifrados seguros</strong> y deshabilitar algoritmos débiles",
                    "Implementar <strong>HSTS</strong> (HTTP Strict Transport Security)",
                    "Utilizar <strong>certificados válidos</strong> de autoridades de certificación confiables",
                    "Configurar <strong>Perfect Forward Secrecy</strong> (PFS) para proteger datos pasados"
                ]
            },
            autorizacionAutenticacion: {
                title: "Autenticación y Autorización",
                description: "Los protocolos de autenticación y autorización permiten verificar la identidad de usuarios y sistemas, y determinar sus niveles de acceso. Estos protocolos son fundamentales para la seguridad de aplicaciones web y APIs.",
                characteristics: {
                    left: {
                        title: "Protocolos comunes",
                        items: [
                            "OAuth 2.0",
                            "OpenID Connect",
                            "SAML (Security Assertion Markup Language)",
                            "JWT (JSON Web Tokens)",
                        ]
                    },
                    right: {
                        title: "Componentes clave",
                        items: [
                            "Tokens de acceso y actualización",
                            "Firmas digitales",
                            "Flujos de autenticación",
                            "Gestión de sesiones"
                        ]
                    }
                },
                examples: [{
                    language: 'javascript',
                    code: `const jwt = require('jsonwebtoken');\nconst crypto = require('crypto');\n\n// Generar una clave secreta segura (en producción, almacenar de forma segura)\nconst generateSecretKey = () => {\n  return crypto.randomBytes(64).toString('hex');\n};\n\n// Clave secreta para firmar y verificar tokens\nconst secretKey = generateSecretKey();\n\n// Función para crear un token JWT\nfunction createToken(payload, options = {}) {\n  // Configuración predeterminada segura\n  const defaultOptions = {\n    expiresIn: '1h',        // Tiempo de expiración corto\n    algorithm: 'HS256',     // Algoritmo de firma\n    issuer: 'mi-aplicacion', // Emisor del token\n    audience: 'mi-api',     // Audiencia del token\n    jwtid: crypto.randomBytes(16).toString('hex') // ID único para prevenir reutilización\n  };\n  \n  // Combinar opciones predeterminadas con las proporcionadas\n  const tokenOptions = { ...defaultOptions, ...options };\n  \n  // Crear y firmar el token\n  return jwt.sign(payload, secretKey, tokenOptions);\n}\n\n// Función para verificar un token JWT\nfunction verifyToken(token) {\n  try {\n    // Verificar y decodificar el token\n    const decoded = jwt.verify(token, secretKey, {\n      algorithms: ['HS256'],      // Limitar a algoritmos seguros\n      issuer: 'mi-aplicacion',    // Verificar emisor\n      audience: 'mi-api',         // Verificar audiencia\n      clockTolerance: 30          // Tolerancia de 30 segundos para diferencias de reloj\n    });\n    \n    return { valid: true, payload: decoded };\n  } catch (error) {\n    return { \n      valid: false, \n      error: error.name, \n      message: error.message \n    };\n  }\n}\n\n// Ejemplo de uso\nconst userData = {\n  id: '12345',\n  username: 'usuario_ejemplo',\n  role: 'user'\n};\n\n// Crear token\nconst token = createToken(userData);\nconsole.log('Token JWT:', token);\n\n// Verificar token válido\nconst verification = verifyToken(token);\nconsole.log('Verificación:', verification);\n\n// Verificar token manipulado\nconst tampered = token.slice(0, -5) + 'xxxxx';\nconst tamperedVerification = verifyToken(tampered);\nconsole.log('Verificación de token manipulado:', tamperedVerification);`
                }],
                securityPoints: [
                    "Usar <strong>tiempos de expiración cortos</strong> para tokens de acceso",
                    "Implementar <strong>rotación de tokens</strong> con tokens de actualización",
                    "Validar <strong>todos los campos</strong> del token (emisor, audiencia, tiempo)",
                    "Almacenar <strong>claves secretas de forma segura</strong> y rotarlas periódicamente",
                    "Implementar <strong>revocación de tokens</strong> para sesiones comprometidas"
                ]
            },
        }
    },
    blockchainCrypto: {
        title: "Criptografía en Blockchain y Contratos Inteligentes",
        iconName: "orbit",
        subsections: {
            "blockchain-basics": {
                title: "Fundamentos Criptográficos en Blockchain",
                description: "Blockchain es una tecnología de registro distribuido que garantiza la inmutabilidad y transparencia de la información mediante criptografía y consenso descentralizado. Su diseño resistente a manipulaciones lo hace ideal para almacenar transacciones, registros digitales y datos auditables",
                characteristics: {
                    left: {
                        title: "Componentes clave",
                        items: [
                            "Funciones hash criptográficas (SHA-256, Keccak-256)",
                            "Firmas digitales (ECDSA, EdDSA)",
                            "Merkle Trees para verificación de datos",
                            "Algoritmos de consenso (PoW, PoS)"
                        ]
                    },
                    right: {
                        title: "Beneficios",
                        items: [
                            "Integridad e inmutabilidad de los datos",
                            "Verificación descentralizada",
                            "Resistencia a la censura y manipulación",
                            "Transparencia en entornos distribuidos"
                        ]
                    }
                },
                examples: [
                    {
                        language: "javascript",
                        code: `const crypto = require('crypto');\n\n// Función que aplica SHA-256 a un string\nfunction sha256(data) {\n  return crypto.createHash('sha256').update(data).digest('hex');\n}\n\n// Simulamos un conjunto de transacciones dentro de un bloque\nconst transactions = ["Tx1", "Tx2", "Tx3", "Tx4"];\n\n// Ciframos cada transacción con SHA-256\nconst hashedTxs = transactions.map(sha256);\n\n// Función recursiva para construir la raíz de Merkle\nfunction buildMerkleRoot(hashes) {\n  // Caso base: si solo queda un hash, es la raíz\n  if (hashes.length === 1) return hashes[0];\n\n  const newLevel = [];\n  for (let i = 0; i < hashes.length; i += 2) {\n    // Tomamos pares de hashes y los concatenamos\n    const left = hashes[i];\n    const right = hashes[i + 1] || left; // Duplicamos si hay número impar\n\n    // Hasheamos el resultado y lo agregamos al nuevo nivel\n    newLevel.push(sha256(left + right));\n  }\n\n  // Repetimos hasta obtener una sola raíz\n  return buildMerkleRoot(newLevel);\n}\n\nconst merkleRoot = buildMerkleRoot(hashedTxs);\nconsole.log("Merkle Root:", merkleRoot);`,
                    }
                ],
                securityPoints: [
                    "<strong>Evitar</strong> algoritmos hash obsoletos (como SHA-1)",
                    "Usar <strong>claves privadas</strong> almacenadas en entornos seguros",
                    "<strong>Verificar</strong> correctamente las firmas de transacciones",
                    "Auditar los <strong>contratos inteligentes</strong> para evitar errores lógicos"
                ]
            },
            "smart-contracts": {
                title: "Contratos Inteligentes y Seguridad Criptográfica",
                description:
                    "Son programas autoejecutables desplegados en una blockchain que gestionan acuerdos de forma automática y sin intermediarios. Su lógica codificada permite garantizar cumplimiento, transparencia y seguridad en diversas aplicaciones como finanzas, logística o identidad digital.",
                characteristics: {
                    left: {
                        title: "Tecnologías involucradas",
                        items: [
                            "Lenguajes como Solidity o Vyper",
                            "Firmas digitales (ECDSA)",
                            "Direcciones derivadas de claves públicas",
                            "Transacciones criptográficamente firmadas"
                        ]
                    },
                    right: {
                        title: "Aplicaciones prácticas",
                        items: [
                            "Sistemas DeFi y préstamos automáticos",
                            "Mercados NFT",
                            "Automatización de pagos",
                            "Gobernanza descentralizada (DAO)"
                        ]
                    }
                },
                examples: [
                    {
                        language: "solidity",
                        code: `pragma solidity ^0.8.0;\n\ncontract SecureWallet {\n    // Dirección del propietario de la wallet\n    address public owner;\n\n    // Eventos para registrar depósitos y transferencias\n    event Deposited(address indexed from, uint amount);\n    event Transferred(address indexed to, uint amount);\n\n    // Constructor: se guarda el creador como dueño\n    constructor() {\n        owner = msg.sender;\n    }\n\n    // Modificador para restringir acceso solo al dueño\n    modifier onlyOwner() {\n        require(msg.sender == owner, "No autorizado");\n        _;\n    }\n\n    // Función para recibir fondos\n    function deposit() external payable {\n        emit Deposited(msg.sender, msg.value);\n    }\n\n    // Función que transfiere fondos solo si es el dueño\n    function transferFunds(address payable to, uint amount) external onlyOwner {\n        require(address(this).balance >= amount, "Fondos insuficientes");\n        to.transfer(amount);\n        emit Transferred(to, amount);\n    }\n\n    // Obtener el balance actual del contrato\n    function getBalance() public view returns (uint) {\n        return address(this).balance;\n    }\n}`,
                    }
                ],
                securityPoints: [
                    "<strong>Validar</strong> entradas y salidas del contrato",
                    "Evitar ataques de reentrancia",
                    "Limitar el uso de <strong>funciones críticas</strong> a propietarios",
                    "Usar herramientas como <strong>Slither</strong> o <strong>MythX</strong> para análisis"
                ]
            }
        }
    },
    criptografiaAvanzada: {
        title: "Criptografía Avanzada",
        iconName: "fingerprint",
        subsections: {
            ecc: {
                title: "Criptografía de Curva Elíptica (ECC)",
                description: "La Criptografía de Curva Elíptica (ECC) ofrece el mismo nivel de seguridad que RSA pero con claves mucho más pequeñas, lo que la hace ideal para dispositivos con recursos limitados y aplicaciones móviles.",
                characteristics: {
                    left: {
                        title: "Ventajas",
                        items: [
                            "Claves más pequeñas (256 bits ECC ≈ 3072 bits RSA)",
                            "Menor consumo de recursos computacionales",
                            "Mejor rendimiento en dispositivos móviles",
                            "Ideal para IoT y sistemas embebidos",
                        ]
                    },
                    right: {
                        title: "Curvas populares",
                        items: [
                            "Curve25519 / X25519 (intercambio de claves)",
                            "Ed25519 (firmas digitales)",
                            "P-256 (NIST)",
                            "secp256k1 (utilizada en Bitcoin y blockchain)"
                        ]
                    }
                },
                examples: [{
                    language: 'javascript',
                    code: `//Ejemplo: Firma digital con Ed25519\n\nconst nacl = require('tweetnacl');\nconst util = require('tweetnacl-util');\n\n// Convertir string a Uint8Array y viceversa\nconst { encodeUTF8, decodeUTF8, encodeBase64, decodeBase64 } = util;\n\n// Función para generar par de claves Ed25519\nfunction generateKeyPair() {\n  const keyPair = nacl.sign.keyPair();\n  return {\n    publicKey: encodeBase64(keyPair.publicKey),\n    secretKey: encodeBase64(keyPair.secretKey)\n  };\n}\n\n// Función para firmar un mensaje\nfunction signMessage(message, secretKeyBase64) {\n  const messageUint8 = decodeUTF8(message);\n  const secretKey = decodeBase64(secretKeyBase64);\n  const signature = nacl.sign.detached(messageUint8, secretKey);\n  return encodeBase64(signature);\n}\n\n// Función para verificar una firma\nfunction verifySignature(message, signature, publicKeyBase64) {\n  const messageUint8 = decodeUTF8(message);\n  const signatureUint8 = decodeBase64(signature);\n  const publicKey = decodeBase64(publicKeyBase64);\n  \n  return nacl.sign.detached.verify(messageUint8, signatureUint8, publicKey);\n}\n\n// Ejemplo de uso\nconst message = 'Mensaje importante que necesita ser firmado';\n\n// Generar par de claves\nconst keyPair = generateKeyPair();\nconsole.log('Clave pública:', keyPair.publicKey);\nconsole.log('Clave privada:', keyPair.secretKey);\n\n// Firmar mensaje\nconst signature = signMessage(message, keyPair.secretKey);\nconsole.log('Firma:', signature);\n\n// Verificar firma (debería ser true)\nconst isValid = verifySignature(message, signature, keyPair.publicKey);\nconsole.log('¿Firma válida?', isValid);\n\n// Verificar firma con mensaje modificado (debería ser false)\nconst isValidModified = verifySignature(message + ' modificado', signature, keyPair.publicKey);\nconsole.log('¿Firma válida con mensaje modificado?', isValidModified);`
                }],
                securityPoints: [
                    "Elegir <strong>curvas seguras y estandarizadas</strong> (Curve25519, P-256)",
                    "Utilizar <strong>implementaciones validadas</strong> y bibliotecas probadas",
                    "Proteger las <strong>claves privadas</strong> con el mismo cuidado que en RSA",
                    "Verificar la <strong>generación de números aleatorios</strong> para la creación de claves",
                ]
            },
            "homomorphic-encryption": {
                title: "Cifrado Homomórfico",
                description:
                    "Permite realizar operaciones matemáticas directamente sobre datos cifrados, sin necesidad de descifrarlos previamente. Esto posibilita el procesamiento seguro de información sensible en entornos no confiables, como servicios en la nube.",
                characteristics: {
                    left: {
                        title: "Tipos de cifrado homomórfico",
                        items: [
                            "Parcialmente homomórfico (PHE)",
                            "Homomórfico por capas (Somewhat HE)",
                            "Totalmente homomórfico (FHE)"
                        ]
                    },
                    right: {
                        title: "Ventajas",
                        items: [
                            "Procesamiento seguro de datos sensibles",
                            "Aplicaciones en salud, finanzas y datos privados",
                            "Reducción de exposición de datos a terceros",
                            "Cálculo seguro en la nube"
                        ]
                    }
                },
                examples: [
                    {
                        language: "python",
                        code: `from phe import paillier\n\n# Generamos un par de claves públicas/privadas\npublic_key, private_key = paillier.generate_paillier_keypair()\n\n# Simulamos salarios confidenciales\nsalaries = [3500, 4200, 3900]\n\n# Ciframos cada salario con la clave pública\nencrypted_salaries = [public_key.encrypt(s) for s in salaries]\n\n# Sumamos los salarios cifrados (sin descifrar)\ntotal_encrypted = sum(encrypted_salaries)\n\n# Desciframos el total para obtener la suma real\ntotal_decrypted = private_key.decrypt(total_encrypted)\n\n# Calculamos el promedio (de forma local)\naverage_salary = total_decrypted / len(salaries)\n\nprint("Total descifrado:", total_decrypted)\nprint("Promedio salarial:", average_salary)`
                    }
                ],
                securityPoints: [
                    "Los algoritmos homomórficos requieren <strong>mayor tiempo de procesamiento</strong>",
                    "Evitar <strong>filtrado lateral</strong> de datos en el entorno de ejecución",
                    "Usar <strong>bibliotecas confiables</strong> y auditadas",
                    "Proteger las <strong>claves privadas</strong> con medidas adicionales"
                ]
            },
            "secure-multiparty-computation": {
                title: "Computación Multipartita Segura (SMPC)",
                description:
                    "Ppermite a varias partes colaborar en el cálculo de una función sin revelar sus datos privados entre ellas. Es fundamental en escenarios donde se requiere cooperación con alta privacidad, como análisis entre empresas o votaciones digitales.",
                characteristics: {
                    left: {
                        title: "Técnicas comunes",
                        items: [
                            "Secret sharing (Shamir)",
                            "Oblivious Transfer",
                            "Garbled Circuits",
                            "ZK-SNARKs y ZK-STARKs"
                        ]
                    },
                    right: {
                        title: "Usos frecuentes",
                        items: [
                            "Votaciones seguras",
                            "Subastas sin revelación de pujas",
                            "Cómputos colaborativos privados",
                            "Protección de datos en IA federada"
                        ]
                    }
                },
                examples: [
                    {
                        language: "python",
                        code: `from mpyc.runtime import mpc\n\n# Inicializamos un tipo seguro entero (32 bits por defecto)\nsecint = mpc.SecInt()\n\n# Arrancamos el entorno seguro\nawait mpc.start()\n\n# Votos individuales simulados (1 = sí, 0 = no), ocultos en forma cifrada\nvotes = [secint(1), secint(0), secint(1), secint(1)]\n\n# Suma segura de los votos (sin conocer su valor individual)\ntotal_votes = sum(votes)\n\n# Obtenemos el resultado de la suma revelando solo el total\nresult = await mpc.output(total_votes)\n\nprint("Votos a favor:", result, "de", len(votes))\n\n# Cerramos el entorno seguro\nawait mpc.shutdown()`,
                    }
                ],
                securityPoints: [
                    "La implementación debe seguir un <strong>modelo de amenaza</strong> claro",
                    "Minimizar fugas de información durante la comunicación",
                    "Utilizar <strong>canales seguros</strong> entre participantes",
                    "Verificar que las librerías estén bien mantenidas"
                ]
            },
            cuantica: {
                title: "Criptografía Cuántica y Post-Cuántica",
                description: "La computación cuántica representa una amenaza para muchos algoritmos criptográficos actuales. La criptografía post-cuántica desarrolla algoritmos resistentes a ataques de computadoras cuánticas.",
                characteristics: {
                    left: {
                        title: "Algoritmos vulnerables a ataques cuánticos",
                        items: [
                            "RSA (factorización de números)",
                            "ECC (logaritmo discreto)",
                            "Diffie-Hellman (logaritmo discreto)",
                        ]
                    },
                    right: {
                        title: "Algoritmos post-cuánticos",
                        items: [
                            "Lattice-based (NTRU, CRYSTALS-Kyber)",
                            "Hash-based (SPHINCS+)",
                            "Code-based (McEliece)",
                            "Multivariate-based (Rainbow)"
                        ]
                    }
                },
                examples: [{
                    language: 'javascript',
                    code: `// Nota: Este es un ejemplo conceptual, ya que las implementaciones\n// de criptografía post-cuántica aún están en desarrollo y estandarización\n\nconst kyber = require('kyber-crystals');\n\n// Generar par de claves Kyber\nfunction generateKyberKeys() {\n  // Kyber-768 ofrece seguridad de nivel 3 (equivalente a AES-192)\n  const keyPair = kyber.keyPair(768);\n  return {\n    publicKey: keyPair.publicKey,\n    secretKey: keyPair.secretKey\n  };\n}\n\n// Encapsular una clave compartida usando la clave pública\nfunction encapsulate(publicKey) {\n  const result = kyber.encapsulate(publicKey);\n  return {\n    sharedSecret: result.sharedSecret, // Clave simétrica para cifrado\n    ciphertext: result.ciphertext      // Datos para que el receptor derive la misma clave\n  };\n}\n\n// Desencapsular para obtener la misma clave compartida\nfunction decapsulate(ciphertext, secretKey) {\n  const sharedSecret = kyber.decapsulate(ciphertext, secretKey);\n  return sharedSecret;\n}\n\n// Ejemplo de uso\nasync function secureExchange() {\n  // Generar claves para el receptor\n  const receiverKeys = generateKyberKeys();\n  \n  // Remitente encapsula una clave compartida\n  const { sharedSecret: senderSharedSecret, ciphertext } = encapsulate(receiverKeys.publicKey);\n  \n  // Receptor desencapsula para obtener la misma clave compartida\n  const receiverSharedSecret = decapsulate(ciphertext, receiverKeys.secretKey);\n  \n  // Ambas partes ahora tienen la misma clave secreta\n  console.log('¿Claves iguales?', Buffer.compare(senderSharedSecret, receiverSharedSecret) === 0);\n  \n  // Esta clave compartida puede usarse para cifrado simétrico (AES)\n  // const aesKey = sharedSecret.slice(0, 32); // 256 bits para AES-256\n}\n\nsecureExchange();`
                }],
                securityPoints: [
                    "Mantenerse informado sobre los <strong>estándares emergentes</strong> del NIST",
                    "Implementar <strong>criptografía híbrida</strong> (tradicional + post-cuántica)",
                    "Diseñar sistemas con <strong>agilidad criptográfica</strong> para facilitar la transición",
                    "Evaluar el <strong>impacto en el rendimiento</strong> de los algoritmos post-cuánticos",
                    "Comenzar a <strong>planificar la migración</strong> de sistemas críticos"
                ]
            }
        }
    },
    implementacionesPracticas: {
        title: "Implementaciones Prácticas",
        iconName: "book-text",
        subsections: {
            firmasDigitales: {
                title: "Firmas Digitales",
                description:
                    "Las firmas digitales proporcionan autenticidad, integridad y no repudio a los documentos electrónicos. Combinan criptografía asimétrica y funciones hash para crear un mecanismo que verifica tanto el origen como la integridad de los datos.",
                characteristics: {
                    left: {
                        title: "Proceso de firma",
                        items: [
                            "Generar un hash del documento original",
                            "Cifrar el hash con la clave privada del firmante",
                            "Distribuir el documento junto con la firma",
                            "El receptor verifica usando la clave pública del firmante",
                        ],
                    },
                    right: {
                        title: "Aplicaciones",
                        items: [
                            "Documentos legales electrónicos",
                            "Certificados digitales",
                            "Código de software (verificación de integridad)",
                            "Transacciones financieras",
                            "Correos electrónicos firmados (S/MIME, PGP)",
                        ],
                    },
                },
                examples: [
                    {
                        language: "java",
                        code: `import java.nio.file.Files;\nimport java.nio.file.Paths;\nimport java.security.*;\nimport java.util.Base64;\n\npublic class DigitalSignatureExample {\n\n    // Generar par de claves RSA\n    public static KeyPair generateKeyPair() throws Exception {\n        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");\n        keyPairGenerator.initialize(2048); // Tamaño de clave recomendado\n        return keyPairGenerator.generateKeyPair();\n    }\n\n    // Firmar datos con clave privada\n    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {\n        Signature signature = Signature.getInstance("SHA256withRSA");\n        signature.initSign(privateKey);\n        signature.update(data);\n        return signature.sign();\n    }\n\n    // Verificar firma con clave pública\n    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {\n        Signature signature = Signature.getInstance("SHA256withRSA");\n        signature.initVerify(publicKey);\n        signature.update(data);\n        return signature.verify(signatureBytes);\n    }\n\n    public static void main(String[] args) {\n        try {\n            // Generar par de claves\n            KeyPair keyPair = generateKeyPair();\n            PublicKey publicKey = keyPair.getPublic();\n            PrivateKey privateKey = keyPair.getPrivate();\n\n            // Datos a firmar (podría ser un archivo)\n            String message = "Este es un documento importante que necesita ser firmado digitalmente";\n            byte[] data = message.getBytes();\n\n            // Firmar los datos\n            byte[] signatureBytes = sign(data, privateKey);\n            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);\n            System.out.println("Firma digital: " + signatureBase64);\n\n            // Verificar la firma (simulando recepción)\n            boolean isValid = verify(data, signatureBytes, publicKey);\n            System.out.println("¿Firma válida? " + isValid);\n\n            // Verificar con datos modificados (debe fallar)\n            String modifiedMessage = message + " con modificación no autorizada";\n            byte[] modifiedData = modifiedMessage.getBytes();\n            boolean isValidModified = verify(modifiedData, signatureBytes, publicKey);\n            System.out.println("¿Firma válida con datos modificados? " + isValidModified);\n\n        } catch (Exception e) {\n            System.err.println("Error: " + e.getMessage());\n            e.printStackTrace();\n        }\n    }\n}`,
                    },
                ],
                securityPoints: [
                    "Utilizar <strong>algoritmos de firma robustos</strong> como RSA-PSS, ECDSA o Ed25519",
                    "Proteger las <strong>claves privadas</strong> con medidas estrictas de seguridad",
                    "Implementar <strong>validación completa</strong> de certificados en la cadena de confianza",
                    "Usar <strong>funciones hash seguras</strong> (SHA-256 o superior) en el proceso de firma",
                    "Considerar la <strong>revocación de certificados</strong> en caso de compromiso de claves",
                ],
            },
            secureShell: {
                title: "Secure Shell (SSH)",
                description:
                    "SSH (Secure Shell) es un protocolo criptográfico para operar servicios de red de forma segura sobre una red no segura. Proporciona un canal cifrado para la comunicación de datos, autenticación fuerte y gestión de sesiones seguras.",
                characteristics: {
                    left: {
                        title: "Características principales",
                        items: [
                            "Autenticación por clave pública/privada",
                            "Cifrado de datos en tránsito",
                            "Integridad de datos mediante MACs",
                            "Reenvío de puertos (port forwarding)",
                            "Túneles seguros para otros protocolos",
                        ],
                    },
                    right: {
                        title: "Aplicaciones comunes",
                        items: [
                            "Administración remota de servidores",
                            "Transferencia segura de archivos (SFTP, SCP)",
                            "Túneles para bases de datos y servicios internos",
                            "Automatización de despliegues (CI/CD)",
                            "Acceso seguro a repositorios Git",
                        ],
                    },
                },
                examples: [
                    {
                        language: "python",
                        code: `import paramiko\nimport os\nimport socket\nimport sys\n\nclass SecureShellClient:\n    def __init__(self, hostname, port=22, username=None, key_filename=None, password=None):\n        self.hostname = hostname\n        self.port = port\n        self.username = username\n        self.key_filename = key_filename\n        self.password = password\n        self.client = None\n        self.session_log = []\n    \n    def connect(self):\n        """Establece una conexión SSH segura con el servidor"""\n        try:\n            # Inicializar cliente SSH\n            self.client = paramiko.SSHClient()\n            \n            # Configuración de seguridad para host keys\n            # En producción, usar 'system' o implementar verificación personalizada\n            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n            \n            # Registrar intento de conexión\n            self.log_action(f"Conectando a {self.hostname}:{self.port} como {self.username}")\n            \n            # Conectar usando autenticación por clave o contraseña\n            if self.key_filename:\n                self.client.connect(\n                    hostname=self.hostname,\n                    port=self.port,\n                    username=self.username,\n                    key_filename=self.key_filename,\n                    timeout=10\n                )\n                self.log_action("Autenticado con clave privada")\n            elif self.password:\n                self.client.connect(\n                    hostname=self.hostname,\n                    port=self.port,\n                    username=self.username,\n                    password=self.password,\n                    timeout=10\n                )\n                self.log_action("Autenticado con contraseña")\n            else:\n                raise ValueError("Se requiere clave privada o contraseña para la autenticación")\n                \n            return True\n            \n        except paramiko.AuthenticationException:\n            self.log_action("Error: Falló la autenticación")\n            return False\n        except paramiko.SSHException as e:\n            self.log_action(f"Error SSH: {str(e)}")\n            return False\n        except socket.error as e:\n            self.log_action(f"Error de conexión: {str(e)}")\n            return False\n    \n    def execute_command(self, command):\n        """Ejecuta un comando en el servidor remoto"""\n        if not self.client:\n            raise RuntimeError("No hay conexión SSH establecida")\n        \n        self.log_action(f"Ejecutando comando: {command}")\n        \n        # Crear canal para el comando\n        stdin, stdout, stderr = self.client.exec_command(command)\n        \n        # Obtener resultados\n        output = stdout.read().decode('utf-8')\n        error = stderr.read().decode('utf-8')\n        \n        if error:\n            self.log_action(f"Error en comando: {error}")\n        \n        return output\n    \n    def upload_file(self, local_path, remote_path):\n        """Sube un archivo al servidor remoto usando SFTP"""\n        if not self.client:\n            raise RuntimeError("No hay conexión SSH establecida")\n        \n        self.log_action(f"Subiendo archivo: {local_path} -> {remote_path}")\n        \n        try:\n            # Abrir sesión SFTP\n            sftp = self.client.open_sftp()\n            \n            # Subir archivo\n            sftp.put(local_path, remote_path)\n            \n            # Cerrar sesión SFTP\n            sftp.close()\n            \n            return True\n        except Exception as e:\n            self.log_action(f"Error al subir archivo: {str(e)}")\n            return False\n    \n    def download_file(self, remote_path, local_path):\n        """Descarga un archivo del servidor remoto usando SFTP"""\n        if not self.client:\n            raise RuntimeError("No hay conexión SSH establecida")\n        \n        self.log_action(f"Descargando archivo: {remote_path} -> {local_path}")\n        \n        try:\n            # Abrir sesión SFTP\n            sftp = self.client.open_sftp()\n            \n            # Descargar archivo\n            sftp.get(remote_path, local_path)\n            \n            # Cerrar sesión SFTP\n            sftp.close()\n            \n            return True\n        except Exception as e:\n            self.log_action(f"Error al descargar archivo: {str(e)}")\n            return False\n    \n    def close(self):\n        """Cierra la conexión SSH"""\n        if self.client:\n            self.client.close()\n            self.log_action("Conexión SSH cerrada")\n            self.client = None\n    \n    def log_action(self, message):\n        """Registra acciones para auditoría"""\n        self.session_log.append(message)\n        print(message)\n\n# Ejemplo de uso\nif __name__ == "__main__":\n    # Conexión con clave privada (más seguro)\n    ssh = SecureShellClient(\n        hostname="ejemplo.servidor.com",\n        username="usuario",\n        key_filename="~/.ssh/id_rsa"\n    )\n    \n    # Alternativa: conexión con contraseña (menos seguro)\n    # ssh = SecureShellClient(\n    #     hostname="ejemplo.servidor.com",\n    #     username="usuario",\n    #     password="contraseña_segura"\n    # )\n    \n    if ssh.connect():\n        # Ejecutar comandos\n        output = ssh.execute_command("ls -la")\n        print(f"Resultado del comando:\\n{output}")\n        \n        # Transferir archivos\n        ssh.upload_file("archivo_local.txt", "/ruta/remota/archivo.txt")\n        ssh.download_file("/ruta/remota/datos.csv", "datos_locales.csv")\n        \n        # Cerrar conexión\n        ssh.close()`,
                    },
                ],
                securityPoints: [
                    "Usar <strong>autenticación por clave pública</strong> en lugar de contraseñas",
                    "Deshabilitar el <strong>acceso root</strong> directo",
                    "Implementar <strong>autenticación de dos factores</strong> (2FA)",
                    "Limitar los <strong>intentos de inicio de sesión</strong> y usar listas blancas de IP",
                    "Mantener el <strong>software SSH actualizado</strong> para parchar vulnerabilidades",
                    "Configurar <strong>algoritmos criptográficos seguros</strong> y deshabilitar los obsoletos",
                ],
            },
            zeroKnowledgeProofs: {
                title: "Zero-Knowledge Proofs (ZKP)",
                description:
                    "Las pruebas de conocimiento cero (Zero-Knowledge Proofs) son protocolos criptográficos que permiten a una parte (el probador) demostrar a otra parte (el verificador) que conoce un valor o secreto, sin revelar ninguna información sobre el secreto mismo.",
                characteristics: {
                    left: {
                        title: "Propiedades clave",
                        items: [
                            "<strong>Completitud:</strong> Si la afirmación es verdadera, el verificador quedará convencido",
                            "<strong>Solidez:</strong> Si la afirmación es falsa, el probador no podrá convencer al verificador",
                            "<strong>Conocimiento cero:</strong> El verificador no aprende nada más que la veracidad de la afirmación",
                        ],
                    },
                    right: {
                        title: "Aplicaciones",
                        items: [
                            "Autenticación sin revelar contraseñas",
                            "Transacciones privadas en blockchain",
                            "Votación electrónica anónima",
                            "Verificación de identidad preservando la privacidad",
                            "Auditorías confidenciales",
                        ],
                    },
                },
                examples: [
                    {
                        language: "javascript",
                        code: `const crypto = require('crypto');\n\n/**\n * Implementación simplificada de una prueba de conocimiento cero para verificar\n * que un usuario conoce una contraseña sin revelarla.\n * \n * Este es un ejemplo educativo que ilustra el concepto de ZKP.\n * Para aplicaciones reales, use bibliotecas criptográficas especializadas.\n */\nclass PasswordZKP {\n  /**\n   * Configuración inicial para el protocolo\n   * @param {string} password - La contraseña que el probador conoce\n   */\n  constructor(password) {\n    // Generar un salt aleatorio para el hash\n    this.salt = crypto.randomBytes(16).toString('hex');\n    \n    // Calcular el hash de la contraseña (esto se almacenaría en el servidor)\n    this.passwordHash = this.hashPassword(password);\n    \n    // Número de rondas para la verificación\n    this.rounds = 10;\n  }\n  \n  /**\n   * Función para hashear la contraseña con el salt\n   * @param {string} password - La contraseña a hashear\n   * @returns {string} - El hash resultante en formato hex\n   */\n  hashPassword(password) {\n    return crypto.createHash('sha256')\n      .update(password + this.salt)\n      .digest('hex');\n  }\n  \n  /**\n   * Genera un desafío aleatorio para una ronda de verificación\n   * @returns {string} - Un desafío aleatorio\n   */\n  generateChallenge() {\n    return crypto.randomBytes(32).toString('hex');\n  }\n  \n  /**\n   * El probador genera un compromiso basado en la contraseña y un valor aleatorio\n   * @param {string} password - La contraseña del usuario\n   * @returns {Object} - El compromiso y el valor aleatorio usado\n   */\n  generateCommitment(password) {\n    // Generar un valor aleatorio (nonce) para esta ronda\n    const nonce = crypto.randomBytes(32).toString('hex');\n    \n    // Crear un compromiso combinando la contraseña con el nonce\n    const commitment = crypto.createHash('sha256')\n      .update(password + nonce)\n      .digest('hex');\n    \n    return { commitment, nonce };\n  }\n  \n  /**\n   * El probador genera una respuesta al desafío\n   * @param {string} password - La contraseña del usuario\n   * @param {string} challenge - El desafío recibido\n   * @param {string} nonce - El nonce usado en el compromiso\n   * @returns {string} - La respuesta al desafío\n   */\n  generateResponse(password, challenge, nonce) {\n    // Combinar la contraseña, el nonce y el desafío\n    return crypto.createHash('sha256')\n      .update(password + nonce + challenge)\n      .digest('hex');\n  }\n  \n  /**\n   * El verificador comprueba si la respuesta es correcta\n   * @param {string} commitment - El compromiso inicial\n   * @param {string} challenge - El desafío enviado\n   * @param {string} response - La respuesta recibida\n   * @returns {boolean} - True si la verificación es exitosa\n   */\n  verifyResponse(commitment, challenge, response) {\n    // En una implementación real, el verificador reconstruiría la respuesta\n    // usando el hash almacenado de la contraseña, el desafío y el compromiso\n    \n    // Para simplificar, aquí solo verificamos que la respuesta sea consistente\n    // con el compromiso y el desafío\n    \n    // Nota: Esta es una simplificación y no es una verdadera ZKP criptográficamente segura\n    const expectedPattern = commitment.substring(0, 8) + challenge.substring(0, 8);\n    return response.startsWith(expectedPattern);\n  }\n  \n  /**\n   * Ejecuta el protocolo completo de verificación\n   * @param {string} password - La contraseña que el probador afirma conocer\n   * @returns {boolean} - True si la verificación es exitosa\n   */\n  verify(password) {\n    // Verificar primero si el hash de la contraseña coincide\n    // Esto simula la verificación tradicional (no ZKP)\n    const providedHash = this.hashPassword(password);\n    if (providedHash !== this.passwordHash) {\n      console.log("❌ Verificación tradicional fallida: Hash incorrecto");\n      return false;\n    }\n    \n    console.log("✅ Verificación tradicional exitosa: Hash correcto");\n    console.log("Iniciando protocolo de conocimiento cero...");\n    \n    // Ejecutar múltiples rondas de verificación ZKP\n    let allRoundsSuccessful = true;\n    \n    for (let round = 1; round <= this.rounds; round++) {\n      console.log(\`\nRonda \${round}/\${this.rounds}:\`);\n      \n      // Paso 1: El probador genera un compromiso\n      const { commitment, nonce } = this.generateCommitment(password);\n      console.log(\`- Probador envía compromiso: \${commitment.substring(0, 16)}...\`);\n      \n      // Paso 2: El verificador envía un desafío\n      const challenge = this.generateChallenge();\n      console.log(\`- Verificador envía desafío: \${challenge.substring(0, 16)}...\`);\n      \n      // Paso 3: El probador genera una respuesta al desafío\n      const response = this.generateResponse(password, challenge, nonce);\n      console.log(\`- Probador envía respuesta: \${response.substring(0, 16)}...\`);\n      \n      // Paso 4: El verificador comprueba la respuesta\n      const isValid = this.verifyResponse(commitment, challenge, response);\n      \n      if (isValid) {\n        console.log(\`✅ Ronda \${round}: Verificación exitosa\`);\n      } else {\n        console.log(\`❌ Ronda \${round}: Verificación fallida\`);\n        allRoundsSuccessful = false;\n        break;\n      }\n    }\n    \n    return allRoundsSuccessful;\n  }\n}\n\n// Ejemplo de uso\nconst secretPassword = "mi_contraseña_secreta";\n\n// Configurar el protocolo\nconst zkp = new PasswordZKP(secretPassword);\n\n// Verificar con la contraseña correcta\nconsole.log("Verificando con contraseña correcta:");\nconst isValidCorrect = zkp.verify(secretPassword);\nconsole.log(\`\nResultado final: \${isValidCorrect ? "✅ Verificación exitosa" : "❌ Verificación fallida"}\`);\n\n// Verificar con una contraseña incorrecta\nconsole.log("\n-----------------------------------\n");\nconsole.log("Verificando con contraseña incorrecta:");\nconst isValidIncorrect = zkp.verify("contraseña_incorrecta");\nconsole.log(\`\nResultado final: \${isValidIncorrect ? "✅ Verificación exitosa" : "❌ Verificación fallida"}\`);`,
                    },
                ],
                securityPoints: [
                    "Utilizar <strong>bibliotecas especializadas</strong> para implementaciones reales de ZKP",
                    "Considerar <strong>protocolos estandarizados</strong> como zk-SNARKs o zk-STARKs para aplicaciones críticas",
                    "Implementar <strong>verificación de integridad</strong> para todos los mensajes intercambiados",
                    "Asegurar que el <strong>canal de comunicación</strong> entre probador y verificador sea seguro",
                    "Realizar <strong>auditorías de seguridad</strong> en implementaciones de ZKP",
                ],
            },
        },
    },
}

export default criptografiaData
