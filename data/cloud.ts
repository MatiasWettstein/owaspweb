const cloudData = {
    risk1: {
        "title": "Configuración insegura de la nube, contenedores u orquestadores",
        "attackVector": "Actores maliciosos explotan configuraciones inseguras como buckets públicos, contenedores ejecutándose como root o recursos compartidos con el host.",
        "weakness": "Falta de validación y revisión en configuraciones predeterminadas o personalizadas en servicios cloud, contenedores o herramientas de orquestación.",
        "impact": "Accesos no autorizados, escalamiento de privilegios, exfiltración de datos o compromiso completo del entorno de ejecución.",
        "mitigationStrategies": [
            "Aplicar configuraciones seguras por defecto y revisar IaC (Infrastructure as Code) antes del despliegue.",
            "Evitar ejecutar contenedores con privilegios elevados o como usuario root.",
            "Auditar y restringir los permisos de recursos como buckets, volúmenes compartidos y roles del orquestador."
        ],
        "example1": {
            "language": "docker",
            "vulnerable": "// ❌ Dockerfile vulnerable: contenedor se ejecuta como root\nFROM ubuntu:latest\nRUN apt-get update && apt-get install -y nginx\nCMD [\"/usr/sbin/nginx\", \"-g\", \"daemon off;\"]",
            "secure": "// ✅ Dockerfile seguro: define un usuario sin privilegios\nFROM ubuntu:latest\nRUN useradd -m appuser && apt-get update && apt-get install -y nginx\nUSER appuser\nCMD [\"/usr/sbin/nginx\", \"-g\", \"daemon off;\"]"
        },
        "example2": {
            "language": "yaml",
            "vulnerable": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: vulnerable-pod\nspec:\n  containers:\n    - name: insecure-container\n      image: myapp:latest\n      securityContext:\n        privileged: true",
            "secure": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: secure-pod\nspec:\n  containers:\n    - name: secure-container\n      image: myapp:latest\n      securityContext:\n        runAsUser: 1000\n        runAsGroup: 3000\n        allowPrivilegeEscalation: false\n        privileged: false\n        readOnlyRootFilesystem: true"
        },
        "goodPractices": [
            "Revisar y aplicar políticas seguras por defecto en IaC.",
            "Usar herramientas de escaneo de configuración como kube-bench, tfsec o Checkov.",
            "Deshabilitar privilegios innecesarios y recursos compartidos entre host y contenedor.",
            "Asegurar que ningún recurso esté expuesto públicamente sin justificación explícita."
        ]
    },
    risk2: {
        "title": "Fallos de inyección (capa de aplicación, eventos cloud, servicios cloud)",
        "attackVector": "Los atacantes aprovechan puntos de entrada donde no se validan adecuadamente los datos para ejecutar código malicioso, comandos del sistema o manipular estructuras de datos.",
        "weakness": "Falta de sanitización, validación o escapes en los datos que interactúan con servicios internos, bases de datos, o infraestructura cloud.",
        "impact": "Compromiso de datos, ejecución remota de código, acceso no autorizado o corrupción de servicios críticos.",
        "mitigationStrategies": [
            "Validar y sanear estrictamente toda entrada de usuario en cada punto de interacción.",
            "Usar consultas parametrizadas y evitar concatenaciones de strings en consultas a servicios o bases de datos.",
            "Aplicar políticas de permisos mínimos para mitigar el alcance de una posible inyección exitosa."
        ],
        "example1": {
            "language": "javascript",
            "vulnerable": "// Vulnerable: comando del sistema con entrada directa\nconst { exec } = require('child_process');\napp.get('/ping', (req, res) => {\n  exec(`ping -c 3 ${req.query.host}`, (err, stdout) => {\n    res.send(stdout);\n  });\n});",
            "secure": "// Seguro: validación estricta de entrada\nconst { exec } = require('child_process');\nconst isValidHost = host => /^[a-zA-Z0-9.-]+$/.test(host);\napp.get('/ping', (req, res) => {\n  const host = req.query.host;\n  if (!isValidHost(host)) return res.status(400).send('Invalid host');\n  exec(`ping -c 3 ${host}`, (err, stdout) => {\n    res.send(stdout);\n  });\n});"
        },
        "example2": {
            "language": "hcl",
            "vulnerable": "# Vulnerable: entrada sin validación en evento Lambda\nresource \"aws_lambda_function\" \"example\" {\n  function_name = \"unvalidated-event\"\n  handler       = \"index.handler\"\n  runtime       = \"nodejs18.x\"\n  filename      = \"lambda.zip\"\n  environment {\n    variables = {\n      DANGEROUS_COMMAND = var.user_input\n    }\n  }\n}",
            "secure": "# Seguro: se define una variable validada y controlada\nvariable \"safe_input\" {\n  type    = string\n  default = \"ping-default\"\n  validation {\n    condition     = can(regex(\"^[a-zA-Z0-9.-]+$\", var.safe_input))\n    error_message = \"Input must be a valid host.\"\n  }\n}\n\nresource \"aws_lambda_function\" \"example\" {\n  function_name = \"validated-event\"\n  handler       = \"index.handler\"\n  runtime       = \"nodejs18.x\"\n  filename      = \"lambda.zip\"\n  environment {\n    variables = {\n      SAFE_COMMAND = var.safe_input\n    }\n  }\n}"
        },
        "goodPractices": [
            "Usar validadores de entrada centralizados o middleware para inputs comunes.",
            "Evitar el uso de `eval`, `exec` o cualquier función que interprete entrada dinámica sin validación.",
            "Configurar firewalls y WAFs para detectar y bloquear payloads de inyección.",
            "Aplicar políticas de seguridad en eventos cloud, como reglas estrictas en triggers Lambda o Step Functions."
        ]
    },
    risk3: {
        "title": "Autenticación y autorización inadecuadas",
        "attackVector": "Los atacantes explotan servicios expuestos sin autenticación o con controles de autorización inadecuados, como APIs internas o consolas de administración.",
        "weakness": "Falta de autenticación robusta, roles excesivamente permisivos o políticas de acceso mal configuradas en microservicios o herramientas de orquestación.",
        "impact": "Acceso no autorizado a recursos sensibles, ejecución de acciones privilegiadas y expansión lateral en la infraestructura cloud.",
        "mitigationStrategies": [
            "Implementar autenticación obligatoria en todas las interfaces, incluyendo APIs internas y consolas de gestión.",
            "Aplicar el principio de menor privilegio al definir roles y permisos en IAM y orquestadores.",
            "Habilitar auditoría de accesos y alertas sobre cambios en políticas de autorización."
        ],
        "example1": {
            "language": "yaml",
            "vulnerable": "# ❌ Vulnerable: Permisos excesivos en el rol\nkind: Role\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  namespace: default\n  name: overly-permissive-role\nrules:\n- apiGroups: [\"*\"]\n  resources: [\"*\"]\n  verbs: [\"*\"]",
            "secure": "# ✅ Seguro: Permisos limitados a recursos específicos\nkind: Role\napiVersion: rbac.authorization.k8s.io/v1\nmetadata:\n  namespace: default\n  name: limited-role\nrules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"get\", \"list\"]"
        },
        "example2": {
            "language": "javascript",
            "vulnerable": "// ❌ Hardcodear secretos en el código fuente es una mala práctica\nconst insecureDbPassword = \"supersecreta123\"; // Esto puede filtrarse \n\nfunction getInsecureDbUri() {\n  return `postgresql://admin:${insecureDbPassword}@db:5432/mydb`;\n}\n\nconsole.log(\"Insecure URI:\", getInsecureDbUri());",
            "secure": "// ✅ Usar variables de entorno y gestores de secretos\n\n// Paso 1: Cargar variables de entorno desde el entorno del sistema o desde un gestor de secretos\nconst secureDbPassword = process.env.DATABASE_PASSWORD;\n\n// Paso 2: Validar que la variable de entorno esté definida\nif (!secureDbPassword) {\n  throw new Error(\"La variable de entorno DATABASE_PASSWORD no está definida.\");\n}\n\n// Paso 3: Construir el URI de forma segura\nfunction getSecureDbUri() {\n  return `postgresql://admin:${secureDbPassword}@db:5432/mydb`;\n}\n\nconsole.log(\"Secure URI:\", getSecureDbUri());"
        },
        "goodPractices": [
            "Asegurar que todas las APIs y servicios internos cuenten con autenticación, incluso en entornos de desarrollo.",
            "Revisar regularmente los permisos en IAM y RBAC para eliminar excesos o accesos obsoletos.",
            "Separar los roles de acceso entre entornos (desarrollo, staging, producción).",
            "Auditar y registrar cada intento de acceso a recursos sensibles o administrativos."
        ]
    },
    risk4: {
        "title": "Fallos en la cadena de suministro de software y pipelines CI/CD",
        "attackVector": "Los atacantes comprometen pipelines de CI/CD mal protegidos, imágenes de contenedor no confiables o flujos de integración sin control de integridad.",
        "weakness": "Falta de autenticación en servicios de CI/CD, uso de imágenes o dependencias no verificadas, o acceso no restringido a registros de imágenes.",
        "impact": "Compromiso del entorno de construcción o despliegue, introducción de software malicioso y pérdida de integridad del sistema.",
        "mitigationStrategies": [
            "Habilitar autenticación fuerte y control de acceso en herramientas y pipelines de CI/CD.",
            "Usar solo imágenes y dependencias firmadas o provenientes de fuentes confiables.",
            "Restringir el acceso a registros de contenedores y verificar el contenido antes del uso."
        ],
        "example1": {
            "language": "yaml",
            "vulnerable": "# ❌ Vulnerable: Usa imagen no verificada desde Docker Hub\nactions:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://node:latest\n        with:\n          entrypoint: \"npm install\"",
            "secure": "# ✅ Seguro: Usa imagen verificada y versionada desde fuente confiable\nactions:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://ghcr.io/your-org/node-builder:1.2.3\n        with:\n          entrypoint: \"npm install\""
        },
        "example2": {
            "language": "docker",
            "vulnerable": "# ❌ Vulnerable: Instala dependencias sin control de versiones\nFROM node:18\nRUN npm install express",
            "secure": "# ✅ Seguro: Fija versiones y verifica integridad de las dependencias\nFROM node:18\nCOPY package.json package-lock.json ./\nRUN npm ci --ignore-scripts --prefer-offline"
        },
        "goodPractices": [
            "Aplicar autenticación multifactor en accesos al sistema de CI/CD.",
            "Utilizar repositorios de artefactos privados con control de versiones y políticas de revisión.",
            "Escanear imágenes y dependencias antes del uso en ambientes de construcción o despliegue.",
            "Separar entornos de CI/CD según el nivel de riesgo y tipo de aplicación (producción, testing, desarrollo)."
        ]
    },
    risk5: {
        "title": "Almacenamiento inseguro de secretos",
        "attackVector": "Un atacante puede acceder a secretos expuestos o mal protegidos en contenedores, archivos de configuración o variables de entorno.",
        "weakness": "Almacenamiento de claves, tokens o contraseñas sin cifrado, uso de valores codificados o hardcodeados en el código fuente o dentro de imágenes.",
        "impact": "Compromiso de credenciales sensibles, acceso no autorizado a servicios internos o externos y escalada de privilegios.",
        "mitigationStrategies": [
            "Utilizar servicios de gestión de secretos que cifren la información en reposo y en tránsito.",
            "Evitar almacenar secretos en imágenes, repositorios o archivos de configuración sin cifrado.",
            "Rotar los secretos periódicamente y aplicar el principio de mínimo privilegio en su uso."
        ],
        "example1": {
            "language": "docker",
            "vulnerable": "# ❌ Vulnerable: Clave API hardcodeada\nFROM node:18\n\nENV API_KEY=\"abc123-super-secret-key\"\n\nWORKDIR /usr/src/app\n\nCOPY package*.json ./\nRUN npm install\nCOPY . .\n\n# La app accede a process.env.API_KEY dentro de app.js\nCMD [\"node\", \"app.js\"]",
            "secure": "# ✅ Seguro: Clave API se inyecta al momento de ejecución\nFROM node:18\n\nWORKDIR /usr/src/app\n\nCOPY package*.json ./\nRUN npm install\nCOPY . .\n\n# No se define la variable de entorno en la imagen.\n# Se debe pasar en tiempo de ejecución usando `docker run -e` o un gestor de secretos.\n\n# Ejemplo de ejecución segura (fuera de este archivo):\n# docker run -e API_KEY=$API_KEY_FROM_SECRET_STORE myapp\nCMD [\"node\", \"app.js\"]"
        },
        "example2": {
            "language": "javascript",
            "vulnerable": "// ❌ Vulnerable: Secreto hardcodeado en el código\nconst dbPassword = \"superSecret123\";\nconnectToDatabase(dbPassword);",
            "secure": "// ✅ Seguro: Secreto obtenido desde un gestor de secretos externo\nconst dbPassword = process.env.DB_PASSWORD;\nconnectToDatabase(dbPassword);"
        },
        "goodPractices": [
            "Centralizar la gestión de secretos utilizando herramientas como HashiCorp Vault, AWS Secrets Manager o Azure Key Vault.",
            "Evitar subir secretos a repositorios, incluso privados, mediante reglas de exclusión y escaneos automáticos.",
            "Configurar alertas ante accesos inesperados a secretos o rotaciones no autorizadas.",
            "Implementar rotación automática de secretos en sistemas críticos y documentar el procedimiento de acceso."
        ]
    },
    risk6: {
        "title": "Políticas de red inseguras o con permisos excesivos",
        "attackVector": "Un atacante aprovecha configuraciones de red mal definidas para interceptar, modificar o redirigir tráfico entre servicios internos.",
        "weakness": "Falta de segmentación, reglas de red demasiado permisivas, o comunicaciones sin cifrado entre servicios internos.",
        "impact": "Acceso no autorizado a datos internos, escalada lateral entre servicios y exposición de tráfico sensible a interceptación.",
        "mitigationStrategies": [
            "Aplicar segmentación de red y políticas de comunicación estrictas entre servicios.",
            "Configurar reglas de firewall o políticas de red que limiten el tráfico solo a lo necesario.",
            "Cifrar todas las comunicaciones internas con TLS incluso dentro del clúster o VPC."
        ],
        "example1": {
            "language": "yaml",
            "vulnerable": "# ❌ Vulnerable: Sin política de red definida (tráfico libre entre pods)\napiVersion: v1\nkind: Pod\nmetadata:\n  name: backend\nspec:\n  containers:\n  - name: app\n    image: backend:latest",
            "secure": "# ✅ Seguro: Política que restringe el acceso solo desde el pod 'frontend'\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow-frontend\nspec:\n  podSelector:\n    matchLabels:\n      role: backend\n  ingress:\n  - from:\n    - podSelector:\n        matchLabels:\n          role: frontend"
        },
        "example2": {
            "language": "hcl",
            "vulnerable": "# ❌ Vulnerable: Comunicación HTTP sin cifrado en servicios internos\nupstream backend {\n    server backend.internal:80;\n}\nserver {\n    location / {\n        proxy_pass http://backend;\n    }\n}",
            "secure": "# ✅ Seguro: Comunicación cifrada con HTTPS entre servicios internos\nupstream backend {\n    server backend.internal:443;\n}\nserver {\n    location / {\n        proxy_pass https://backend;\n        proxy_ssl_verify on;\n    }\n}"
        },
        "goodPractices": [
            "Definir políticas de red específicas para cada microservicio, limitando qué servicios pueden comunicarse entre sí.",
            "Auditar y revisar periódicamente las reglas de red, buscando accesos innecesarios o excesivos.",
            "Implementar mecanismos de detección de tráfico anómalo o no autorizado dentro de la red interna.",
            "Cifrar todo el tráfico, incluso en redes privadas, para reducir el riesgo de ataques tipo man-in-the-middle."
        ]
    },
    risk7: {
        "title": "Uso de componentes con vulnerabilidades conocidas",
        "attackVector": "Un atacante explota vulnerabilidades conocidas presentes en librerías, contenedores o servicios utilizados por la aplicación.",
        "weakness": "Uso de versiones obsoletas o inseguras de dependencias, contenedores o imágenes base sin aplicar actualizaciones o escaneos de seguridad.",
        "impact": "Ejecución remota de código, escalada de privilegios o compromiso total de la aplicación o infraestructura.",
        "mitigationStrategies": [
            "Integrar escáneres de vulnerabilidades en el pipeline de CI/CD para detectar versiones inseguras.",
            "Mantener actualizado el software base, contenedores e imágenes utilizadas.",
            "Usar fuentes oficiales y confiables para obtener dependencias y firmar las imágenes utilizadas."
        ],
        "example1": {
            "language": "docker",
            "vulnerable": "# ❌ Vulnerable: Uso de imagen obsoleta con vulnerabilidades conocidas\nFROM node:10\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD [\"npm\", \"start\"]",
            "secure": "# ✅ Seguro: Uso de imagen actualizada y estable con escaneo en CI/CD\nFROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"npm\", \"start\"]"
        },
        "example2": {
            "language": "json",
            "vulnerable": "// ❌ Vulnerable: Dependencia desactualizada\n{\n  \"dependencies\": {\n    \"express\": \"4.16.0\"\n  }\n}",
            "secure": "// ✅ Seguro: Dependencia actualizada con herramientas de escaneo integradas\n{\n  \"dependencies\": {\n    \"express\": \"^4.19.2\"\n  },\n  \"scripts\": {\n    \"audit\": \"npm audit\"\n  }\n}"
        },
        "goodPractices": [
            "Utilizar herramientas automáticas como Snyk, Trivy o Dependabot para detectar y alertar sobre vulnerabilidades.",
            "Restringir el uso de paquetes que no tengan mantenimiento activo o que no provengan de fuentes verificadas.",
            "Adoptar políticas internas que obliguen a mantener una frecuencia de actualización de dependencias.",
            "Revisar los cambios en las versiones antes de actualizarlas para evitar introducir regresiones o nuevas dependencias vulnerables."
        ]
    },
    risk8: {
        "title": "Gestión inadecuada de elementos",
        "attackVector": "Un atacante accede o explota servicios, microservicios o recursos en la nube que están activos pero no documentados ni supervisados.",
        "weakness": "Falta de inventario y documentación de activos cloud como APIs, contenedores, buckets o microservicios; recursos no eliminados o fuera del alcance de la observabilidad.",
        "impact": "Exposición de datos sensibles, incremento de la superficie de ataque, ejecución no autorizada de código o consumo de recursos innecesarios.",
        "mitigationStrategies": [
            "Mantener un inventario actualizado y automatizado de todos los activos cloud, incluyendo microservicios, APIs y recursos desplegados.",
            "Implementar herramientas de descubrimiento de activos y escaneo continuo de entornos cloud.",
            "Establecer políticas de limpieza y gobernanza para eliminar recursos obsoletos o no utilizados."
        ],
        "example1": {
            "language": "bash",
            "vulnerable": "# ❌ Código vulnerable: bucket público sin control ni inventario\n# Este bucket fue creado para compartir archivos temporalmente\naws s3api create-bucket --bucket dev-temporal-data --region us-east-1\naws s3 website s3://dev-temporal-data/ --index-document index.html\naws s3api put-bucket-policy --bucket dev-temporal-data --policy file://public-policy.json\n\n# El bucket queda público y no se elimina ni se documenta.",
            "secure": "# ✅ Código seguro: bucket con control, TTL y acceso restringido\naws s3api create-bucket --bucket dev-temporal-data --region us-east-1 \\n  --create-bucket-configuration LocationConstraint=us-east-1\n\n# Bloquear acceso público por defecto\naws s3api put-public-access-block --bucket dev-temporal-data \\n  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n\n# Agregar tags para visibilidad e inventario\naws s3api put-bucket-tagging --bucket dev-temporal-data --tagging 'TagSet=[{Key=Environment,Value=Dev},{Key=TTL,Value=7d}]'\n\n# Definir una política de ciclo de vida para eliminar objetos automáticamente\naws s3api put-bucket-lifecycle-configuration --bucket dev-temporal-data --lifecycle-configuration file://lifecycle.json\n"
        },
        "example2": {
            "language": "bash",
            "vulnerable": "# ❌ Vulnerable: Servicio no registrado ni con etiquetas para trazabilidad\naws ec2 run-instances --image-id ami-123456 --instance-type t2.micro",
            "secure": "# ✅ Seguro: Instancia lanzada con etiquetas de auditoría y centralización en inventario\naws ec2 run-instances \\\n  --image-id ami-123456 \\\n  --instance-type t2.micro \\\n  --tag-specifications 'ResourceType=instance,Tags=[{Key=Environment,Value=dev},{Key=Owner,Value=infra-team}]'"
        },
        "goodPractices": [
            "Etiquetar todos los recursos cloud con información de propietario, propósito y entorno.",
            "Automatizar la detección de activos desconocidos mediante herramientas como AWS Config, Azure Purview o GCP Asset Inventory.",
            "Auditar regularmente el entorno cloud en busca de servicios obsoletos o sin uso reciente.",
            "Centralizar la definición de recursos a través de Infrastructure as Code para mantener consistencia y trazabilidad."
        ]
    },
    risk9: {
        "title": "Límites de cuota de recursos computacionales mal definidos",
        "attackVector": "Un atacante o proceso malicioso puede explotar la ausencia de límites en los recursos computacionales para agotar CPU, memoria u otros recursos compartidos.",
        "weakness": "No establecer límites de uso en contenedores, funciones serverless o servicios expuestos, lo cual permite consumos excesivos o desequilibrados.",
        "impact": "Degradación del servicio, denegación de servicio (DoS) o interrupción total de otros procesos críticos debido a recursos agotados.",
        "mitigationStrategies": [
            "Definir límites y solicitudes explícitas de CPU y memoria para todos los contenedores o funciones desplegadas.",
            "Implementar políticas de cuotas a nivel de namespace, proyecto o tenant en entornos multiusuario.",
            "Monitorear el uso de recursos y aplicar autoscaling controlado para evitar desbordes inesperados."
        ],
        "example1": {
            "language": "yaml",
            "vulnerable": "# ❌ Vulnerable: Pod sin límites de recursos\napiVersion: v1\nkind: Pod\nmetadata:\n  name: unlimited-app\nspec:\n  containers:\n  - name: app\n    image: myapp:latest",
            "secure": "# ✅ Seguro: Pod con límites y solicitudes de recursos definidos\napiVersion: v1\nkind: Pod\nmetadata:\n  name: limited-app\nspec:\n  containers:\n  - name: app\n    image: myapp:latest\n    resources:\n      requests:\n        memory: \"128Mi\"\n        cpu: \"250m\"\n      limits:\n        memory: \"256Mi\"\n        cpu: \"500m\""
        },
        "example2": {
            "language": "javascript",
            "vulnerable": "// ❌ Vulnerable: Función lambda sin configuración adecuada de memoria\n{\n  \"FunctionName\": \"processLargeFiles\",\n  \"Runtime\": \"nodejs20.x\",\n  \"Handler\": \"index.handler\",\n  \"Timeout\": 900\n}",
            "secure": "// ✅ Seguro: Función lambda con asignación de memoria controlada\n{\n  \"FunctionName\": \"processLargeFiles\",\n  \"Runtime\": \"nodejs20.x\",\n  \"Handler\": \"index.handler\",\n  \"Timeout\": 300,\n  \"MemorySize\": 512\n}"
        },
        "goodPractices": [
            "Establecer límites de CPU y memoria como parte obligatoria del ciclo de despliegue.",
            "Auditar regularmente los consumos y aplicar ajustes automáticos según la carga histórica.",
            "Evitar valores por defecto indefinidos en plataformas cloud o Kubernetes.",
            "Aplicar pruebas de carga para validar el comportamiento del sistema bajo condiciones de consumo extremo."
        ]
    },
    risk10: {
        "title": "Registro y monitoreo ineficaces",
        "attackVector": "Un atacante puede aprovechar la falta de monitoreo para ejecutar acciones maliciosas sin ser detectado, como movimientos laterales, exfiltración de datos o uso abusivo de recursos.",
        "weakness": "Ausencia de registro de actividades críticas, monitoreo de red deficiente o nula supervisión de procesos en contenedores y hosts.",
        "impact": "Fallas en la detección temprana de incidentes, pérdida de trazabilidad, demoras en la respuesta a incidentes o incumplimiento de requisitos normativos.",
        "mitigationStrategies": [
            "Implementar herramientas de monitoreo y logging centralizado para contenedores, hosts y red.",
            "Habilitar alertas automáticas ante comportamientos anómalos o patrones sospechosos.",
            "Registrar eventos de seguridad relevantes como accesos, errores, cambios en configuración y operaciones privilegiadas."
        ],
        "example1": {
            "language": "docker",
            "vulnerable": "# ❌ Vulnerable: Contenedor sin configuración de logging\nFROM node:20\nCOPY . /app\nCMD [\"node\", \"index.js\"]",
            "secure": "# ✅ Seguro: Uso de driver de logging y redirección de logs\nFROM node:20\nCOPY . /app\nCMD [\"node\", \"index.js\"]\n# Configurar logging driver al ejecutar:\n# docker run --log-driver=json-file --log-opt max-size=10m --log-opt max-file=3 myapp"
        },
        "example2": {
            "language": "yaml",
            "vulnerable": "# ❌ Vulnerable: No se recolectan logs ni se monitorea la actividad\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: webapp\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n      - name: web\n        image: webapp:latest",
            "secure": "# ✅ Seguro: configurar el servicio para recolección de logs y monitoreo\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: webapp\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n      - name: web\n        image: webapp:latest\n      - name: log-forwarder\n        image: fluentd:latest\n        volumeMounts:\n        - name: logs\n          mountPath: /var/log/app\n      volumes:\n      - name: logs\n        emptyDir: {}"
        },
        "goodPractices": [
            "Centralizar logs con herramientas como ELK, Fluentd, Loki o Cloud-native solutions como CloudWatch o Stackdriver.",
            "Asegurar que todos los contenedores, funciones y servicios generen logs estructurados.",
            "Definir políticas de retención y revisión periódica de logs.",
            "Monitorear métricas clave y establecer alertas proactivas en eventos de seguridad o disponibilidad."
        ]
    }
}

export default cloudData