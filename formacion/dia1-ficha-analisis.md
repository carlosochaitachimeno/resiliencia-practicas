# Análisis de avisos
 
| Aviso (CVE o GHSA) | Componente y versión | Cadena de dependencia | Desarrollo o producción | ¿Llega a lo desplegado? | Corrección propuesta | Por qué |
|---|---|---|---|---|---|---|
|CVE-2025-24813  | org.apache.tomcat.embed:tomcat-embed-core 9.0.41  |org.springframework.samples:spring-petclinic:jar:2.4.0.BUILD-SNAPSHOT → \- org.springframework.boot:spring-boot-starter-web:jar:2.4.1:compile → \- org.springframework.boot:spring-boot-starter-tomcat:jar:2.4.1:compile → \- org.apache.tomcat.embed:tomcat-embed-core:jar:9.0.41:compile  |Producción  |Sí  |Subir la transitiva a 9.0.99  |La nueva versión corrige el CVE  |
|CVE-2025-48988  |org.apache.tomcat.embed:tomcat-embed-core 9.0.99 |org.springframework.samples:spring-petclinic:jar:2.4.0.BUILD-SNAPSHOT → \- org.springframework.boot:spring-boot-starter-web:jar:2.4.2:compile → \- org.springframework.boot:spring-boot-starter-tomcat:jar:2.4.2:compile → \- org.apache.tomcat.embed:tomcat-embed-core:jar:9.0.99:compile  |Producción  |Sí  |Subir la propiedad a 9.0.106 y sobreescribir la versión del BOM  |La nueva versión corrige el CVE.  |
|CVE-2025-52434  |org.apache.tomcat.embed:tomcat-embed-core 9.0.106 |org.springframework.samples:spring-petclinic:jar:2.4.0.BUILD-SNAPSHOT → \- org.springframework.boot:spring-boot-starter-web:jar:2.4.2:compile →  \- org.springframework.boot:spring-boot-starter-tomcat:jar:2.4.2:compile → \- org.apache.tomcat.embed:tomcat-embed-core:jar:9.0.106:compile  |Producción  |Sí  |Subir la propiedad a 9.0.107 y sobreescribir la versión del BOM  | La nueva versión corrige el CVE  |
|CVE-2024-4068  |braces@2.3.2 |jest@26.6.3 → @jest/core → jest-haste-map → sane@4.1.0 → micromatch@3.1.10 → braces@2.3.2  |Desarrollo   |No  |Subir la dependencia directa jest y ts-jest si aplica a una versión que ya no arrastre braces@2.3.2  |La nueva versión elimina la dependencia vulnerable desde el origen, sin usar overrides |
|GHSA-mrhx-c7xc-m3w5  |zod@3.25.76  |juice-shop → web3@4.16.0 → web3-validator@2.0.6 → zod@3.25.76  |Producción  |Sí  |Actualizar web3 o web3-validator a una versión que ya use zod ≥ 4.6.6, en vez de forzarlo con overrides  |Porque así se actualiza de forma normal y se evita forzar versiones con overrides  |


## Vulnerabilidad 1: Apache Tomcat embebido (dependencia vulnerable)

**Detección:** Trivy reportó vulnerabilidad en Tomcat embebido.

**Confirmación:** `dependency:tree` mostraba:

| Artefacto | Versión |
|---|---|
| `tomcat-embed-core` | `9.0.41` |
| `tomcat-embed-websocket` | `9.0.41` |

**Decisión:** Subir la propiedad `tomcat.version` (cambio acotado en la rama 9.0.x) mediante override, en lugar de excluir Tomcat (no procede) o subir `spring-boot-starter-parent` (cambio más amplio).

**Corrección aplicada:** en `pom.xml` (raíz), se forzó la versión corregida (sin bloque de código):

- `&lt;properties&gt;`
- `  &lt;tomcat.version&gt;9.0.99&lt;/tomcat.version&gt;`
- `&lt;/properties&gt;`

**Validación:**
- `./mvnw verify` → OK  
- `dependency:tree` → Tomcat `9.0.99`  
- `trivy fs --scanners vuln .` → el hallazgo dejó de aparecer / installed `9.0.99`

---

## Vulnerabilidad 2: Apache Tomcat embebido (dependencia vulnerable)

**Detección:** Trivy reportó vulnerabilidad en Tomcat embebido.

**Confirmación:** `dependency:tree` mostraba:

| Artefacto | Versión |
|---|---|
| `tomcat-embed-core` | `9.0.99` |
| `tomcat-embed-websocket` | `9.0.99` |

**Decisión:** Subir la propiedad `tomcat.version` (cambio acotado en la rama 9.0.x) mediante override, en lugar de excluir Tomcat (no procede) o subir `spring-boot-starter-parent` (cambio más amplio).

**Corrección aplicada:** en `pom.xml` (raíz), se forzó la versión corregida (sin bloque de código):

- `&lt;properties&gt;`
- `  &lt;tomcat.version&gt;9.0.106&lt;/tomcat.version&gt;`
- `&lt;/properties&gt;`

**Validación:**
- `./mvnw verify` → OK  
- `dependency:tree` → Tomcat `9.0.106`  
- `trivy fs --scanners vuln .` → el hallazgo dejó de aparecer / installed `9.0.106`

---

## Vulnerabilidad 3: Apache Tomcat embebido (dependencia vulnerable)

**Detección:** Trivy reportó vulnerabilidad en Tomcat embebido.

**Confirmación:** `dependency:tree` mostraba:

| Artefacto | Versión |
|---|---|
| `tomcat-embed-core` | `9.0.106` |
| `tomcat-embed-websocket` | `9.0.106` |

**Decisión:** Subir la propiedad `tomcat.version` (cambio acotado en la rama 9.0.x) mediante override, en lugar de excluir Tomcat (no procede) o subir `spring-boot-starter-parent` (cambio más amplio).

**Corrección aplicada:** en `pom.xml` (raíz), se forzó la versión corregida (sin bloque de código):

- `&lt;properties&gt;`
- `  &lt;tomcat.version&gt;9.0.107&lt;/tomcat.version&gt;`
- `&lt;/properties&gt;`

**Validación:**
- `./mvnw verify` → OK  
- `dependency:tree` → Tomcat `9.0.107`  
- `trivy fs --scanners vuln .` → el hallazgo dejó de aparecer / installed `9.0.107`




## Lab 2 — Paso 2: Con y sin dependencias de desarrollo (npm audit)

**Comando 1 (total: prod + dev):**
- `npm audit`
- Avisos totales (A): **[114]**

**Comando 2 (solo producción):**
- `npm audit --omit=dev`
- Avisos en producción (B): **[74]**

**Cálculo — parte que no llega a producción (solo dev):**
- Avisos solo dev = **A − B** = **[40]**
- Porcentaje solo dev = **((A − B) / A) × 100** = **[35,1]%**

**Conclusión:**
- Del total de avisos detectados, **[40]** (**[35.1]%**) corresponden a dependencias de desarrollo y **no deberían llegar a producción**.




## Lab 2 — Paso 3: Qué pasa sin lockfile (Trivy)

**Comandos ejecutados:**
- Con lockfile:
  - `trivy fs --scanners vuln --format table --no-progress -o con-lockfile.txt .`
- Sin lockfile:
  - `mv package-lock.json package-lock.json.bak`
  - `trivy fs --scanners vuln --format table --no-progress -o sin-lockfile.txt .`
  - `mv package-lock.json.bak package-lock.json`

**Resultados:**
- **Con lockfile (`con-lockfile.txt`)**: **Total: 167 vulnerabilidades**
- **Sin lockfile (`sin-lockfile.txt`)**: el *Report Summary* muestra `-` (**Not scanned**), es decir, **no se pudo realizar el escaneo** al faltar información para resolver dependencias/versiones.

**Comparación y explicación:**
- Con `package-lock.json`, la herramienta puede ver el **árbol de dependencias resuelto** (dependencias directas y transitivas con versiones exactas), por lo que el recuento refleja mucho mejor el **riesgo real**.
- Sin `package-lock.json`, el análisis queda **incompleto** (en este caso, directamente **no escaneado**), por lo que la cifra puede bajar artificialmente a **0 / sin resultados** aunque el riesgo siga existiendo. Esto ilustra por qué, sin lockfile, muchas herramientas (incluidas algunas usadas en entornos bancarios) pueden **subestimar** el riesgo al no ver correctamente las dependencias transitivas.

**Conclusión:**
- El lockfile es clave para obtener un reporte fiable; sin lockfile, los resultados pueden ser **engañosos** (infravaloran o no reflejan el riesgo real).


## Lab 2 — Paso 4: Dónde se corrige

**Aviso elegido (transitiva):** `braces` (`braces@2.3.2`)

**Quién la trae (npm ls):**
- `jest@26.6.3 -> @jest/core -> jest-haste-map -> sane@4.1.0 -> micromatch@3.1.10 -> braces@2.3.2`

**Corrección elegida (regla del proyecto):** corregir en el origen
- En vez de usar `overrides` para forzar `braces`, actualizar la dependencia directa que lo introduce (**`jest`**, y alinear `ts-jest` si aplica) a una versión que ya no arrastre esa rama antigua.

**Por qué:**
- `overrides` deja deuda y puede romper en ejecución; actualizar el origen es más mantenible.


**Aviso elegido (transitiva):** `zod` (GHSA-mrhx-c7xc-m3w5, `zod@3.25.76`)

**Quién la trae (npm ls):**
- `juice-shop -> web3@4.16.0 -> web3-validator@2.0.6 -> zod@3.25.76`

**Corrección elegida (regla del proyecto):** corregir en el origen
- En vez de usar `overrides` para forzar `zod`, actualizar la dependencia directa que lo introduce (**`web3`** y/o **`web3-validator`**) a una versión que ya use `zod >= 4.6.6`.

**Por qué:**
- Evita forzar versiones con `overrides`.


## Lab 3 — SAST sobre WebGoat 

| # | check_id | path | severity | clasificación | justificación (1 línea) |
|---|----------|------|----------|---------------|--------------------------|
| 1 | java.lang.security.audit.formatted-sql-string.formatted-sql-string | src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java | ERROR | Código que no se despliega (demo/lesson) | WebGoat es una app de entrenamiento y este código está en `lessons/challenges`, diseñado para ser vulnerable. |
| 2 | yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | .github/workflows/build.yml | WARNING | Real | Usar tags/branches mutables en GitHub Actions es un riesgo real de supply-chain; se debería fijar a un commit SHA. |
| 3 | java.spring.security.injection.tainted-url-host.tainted-url-host | src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java | ERROR | Código que no se despliega (demo/lesson) | Está en `lessons/jwt/...` y forma parte de un ejercicio didáctico, no de una funcionalidad “productiva”. |
| 4 | java.lang.security.audit.formatted-sql-string.formatted-sql-string | src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java | ERROR | Código que no se despliega (demo/lesson) | Está en `lessons/sqlinjection/...` y el objetivo del proyecto es mostrar SQLi de forma intencionada. |
| 5 | yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | .github/workflows/release.yml | WARNING | Real | Mismo problema: acción referenciada por tag mutable; fijar a SHA reduce el riesgo de cambios maliciosos. |











