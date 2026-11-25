# Análisis de avisos
 
| Aviso (CVE o GHSA) | Componente y versión | Cadena de dependencia | Desarrollo o producción | ¿Llega a lo desplegado? | Corrección propuesta | Por qué |
|---|---|---|---|---|---|---|
|CVE-2025-24813, CVE-2025-48988, CVE-2025-52434 | org.apache.tomcat.embed:tomcat-embed-core:9.0.124, org.apache.tomcat.embed:tomcat-embed-websocket:9.0.124 | spring-petclinic → spring-boot-starter-web:2.4.1 → spring-boot-starter-tomcat:2.4.1 → org.apache.tomcat.embed:*:9.0.124 | Producción | Sí | Fijar la propiedad tomcat.version a 9.0.124 en pom.xml (gestionada por el BOM Spring Boot) | Se evita corregir aviso a aviso y se salta directamente a la última 9.0.x estable, quedando Tomcat sin avisos en Trivy |
|CVE-2024-4068  |braces@2.3.2 |jest@26.6.3 → @jest/core → jest-haste-map → sane@4.1.0 → micromatch@3.1.10 → braces@2.3.2  |Desarrollo   |No  |Subir la dependencia directa jest y ts-jest si aplica a una versión que ya no arrastre braces@2.3.2  |La nueva versión elimina la dependencia vulnerable desde el origen, sin usar overrides |
|GHSA-mrhx-c7xc-m3w5 | zod@3.25.76 | juice-shop → web3@4.16.0 → web3-validator@2.0.6 → zod@3.25.76 | Producción | Sí | Override documentado como excepción (forzar zod >= 4.6.6 con overrides) | npm view web3-validator version devuelve 2.0.6 y npm view web3-validator@2.0.6 dependencies declara zod: ^3.21.4 (Zod 3). No existe fix upstream (no hay versión que use Zod 4), así que se elige override temporal documentado como deuda técnica y se valida con audit/trivy/tests. |


## Vulnerabilidad : Apache Tomcat embebido (dependencia vulnerable)

**Detección:** Trivy reportó vulnerabilidades en Tomcat embebido en versiones anteriores de la rama 9.0.x.

**Confirmación:** Maven muestra que la aplicación usa Tomcat embebido a través de `spring-boot-starter-web` → `spring-boot-starter-tomcat`. Tras fijar la propiedad `tomcat.version`, el árbol de dependencias resuelto queda en:

| Artefacto | Versión |
|---|---|
| `tomcat-embed-core` | `9.0.124` |
| `tomcat-embed-websocket` | `9.0.124` |

**Decisión:** En lugar de seguir corrigiendo aviso a aviso (`9.0.99` → `9.0.106` → `9.0.107`), se fijó directamente la última versión estable de la rama 9.0.x. En Maven, esto no se documenta como un “override” al estilo npm, sino como el ajuste de la propiedad `tomcat.version` gestionada por el BOM de Spring Boot.

**Corrección aplicada:** en `pom.xml` (raíz), se fijó:

- `<properties>`
- `  <tomcat.version>9.0.124</tomcat.version>`
- `</properties>`

**Validación:**
- `mvn -q -DskipTests dependency:resolve` → OK
- `mvn dependency:tree` → aparecen:
  - `org.apache.tomcat.embed:tomcat-embed-core:jar:9.0.124:compile`
  - `org.apache.tomcat.embed:tomcat-embed-websocket:jar:9.0.124:compile`
- `trivy fs --scanners vuln --pkg-types library . | grep -i tomcat` → sin resultados (0 avisos de Tomcat)

**Conclusión:** La solución final correcta es fijar `tomcat.version` a `9.0.124`, última estable de la rama 9.0.x, eliminando los avisos de Tomcat del escaneo y evitando dejar el análisis desactualizado con versiones intermedias.




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


**Aviso elegido (transitiva):** GHSA-mrhx-c7xc-m3w5 (zod@3.25.76)

**Quién la trae (npm ls):** 
- `juice-shop` → `web3@4.16.0` → `web3-validator@2.0.6` → `zod@3.25.76`

**Comprobación upstream (npm view):** 
- `web3-validator` latest es 2.0.6 y depende de `zod: ^3.21.4` (Zod 3), por lo que no hay corrección en el origen mediante actualización normal a Zod 4.

**Corrección elegida:** 
- Override documentado como excepción, forzando `zod >= 4.6.6` en package.json.

**Por qué:** 
- No existe versión upstream compatible con Zod 4; el override es temporal, se documenta como deuda técnica y requiere validación continua.

**Comandos para regenerar lockfile y validar:**

```powershell
Remove-Item -Force package-lock.json
npm install --package-lock-only --ignore-scripts
npm audit
trivy fs --scanners vuln . > con-lockfile-after.txt
```


## Lab 3 — SAST sobre WebGoat 

| # | check_id | path | severity | clasificación | justificación (1 línea) |
|---|----------|------|----------|---------------|--------------------------|
| 1 | java.lang.security.audit.formatted-sql-string.formatted-sql-string | src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java | ERROR | Código que no se despliega (demo/lesson) | WebGoat es una app de entrenamiento y este código está en `lessons/challenges`, diseñado para ser vulnerable. |
| 2 | yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | .github/workflows/build.yml | WARNING | Real | Usar tags/branches mutables en GitHub Actions es un riesgo real de supply-chain; se debería fijar a un commit SHA. |
| 3 | java.spring.security.injection.tainted-url-host.tainted-url-host | src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java | ERROR | Código que no se despliega (demo/lesson) | Está en `lessons/jwt/...` y forma parte de un ejercicio didáctico, no de una funcionalidad “productiva”. |
| 4 | java.lang.security.audit.formatted-sql-string.formatted-sql-string | src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java | ERROR | Código que no se despliega (demo/lesson) | Está en `lessons/sqlinjection/...` y el objetivo del proyecto es mostrar SQLi de forma intencionada. |
| 5 | yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | .github/workflows/release.yml | WARNING | Real | Mismo problema: acción referenciada por tag mutable; fijar a SHA reduce el riesgo de cambios maliciosos. |
