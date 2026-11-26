### Lab 8 — Plantilla B.2 (alerta corregida con aXet.PlugIn)

| Campo | Contenido |
|---|---|
| **Alerta** | **Número:** #16 <br>**GHSA:** GHSA-36p3-wjmg-h94x <br>**CVE:** CVE-2022-22965 <br>**Paquete:** org.springframework.boot:spring-boot-starter-web (Maven) <br>**Descripción:** Remote Code Execution in Spring Framework (Spring4Shell) <br>**Affected versions:** `< 2.5.12` <br>**Patched version:** `2.5.12` <br>**Estado final:** Fixed (cerrada por Dependabot como *completed*) |
| **Herramienta** | **aXet.PlugIn (versión):** v3.0.0 <br>**Modelo usado:** Auto-selected: GPT-4o (según logs del entorno) <br>**Modo:** agente (con ejecución de comandos) + revisión humana |
| **Instrucciones dadas** | “En este repositorio hay una alerta de Dependabot sobre Spring4Shell (GHSA-36p3-wjmg-h94x). 1) Analiza de dónde viene la dependencia y si llega al artefacto desplegado. 2) Propón un plan de corrección en el origen, sin overrides ni exclusiones si se puede evitar. 3) No modifiques ningún fichero hasta que yo apruebe el plan. 4) Cuando lo apruebe: aplica el cambio, ejecuta `./mvnw verify` y vuelve a escanear con Trivy. 5) Resume qué has cambiado y cómo lo has verificado.” |
| **Plan propuesto** | **Resumen:** actualizar la dependencia en el origen elevando el *parent* de Spring Boot (cambio mínimo, sin overrides/exclusions) de `2.4.1` a `2.5.12` para cerrar GHSA-36p3-wjmg-h94x / CVE-2022-22965. <br>**Aprobación humana #1 (antes de tocar código):** Sí (aprobación explícita antes de hacer `git add/commit`). <br>**Qué se corrigió/revisó:** se evitó usar comandos que colgaban la terminal (usar `git --no-pager ...`) y se controló manualmente el alcance del commit para no incluir ficheros `??` no relacionados. |
| **Cambios aplicados** | **Fichero:** `pom.xml` <br>**Cambio:** `spring-boot-starter-parent` `2.4.1 → 2.5.12` <br>**Evidencia (commits del PR):** <br>- “Lab8: reproducir alerta Dependabot (bootstrap 2.3.2 temporalmente)” <br>- “Upgrade Spring Boot parent to 2.5.12 (CVE-2022-22965)” |
| **Verificación** | **Build/Tests (local):** BUILD SUCCESS (ejecutado con JDK 8 para evitar errores de instrumentación de JaCoCo con JDK 17/21). Evidencia: verify-lab8-after-java8.txt. <br>**Trivy (after):** Ejecutado y completado. Total: 96 (UNKNOWN: 0, LOW: 9, MEDIUM: 40, HIGH: 35, CRITICAL: 12). No aparece GHSA-36p3-wjmg-h94x ni CVE-2022-22965 en el reporte. Evidencia: trivy-lab8-after.txt. <br>**Pipeline/checks (GitHub):** en verde (checks pasaron en el PR). <br>**Estado alerta Dependabot:** Fixed / cerrada como completed. <br>**PR Dependabot #1:** cerrada. <br>**Evidencia:** salidas capturadas en `verify-lab8-after-java8.txt` (./mvnw verify) y `trivy-lab8-after.txt` (Trivy). |
| **Errores o riesgos** | **Riesgo si no hay revisión humana:** el agente podía incluir en el commit ficheros no trackeados (`alertas.json`, `trivy-before.txt`, etc.) si se hubiese usado `git add .`. Se mitigó con control humano usando `git add pom.xml`. <br>**Riesgo del entorno:** con JDK 17/21 se observaron errores de JaCoCo (“Unsupported class file major version 61/65”); se mitigó ejecutando verify con JDK 8 sin cambiar el código del proyecto. <br>**Trazabilidad:** se capturaron salidas de verify y Trivy como evidencia (verify-lab8-after-java8.txt, trivy-lab8-after.txt). |
| **Tiempos** | **Fase 1 — Análisis (agente propone plan):** 08:05 <br>**Fase 2 — Cambio:** 12:58 <br>**Fase 3 — Verificación:** 14:58 <br>**Fase 4 — PR y cierre:** 19:01 |
| **Consumo** | No disponible |
| **Conclusión** | 1) El agente acelera la identificación de la corrección mínima (upgrade en el origen) y reduce la fricción operativa. <br>2) Hace falta una persona para aprobar el plan y controlar el alcance (evitar cambios colaterales y commits con ficheros extra). <br>3) Antes de fusionar, una segunda revisión humana y checks en verde dan la confianza final (y evidencian el cierre de la alerta). |

**Aprobación humana #2 (antes de fusionar):** Sí (review/approve en el PR y merge solo con checks en verde).




PR Lab 5 (Merged): PR #2 — “Sube bootstrap a 3.4.1…” → https://github.com/carlosochaitachimeno/resiliencia-practicas/pull/2
PR Lab 8 (Merged): PR #? — “Upgrade Spring Boot parent to 2.5.12…” → https://github.com/carlosochaitachimeno/resiliencia-practicas/pull/10
PR Dependabot #1 (Closed): https://github.com/carlosochaitachimeno/resiliencia-practicas/pull/1 




# Lab6 · Secretos – Respuesta

## 1) ¿Por qué el segundo escaneo sigue encontrando el secreto?
Porque el secreto quedó registrado en el historial de Git (en el commit donde se añadió y/o en los diffs). Aunque se borre el archivo en un commit posterior, el contenido sigue existiendo en commits anteriores, y gitleaks escanea el historial.

## 2) ¿Por qué borrarlo no basta y quién tiene que rotarlo?
Borrarlo del último commit no basta porque cualquiera con acceso al repositorio puede recuperar el secreto desde el historial. Al haberse expuesto, hay que rotar/revocar el secreto. La rotación la hace el propietario del secreto en el sistema que lo emite (AWS/GitHub/proveedor), no Git.

## 3) ¿Qué cambiarías para que no vuelva a pasar?
- Usar un gestor de secretos o variables de entorno (no almacenar credenciales en el repositorio; como mucho un archivo `.example` sin secretos).
- Añadir una regla antes del commit (pre-commit hook) para ejecutar gitleaks y bloquear commits si detecta secretos.
