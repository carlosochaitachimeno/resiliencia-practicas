# B.2 Bitácora del agente (día 2)

| Campo | Contenido |
|---|---|
| **Alerta** | **Número:** #2 <br>**GHSA:** GHSA-9v3m-8fp8-mj99 <br>**Paquete:** org.webjars:bootstrap <br>**CVE:** CVE-2019-8331 <br>**Severidad:** Moderate (CVSS 6.1) |
| **Herramienta** | **aXet.PlugIn versión:** v3.0.0 <br>**Modelo usado:** GPT-5.4 <br>**Modo:** agente |
| **Instrucciones dadas** | Actualizar `org.webjars:bootstrap` en `pom.xml` a la versión mínima parcheada `3.4.1` para cerrar la alerta “Bootstrap Vulnerable to Cross-Site Scripting #2”. Mantener la bitácora `docs/dia2-bitacora-agente.md` completamente actualizada en cada hito, rellenando todos los campos y sin inventar datos no disponibles. |
| **Plan propuesto** | **Resumen del plan:** 1. Cambiar `webjars-bootstrap.version` de `3.4.0` a `3.4.1`. <br>2. Actualizar la bitácora con datos de alerta, herramienta, plan y riesgos. <br>3. Ejecutar verificación Maven y registrar resultados reales. <br>4. Hacer commit, push a `practicas` y abrir PR hacia `lab8-agente-recrear-alerta`. <br>**¿Aprobado a la primera?:** sí <br>**Si no, ¿qué corregiste/pediste cambiar?:** No hubo cambios al plan inicial. |
| **Cambios aplicados** | **Ficheros tocados:** `pom.xml`, `docs/dia2-bitacora-agente.md` <br>**Resumen:** actualización mínima de Bootstrap vulnerable a la versión parcheada y documentación completa del proceso en la bitácora. <br>**Mini-diff:** `webjars-bootstrap.version 3.4.0 -> 3.4.1` |
| **Verificación** | **`./mvnw verify`:** BUILD SUCCESS <br>**Tests:** 40 tests, 0 fallos, 0 errores, 1 omitido. <br>**Re-escaneo (trivy):** No ejecutado (no requerido / no disponible). <br>**Pipeline:** No aplica / no ejecutado. <br>**Estado final de la alerta:** Fixed (cerrada por PR #3, 19/11/2026). |
| **Errores o riesgos** | Se evitó saltar a Bootstrap 5.0.0 para no introducir breaking changes innecesarios. Se limita el cambio a la versión mínima parcheada `3.4.1`. Se evitará incluir en commit ficheros no relacionados con la alerta y la bitácora. Se observan avisos de JaCoCo con Java 21, pero al no romper `verify` se documentan como riesgo técnico aparte y no como bloqueo de este cambio. |
| **Tiempos** | **Análisis:** 10 min estimado <br>**Cambio:** 5 min estimado <br>**Verificación:** 5 min estimado <br>**PR y cierre:** 10 min estimado <br>**(Añadir también los tiempos del Lab 5):** No aplica |
| **Consumo** | No disponible |
| **Conclusión** | 1) El cambio mínimo en `pom.xml` es suficiente para abordar la alerta indicada. <br>2) Mantener la bitácora actualizada por hitos mejora la trazabilidad del trabajo. <br>3) Verificar antes de abrir la PR reduce el riesgo de propagar un cambio incorrecto. |


## Evidencias / Entregables

- PR Lab 5 (mergeada): https://github.com/carlosochaitachimeno/resiliencia-practicas/pull/2
- PR Lab 8 (mergeada): https://github.com/carlosochaitachimeno/resiliencia-practicas/pull/4



## Lab 6 · Secretos — Respuesta

1) **¿Por qué el segundo escaneo sigue encontrando el secreto?**  
Porque el secreto quedó registrado en el historial de Git (en el commit donde se añadió y/o en los diffs). Aunque se borre el archivo en un commit posterior, el contenido sigue existiendo en commits anteriores, y gitleaks escanea el historial.

2) **¿Por qué borrarlo no basta y quién tiene que rotarlo?**  
Borrarlo del último commit no basta porque cualquiera con acceso al repositorio puede recuperar el secreto desde el historial. Al haberse expuesto, hay que rotar/revocar el secreto. La rotación la hace el propietario del secreto en el sistema que lo emite (AWS/GitHub/proveedor), no Git.

3) **¿Qué cambiarías para que no vuelva a pasar?**  
- Usar un gestor de secretos o variables de entorno (no almacenar credenciales en el repositorio; como mucho un archivo `.example` sin secretos).  
- Añadir una regla antes del commit (pre-commit hook) para ejecutar gitleaks y bloquear commits si detecta secretos.
