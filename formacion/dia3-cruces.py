import json

# Cargar las alertas de Dependabot.
with open("alertas.json", encoding="utf-16") as archivo:
    paginas = json.load(archivo)

# Unir las páginas descargadas con --slurp.
alertas = [alerta for pagina in paginas for alerta in pagina]

avisos_dependabot = {
    alerta["security_advisory"]["ghsa_id"]
    for alerta in alertas
    if alerta.get("security_advisory", {}).get("ghsa_id")
}

# Cargar los hallazgos de Trivy.
with open("trivy.json", encoding="utf-8") as archivo:
    datos_trivy = json.load(archivo)

hallazgos = [
    vulnerabilidad
    for resultado in datos_trivy.get("Results", [])
    for vulnerabilidad in resultado.get("Vulnerabilities", []) or []
]

avisos_trivy = {
    hallazgo["VulnerabilityID"]
    for hallazgo in hallazgos
    if hallazgo.get("VulnerabilityID")
}

print("Dependabot")
print("  Alertas totales:", len(alertas))
print("  Avisos distintos:", len(avisos_dependabot))

print("\nTrivy")
print("  Hallazgos:", len(hallazgos))
print("  Identificadores distintos:", len(avisos_trivy))


avisos_por_paquete = {}

for hallazgo in hallazgos:
    paquete = hallazgo.get("PkgName")
    identificador = hallazgo.get("VulnerabilityID")

    if paquete and identificador:
        avisos_por_paquete.setdefault(paquete, set()).add(identificador)

top_cinco = sorted(
    avisos_por_paquete.items(),
    key=lambda elemento: (-len(elemento[1]), elemento[0])
)[:5]

print("\nCinco paquetes con más avisos distintos:")
for paquete, avisos in top_cinco:
    print(f"  {paquete}: {len(avisos)}")



# Comparar los identificadores de Dependabot con los de Trivy.
ids_trivy_coincidentes = set()
avisos_coincidentes = 0
avisos_sin_coincidencia = 0

print("\nComparación de avisos:")

for alerta in alertas:
    aviso = alerta.get("security_advisory") or {}
    ghsa = aviso.get("ghsa_id", "Sin GHSA")

    # Reunir los identificadores disponibles para este aviso.
    identificadores = {ghsa}

    if aviso.get("cve_id"):
        identificadores.add(aviso["cve_id"])

    for identificador in aviso.get("identifiers") or []:
        if identificador.get("value"):
            identificadores.add(identificador["value"])

    coincidencias = identificadores & avisos_trivy

    if coincidencias:
        avisos_coincidentes += 1
        ids_trivy_coincidentes.update(coincidencias)
        print(f"  {ghsa}: coincide con {', '.join(sorted(coincidencias))}")
    else:
        avisos_sin_coincidencia += 1
        print(f"  {ghsa}: sin coincidencia identificada en Trivy")

print("\nResumen del cruce:")
print("  Avisos de Dependabot con coincidencia:", avisos_coincidentes)
print("  Avisos de Dependabot sin coincidencia identificada:", avisos_sin_coincidencia)
print(
    "  Identificadores de Trivy sin coincidencia identificada:",
    len(avisos_trivy - ids_trivy_coincidentes)
)



# Crear un mapa de identificadores equivalentes.
equivalencias = {}

for alerta in alertas:
    aviso = alerta.get("security_advisory") or {}
    ghsa = aviso.get("ghsa_id")

    if not ghsa:
        continue

    ids = {ghsa}

    if aviso.get("cve_id"):
        ids.add(aviso["cve_id"])

    for identificador in aviso.get("identifiers") or []:
        if identificador.get("value"):
            ids.add(identificador["value"])

    for identificador in ids:
        equivalencias[identificador.upper()] = ghsa.upper()


def aviso_canonico(identificador):
    identificador = identificador.upper()
    return equivalencias.get(identificador, identificador)


# Reunir avisos de ambas fuentes por paquete.
avisos_combinados = {}

for alerta in alertas:
    dependencia = alerta.get("dependency") or {}
    paquete = (dependencia.get("package") or {}).get("name")
    ghsa = (alerta.get("security_advisory") or {}).get("ghsa_id")

    if paquete and ghsa:
        avisos_combinados.setdefault(paquete.lower(), set()).add(
            aviso_canonico(ghsa)
        )

for hallazgo in hallazgos:
    paquete = hallazgo.get("PkgName")
    identificador = hallazgo.get("VulnerabilityID")

    if paquete and identificador:
        avisos_combinados.setdefault(paquete.lower(), set()).add(
            aviso_canonico(identificador)
        )

top_combinado = sorted(
    avisos_combinados.items(),
    key=lambda elemento: (-len(elemento[1]), elemento[0])
)[:5]

print("\nCinco paquetes con más avisos entre ambas fuentes:")
for paquete, avisos in top_combinado:
    print(f"  {paquete}: {len(avisos)}")



# Listar los identificadores sin coincidencia identificada.
avisos_dep_canonicos = {
    aviso_canonico(aviso) for aviso in avisos_dependabot
}

avisos_trivy_canonicos = {
    aviso_canonico(aviso) for aviso in avisos_trivy
}

solo_dependabot = sorted(
    aviso for aviso in avisos_dependabot
    if aviso_canonico(aviso) not in avisos_trivy_canonicos
)

solo_trivy = sorted(
    aviso for aviso in avisos_trivy
    if aviso_canonico(aviso) not in avisos_dep_canonicos
)

print("\n### Avisos solo en Dependabot")
for aviso in solo_dependabot:
    print(f"- `{aviso}`")

print("\n### Identificadores solo en Trivy")
for aviso in solo_trivy:
    print(f"- `{aviso}`")


print("\n### Avisos de Dependabot (6)\n")

for alerta in alertas:
    aviso = alerta.get("security_advisory") or {}
    ghsa = aviso.get("ghsa_id")

    if ghsa:
        print(f"- `{ghsa}`")

print("\n### Identificadores de Trivy (148)\n")

for identificador in sorted(avisos_trivy):
    print(f"- `{identificador}`")


