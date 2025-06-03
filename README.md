# Escanear archivos con VirusTotal

Este proyecto permite aprovechar la API de VirusTotal para escanear los archivos contenidos en un directorio y detectar contenido malicioso. El escaneo se realiza de forma asíncrona para archivos individuales o directorios completos. Proporciona informes detallados por archivo y un resumen general del análisis.

### Requisitos: 

- Python 3.7 o superior.
- API key de VirusTotal (gratuita o premium).
- Conexión a internet.

### Limitaciones:

- Tasa límite de la API gratuita: 4 solicitudes por minuto. El script incluye un delay de 15 segundos entre archivos para cumplir con los límites de la API gratuita.
- Tamaño máximo por archivo: 650MB (límite de VirusTotal).


### Uso:

- Modifica la ruta del DIRECTORIO_A_ESCANEAR.
- Modifica API_KEY_VIRUSTOTAL con tu propia API key.
- Ejecuta escaner_virusTotal.py


Si te resulta de utilidad déjame una estrella ⭐


### Ejemplo de salida:

==================================================
Reporte para: archivo_sospechoso.exe
SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Tamaño: 256.00 KB

Estadísticas:
• Maliciosos: 12
• Sospechosos: 3
• Inofensivos: 25

Cobertura de análisis:
• Total motores: 68
• Motores que lo analizaron: 40
• Porcentaje de detección: 37.5%

Motores de detección que encontraron amenazas:
- Kaspersky: Trojan.Win32.Generic
- BitDefender: Gen:Variant.Razy.123456
- ESET-NOD32: Win32/TrojanDropper.Agent.NEQ
...

==================================================
Resumen del escaneo:
Archivos procesados: 15
Archivos con amenazas: 3
Archivos no infectados: 12

Tiempo total de escaneo: 245.32 segundos