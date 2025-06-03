# -*- coding: utf-8 -*-
"""
Created on Sat May 10 20:36:28 2025

@author: gabroliveros
"""

import vt
import time
import os
import asyncio
from pathlib import Path
import nest_asyncio
nest_asyncio.apply()

class VirusTotalScanner:
    def __init__(self, api_key):
        self.client = vt.Client(api_key)
        self.scan_results = []
        self.malicious_count = 0

    async def scan_file(self, file_path):
        """Envía un archivo a VirusTotal para su análisis (versión asíncrona)"""
        try:
            with open(file_path, "rb") as f:
                print(f"\nEscaneando: {file_path}...")
                analysis = await self.client.scan_file_async(f, wait_for_completion=True)
                return analysis
        except vt.APIError as e:
            print(f"Error API: {e}")
            return None
        except Exception as e:
            print(f"Error general: {e}")
            return None

    def generate_report(self, analysis, file_path):
        """Genera un reporte detallado del análisis"""
        if not analysis or not hasattr(analysis, "stats"):
            print(f"Error: Análisis inválido para {file_path}")
            return None
    
        try:
            report = {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "size": f"{os.path.getsize(file_path)/1024:.2f} KB",
                "sha256": analysis.sha256 if hasattr(analysis, "sha256") else "N/A",
                "malicious": analysis.stats.get("malicious", 0),
                "suspicious": analysis.stats.get("suspicious", 0),
                "undetected": analysis.stats.get("undetected", 0),
                "harmless": analysis.stats.get("harmless", 0),
                "engines": {}
            }
    
            if hasattr(analysis, "results"):
                for engine, result in analysis.results.items():
                    report["engines"][engine] = {
                        "category": result.get("category", "Unknown"),
                        "result": result.get("result", "No result"),
                        "method": result.get("method", "Unknown"),
                        "engine_version": result.get("engine_version", "Unknown")
                    }
    
            self.scan_results.append(report)
            if report["malicious"] > 0:
                self.malicious_count += 1
    
            return report
    
        except Exception as e:
            print(f"Error generando reporte: {str(e)}")
            return None

    def print_detailed_report(self, report):
        """Imprime un reporte detallado en consola
        
        Si SHA-256: N/A
            - El análisis no se completó correctamente
            - VirusTotal no devolvió el hash (poco común)
            - Hay un retraso en el procesamiento del archivo
        """
        print(f"\n{'='*50}")
        print(f"Reporte para: {report['filename']}")
        print(f"SHA-256: {report['sha256']}")
        print(f"Tamaño: {report['size']}")
        print("\nEstadísticas:")
        print(f"• Maliciosos: {report['malicious']}")
        print(f"• Sospechosos: {report['suspicious']}")
        print(f"• Inofensivos: {report['harmless']}")
        print("\nCobertura de análisis:")
        print(f"• Total motores: {report['malicious'] + report['suspicious'] + report['harmless'] + report['undetected']}")
        print(f"• Motores que lo analizaron: {report['undetected'] + report['malicious'] + report['suspicious']}")
        print(f"• Porcentaje de detección: {(report['malicious'] + report['suspicious'])*100/(report['undetected'] + report['malicious'] + report['suspicious']):.1f}%")

        if report["malicious"] > 0:
            print("\nMotores de detección que encontraron amenazas:")
            for engine, result in report["engines"].items():
                if result["category"] == "malicious":
                    print(f"- {engine}: {result['result']}")

    def print_summary(self, file_count):
        """Imprime un resumen general del escaneo"""
        print("\n\n" + "="*50)
        print("Resumen del escaneo:")
        print(f"Archivos procesados: {file_count}")
        print(f"Archivos con amenazas: {self.malicious_count}")
        print(f"Archivos no infectados: {file_count - self.malicious_count}")

    async def scan_directory(self, directory_path):
        """Escanea todos los archivos en un directorio (versión asíncrona)"""
        start_time = time.time()
        file_count = 0
        
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) > 650 * 1024 * 1024:
                        print(f"\nArchivo muy grande, omitiendo: {file_path}")
                        continue
                    
                    analysis = await self.scan_file(file_path)
                    if analysis:
                        report = self.generate_report(analysis, file_path)
                        if report:
                            self.print_detailed_report(report)
                            file_count += 1
                    
                    await asyncio.sleep(15)
        
        finally:
            await self.client.close_async()
            total_time = time.time() - start_time
            print(f"\nTiempo total de escaneo: {total_time:.2f} segundos")
            self.print_summary(file_count)  # Aquí está el cambio clave

async def main():
    DIRECTORIO_A_ESCANEAR = r"C:\Users\MACHINE\Downloads\prueba_vt"
    API_KEY_VIRUSTOTAL = "tu_api_key_aqui"
    
    if not Path(DIRECTORIO_A_ESCANEAR).is_dir():
        print(f"Error: El directorio {DIRECTORIO_A_ESCANEAR} no existe")
        return

    try:
        scanner = VirusTotalScanner(API_KEY_VIRUSTOTAL)
        await scanner.scan_directory(DIRECTORIO_A_ESCANEAR)
    except KeyboardInterrupt:
        print("\nEscaneo cancelado por el usuario")
    except Exception as e:
        print(f"\nError inesperado: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
