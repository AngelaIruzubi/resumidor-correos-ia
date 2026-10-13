"""Ejecuta todos los correos de ejemplo en ambos modos y compara resultados.

Uso:
    python evaluar.py
    python evaluar.py --proveedor anthropic
"""

import argparse
import sys
from pathlib import Path

from resumidor import crear_cliente, resumir_seguro, resumir_vulnerable, secreto_filtrado

CARPETA_EJEMPLOS = Path(__file__).parent / "ejemplos"


def main():
    parser = argparse.ArgumentParser(description="Compara ambos modos con todos los ejemplos.")
    parser.add_argument("--proveedor", choices=["ollama", "anthropic"], default="ollama")
    args = parser.parse_args()

    modos = {"vulnerable": resumir_vulnerable, "seguro": resumir_seguro}

    try:
        cliente = crear_cliente(args.proveedor)
        print(f"{'correo':<28}{'modo':<12}{'¿secreto filtrado?':<20}{'¿inyección detectada?'}")
        print("-" * 82)
        for archivo in sorted(CARPETA_EJEMPLOS.glob("*.txt")):
            correo = archivo.read_text(encoding="utf-8")
            for nombre, funcion in modos.items():
                resultado = funcion(cliente, correo)
                filtrado = "SÍ ⚠️" if secreto_filtrado(resultado) else "no"
                detectada = resultado["posible_inyeccion"]
                detectada = "-" if detectada is None else ("sí" if detectada else "no")
                print(f"{archivo.name:<28}{nombre:<12}{filtrado:<20}{detectada}")
    except RuntimeError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
