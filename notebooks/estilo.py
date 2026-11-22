"""Estilo común de los gráficos de los notebooks y del informe."""

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parents[1]
FIGURAS = BASE / "informe" / "figuras"

SUPERFICIE = "#fcfcfb"
TEXTO = "#0b0b0b"
TEXTO_2 = "#52514e"
REJILLA = "#e4e3df"
AZUL, NARANJA, AQUA, AMARILLO, MAGENTA, VERDE, VIOLETA, ROJO = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
SERIES = [AZUL, NARANJA, AQUA, AMARILLO, MAGENTA, VERDE, VIOLETA, ROJO]
SEGURO, VULNERABLE = AZUL, NARANJA


def aplicar():
    mpl.rcParams.update({
        "figure.facecolor": SUPERFICIE, "axes.facecolor": SUPERFICIE, "savefig.facecolor": SUPERFICIE,
        "axes.edgecolor": REJILLA, "axes.labelcolor": TEXTO_2, "axes.titlecolor": TEXTO,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.labelsize": 10,
        "xtick.color": TEXTO_2, "ytick.color": TEXTO_2, "xtick.labelsize": 9, "ytick.labelsize": 9,
        "axes.grid": True, "grid.color": REJILLA, "grid.linewidth": 0.6, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False, "legend.fontsize": 9,
        "font.family": "DejaVu Sans", "figure.dpi": 110, "savefig.dpi": 200, "savefig.bbox": "tight",
    })


def guardar(fig, nombre):
    FIGURAS.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURAS / f"{nombre}.png")


def etiquetar_barras(ax, barras, formato="{:,.0f}", horizontal=False):
    for b in barras:
        valor = b.get_width() if horizontal else b.get_height()
        if valor <= 0:
            continue
        if horizontal:
            ax.annotate(formato.format(valor).replace(",", "."), (valor, b.get_y() + b.get_height() / 2),
                        xytext=(3, 0), textcoords="offset points", va="center", fontsize=8, color=TEXTO_2)
        else:
            ax.annotate(formato.format(valor).replace(",", "."), (b.get_x() + b.get_width() / 2, valor),
                        xytext=(0, 2), textcoords="offset points", ha="center", fontsize=8, color=TEXTO_2)
