"""Modelo de minería de datos de vulnminer (fases MODIFY y MODEL).

Representación de cada unidad (pipeline reproducible):
  1. TF-IDF de tokens de código (unigramas y bigramas) sobre el código limpio y neutralizado.
  2. TF-IDF de n-gramas de caracteres (3 a 5), que capta diferencias como
     ``execute(sql + x)`` frente a ``execute(sql, (x,))``.
  3. Características de seguridad del análisis estático (vulnminer/caracteristicas.py),
     escaladas al rango [-1, 1].

Componentes aprendidos (todos supervisados):
  - detector:      clasificación binaria vulnerable / no vulnerable.
  - categorizador: clasificación multietiqueta en las categorías OWASP Top 10:2025 y
                   OWASP API Security Top 10:2023 (una o varias por unidad).
  - cwe:           clasificación multiclase del CWE más probable (descripción y recomendación).

Las reglas de análisis estático solo aportan variables y evidencias; la decisión y las
categorías las determina el modelo entrenado.
"""

import json
from dataclasses import dataclass, field

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin, clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, MaxAbsScaler
from sklearn.svm import LinearSVC

from . import caracteristicas as C
from .catalogo import API2023, OWASP2025
from .lexico import preparar, tokenizar_preparado
from .segmentacion import Unidad

CATEGORIAS = list(OWASP2025) + list(API2023)


# ---------------------------------------------------------------------------------------------
# Representación (MODIFY)
# ---------------------------------------------------------------------------------------------
def a_unidades(X):
    """Acepta una lista de Unidad o un DataFrame con las columnas del dataset."""
    if isinstance(X, pd.DataFrame):
        unidades = []
        for r in X.itertuples(index=False):
            meta = getattr(r, "meta", "") or "{}"
            meta = json.loads(meta) if isinstance(meta, str) else dict(meta)
            unidades.append(Unidad(getattr(r, "archivo", ""), r.lenguaje, r.subtipo, getattr(r, "unidad", ""),
                                   [], r.codigo, getattr(r, "contexto", "") or "", meta))
        return unidades
    return list(X)


def _textos(X):
    return [preparar(u.texto) for u in a_unidades(X)]


def _caracteristicas(X):
    return sparse.csr_matrix(np.vstack([C.vector(u) for u in a_unidades(X)]))


class Textos(BaseEstimator, TransformerMixin):
    """Convierte las unidades al texto preparado (limpio y neutralizado)."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return _textos(X)


def representacion(max_tokens=60000, max_caracteres=60000, peso_caracteristicas=1.0):
    tokens = Pipeline([("texto", Textos()),
                       ("tfidf", TfidfVectorizer(tokenizer=tokenizar_preparado, token_pattern=None, lowercase=False,
                                                 ngram_range=(1, 2), min_df=2, max_df=0.9, max_features=max_tokens,
                                                 sublinear_tf=True, dtype=np.float32))])
    caracteres = Pipeline([("texto", Textos()),
                           ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_df=0.9,
                                                     max_features=max_caracteres, sublinear_tf=True, dtype=np.float32))])
    seguridad = Pipeline([("indicadores", FunctionTransformer(_caracteristicas, validate=False)),
                          ("escala", MaxAbsScaler())])
    return FeatureUnion([("tokens", tokens), ("caracteres", caracteres), ("seguridad", seguridad)],
                        transformer_weights={"tokens": 1.0, "caracteres": 1.0, "seguridad": peso_caracteristicas})


def nombres_representacion(repr_ajustada):
    tok = repr_ajustada.transformer_list[0][1].named_steps["tfidf"].get_feature_names_out()
    car = repr_ajustada.transformer_list[1][1].named_steps["tfidf"].get_feature_names_out()
    return ([f"tok:{t}" for t in tok] + [f"car:{c}" for c in car] + [f"seg:{n}" for n in C.nombres_caracteristicas()])


# ---------------------------------------------------------------------------------------------
# Algoritmos comparados (MODEL)
# ---------------------------------------------------------------------------------------------
def _densa(X):
    return X.toarray() if sparse.issparse(X) else X


def crear_clasificador(algoritmo, **p):
    """Clasificador binario sobre la matriz de representación."""
    if algoritmo == "regresion_logistica":
        return LogisticRegression(C=p.get("C", 4.0), class_weight="balanced", max_iter=5000, solver="liblinear")
    if algoritmo == "svm_lineal":
        return CalibratedClassifierCV(LinearSVC(C=p.get("C", 0.5), class_weight="balanced", max_iter=20000),
                                      cv=StratifiedKFold(3, shuffle=True, random_state=42))
    if algoritmo == "random_forest":
        return Pipeline([("seleccion", SelectKBest(chi2, k=p.get("k", 4000))),
                         ("rf", RandomForestClassifier(n_estimators=p.get("n_estimators", 400), max_features=p.get("max_features", "sqrt"),
                                                       min_samples_leaf=p.get("min_samples_leaf", 1), class_weight="balanced_subsample",
                                                       n_jobs=-1, random_state=42))])
    if algoritmo == "gradient_boosting":
        return Pipeline([("svd", TruncatedSVD(n_components=p.get("componentes", 200), random_state=42)),
                         ("hgb", HistGradientBoostingClassifier(learning_rate=p.get("learning_rate", 0.1),
                                                                max_leaf_nodes=p.get("max_leaf_nodes", 31),
                                                                max_iter=p.get("max_iter", 300), class_weight="balanced",
                                                                random_state=42))])
    raise ValueError(algoritmo)


REJILLAS = {
    "regresion_logistica": [{"C": c} for c in (2.0, 8.0, 32.0, 128.0)],
    "svm_lineal": [{"C": c} for c in (0.2, 1.0, 4.0)],
    "random_forest": [{"k": k, "n_estimators": 400, "min_samples_leaf": m} for k in (3000, 8000) for m in (1, 2)],
    "gradient_boosting": [{"componentes": 200, "learning_rate": lr, "max_leaf_nodes": h} for lr in (0.05, 0.1) for h in (31, 63)],
}
NOMBRES_ALGORITMO = {"regresion_logistica": "Regresión logística", "svm_lineal": "SVM lineal (calibrada)",
                     "random_forest": "Random Forest", "gradient_boosting": "Gradient Boosting (HistGB + SVD)"}


def crear_multietiqueta(algoritmo, **p):
    base = crear_clasificador(algoritmo, **p)
    if algoritmo == "random_forest":
        # el bosque admite multietiqueta de forma nativa, pero la selección chi2 no: se envuelve
        return OneVsRestClassifier(base, n_jobs=1)
    return OneVsRestClassifier(base, n_jobs=-1 if algoritmo != "svm_lineal" else 1)


def probabilidades(modelo, X):
    p = modelo.predict_proba(X)
    if isinstance(p, list):
        p = np.column_stack([q[:, 1] for q in p])
    return p


# ---------------------------------------------------------------------------------------------
# Modelo completo
# ---------------------------------------------------------------------------------------------
@dataclass
class ModeloVulnminer:
    representacion: object
    detector: object
    categorizador: object
    clasificador_cwe: object
    categorias: list                       # categorías con clasificador entrenado
    umbral: float = 0.5
    umbrales_categoria: dict = field(default_factory=dict)
    umbral_cwe: float = 0.35
    algoritmo_detector: str = ""
    algoritmo_categorias: str = ""
    no_evaluadas: dict = field(default_factory=dict)   # categoría -> motivo
    metadatos: dict = field(default_factory=dict)

    # ----- inferencia -----
    def transformar(self, unidades):
        return self.representacion.transform(unidades)

    def probabilidad(self, unidades=None, X=None):
        X = self.transformar(unidades) if X is None else X
        return self.detector.predict_proba(X)[:, 1]

    def probabilidad_categorias(self, unidades=None, X=None):
        X = self.transformar(unidades) if X is None else X
        return probabilidades(self.categorizador, X)

    def probabilidad_cwe(self, unidades=None, X=None):
        X = self.transformar(unidades) if X is None else X
        return self.clasificador_cwe.predict_proba(X)

    def predecir(self, unidades, umbral=None):
        """Predicción completa para una lista de unidades."""
        umbral = self.umbral if umbral is None else umbral
        if not unidades:
            return []
        X = self.transformar(unidades)
        p = self.probabilidad(X=X)
        pc = self.probabilidad_categorias(X=X)
        pw = self.probabilidad_cwe(X=X)
        clases_cwe = list(self.clasificador_cwe.classes_)
        salida = []
        for i in range(len(unidades)):
            cats = [(c, float(pc[i, k])) for k, c in enumerate(self.categorias)
                    if pc[i, k] >= self.umbrales_categoria.get(c, 0.5)]
            cats.sort(key=lambda t: -t[1])
            j = int(np.argmax(pw[i]))
            cwe = clases_cwe[j] if pw[i, j] >= self.umbral_cwe else None
            salida.append({
                "probabilidad": float(p[i]),
                "vulnerable": bool(p[i] >= umbral),
                "owasp2025": [(c, q) for c, q in cats if c in OWASP2025],
                "api2023": [(c, q) for c, q in cats if c in API2023],
                "cwe": cwe, "probabilidad_cwe": float(pw[i, j]),
                "categoria_sugerida": (self.categorias[int(np.argmax(pc[i]))], float(pc[i].max())),
            })
        return salida

    def lineas_relevantes(self, unidad, max_lineas=3):
        """Oclusión: líneas cuya eliminación más reduce la probabilidad de vulnerabilidad."""
        lineas = unidad.texto.splitlines()
        if len(lineas) <= 1:
            return [(unidad.linea_inicio, 0.0)]
        variantes = []
        for k in range(len(lineas)):
            texto = "\n".join(l for j, l in enumerate(lineas) if j != k)
            variantes.append(Unidad(unidad.archivo, unidad.lenguaje, unidad.subtipo, unidad.nombre, [], texto,
                                    unidad.contexto, unidad.meta))
        base = self.probabilidad([unidad])[0]
        p = self.probabilidad(variantes)
        caida = base - p
        orden = np.argsort(-caida)
        nums = unidad.lineas or list(range(1, len(lineas) + 1))
        return [(nums[k], float(caida[k])) for k in orden[:max_lineas] if lineas[k].strip()]

    # ----- persistencia -----
    def guardar(self, ruta):
        joblib.dump(self, ruta, compress=3)

    @staticmethod
    def cargar(ruta):
        return joblib.load(ruta)
