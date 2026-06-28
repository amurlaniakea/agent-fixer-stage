#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Capa 2.5 — Scope Drift Detection.

Compara el output del agente con el scope original de la tarea
usando TF-IDF + cosine similarity (ligero, sin dependencias pesadas).

Si el output tiene baja similitud con el scope, se genera una alerta
de scope drift que puede elevar el score o forzar reject.

Diseño:
- Reutiliza TfidfEmbedder de layer2_embeddings (sin código duplicado)
- Se ejecuta solo si scope no está vacío y mode != "fast"
- Umbral configurable (default 0.35)
- Retorna (is_drifted: bool, similarity: float, reason: str)
"""

import re
import math
from collections import Counter
from typing import Optional


class ScopeDriftDetector:
    """
    Detecta si el output del agente se desvía del scope original.

    Usa TF-IDF + cosine similarity para medir semántica.
    No requiere modelos externos — todo en stdlib.
    """

    def __init__(self, threshold: float = 0.35):
        """
        Args:
            threshold: similitud mínima para considerar "en scope".
                       Valores más bajos son más permisivos.
                       Default 0.35 (balance entre falsos positivos y drift real).
        """
        self.threshold = threshold
        self._vocab = {}
        self._idf = {}
        self._fitted = False

    def _tokenize(self, text: str) -> list:
        """Tokenización simple, multiidioma (soporta acentos)."""
        text = text.lower()
        # Mantener letras con acentos (español, francés, alemán, etc.)
        text = re.sub(r'[^\w\s]', ' ', text)
        return text.split()

    def _build_vocabulary(self, documents: list):
        """Construye vocabulario e IDF a partir de documentos."""
        n_docs = len(documents)
        df = Counter()

        for doc in documents:
            tokens = set(self._tokenize(doc))
            for token in tokens:
                df[token] += 1

        self._idf = {
            token: math.log(n_docs / (1 + count))
            for token, count in df.items()
        }
        self._vocab = {token: i for i, token in enumerate(self._idf)}
        self._fitted = True

    def _embed(self, text: str) -> list:
        """Crea embedding TF-IDF para un texto."""
        tokens = self._tokenize(text)
        tf = Counter(tokens)
        total = len(tokens) if tokens else 1

        vector = [0.0] * len(self._vocab)
        for token, count in tf.items():
            if token in self._vocab:
                idx = self._vocab[token]
                vector[idx] = (count / total) * self._idf.get(token, 0)
        return vector

    @staticmethod
    def _cosine_similarity(vec_a: list, vec_b: list) -> float:
        """Cosine similarity entre dos vectores."""
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        mag_a = math.sqrt(sum(a * a for a in vec_a))
        mag_b = math.sqrt(sum(b * b for b in vec_b))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    def check(self, scope: str, output: str) -> tuple:
        """
        Compara output con scope.

        Args:
            scope: descripción de la tarea original
            output: output del agente a evaluar

        Returns:
            (is_drifted: bool, similarity: float, reason: str)
        """
        if not scope or not scope.strip():
            return False, 1.0, "No scope provided, skipping drift check"

        if not output or not output.strip():
            return False, 1.0, "Empty output, skipping drift check"

        # Construir vocabulario con scope + output + ejemplos de referencia
        # Esto da contexto para que TF-IDF funcione bien con pocos documentos
        documents = [scope, output]
        # Añadir palabras del scope con peso adicional (duplicamos)
        # para que el vocabulario sea más robusto
        scope_words = self._tokenize(scope)
        documents.extend([' '.join(scope_words)] * 2)  # Reforzar vocabulario

        self._build_vocabulary(documents)

        scope_embedding = self._embed(scope)
        output_embedding = self._embed(output)

        similarity = self._cosine_similarity(scope_embedding, output_embedding)
        is_drifted = similarity < self.threshold

        if is_drifted:
            reason = (
                f"Scope drift detected: similarity={similarity:.2f} "
                f"< threshold={self.threshold:.2f}"
            )
        else:
            reason = f"Output in scope: similarity={similarity:.2f}"

        return is_drifted, round(similarity, 3), reason

    def check_with_details(self, scope: str, output: str) -> dict:
        """
        Versión detallada que retorna diccionario con métricas.

        Returns:
            {
                'is_drifted': bool,
                'similarity': float,
                'reason': str,
                'scope_tokens': int,
                'output_tokens': int,
                'common_tokens': int,
            }
        """
        is_drifted, similarity, reason = self.check(scope, output)

        scope_tokens = len(self._tokenize(scope))
        output_tokens = len(self._tokenize(output))
        common_tokens = len(
            set(self._tokenize(scope)) & set(self._tokenize(output))
        )

        return {
            'is_drifted': is_drifted,
            'similarity': similarity,
            'reason': reason,
            'scope_tokens': scope_tokens,
            'output_tokens': output_tokens,
            'common_tokens': common_tokens,
        }
