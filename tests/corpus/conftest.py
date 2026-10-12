from __future__ import annotations

from typing import Any

import pyarrow as pa
import pytest

from corpus import schema
from corpus.synthetic import SYNTHETIC_EPOCH as FIXTURE_EPOCH
from corpus.synthetic import build_corpus, build_synthetic_world, corpus_table
from corpus.synthetic import column_value as fixture_value
from corpus.synthetic import default_cell as default_value
from corpus.synthetic import synthetic_hash as fixture_hash

__all__ = [
    "FIXTURE_EPOCH",
    "build_corpus",
    "build_synthetic_world",
    "corpus_table",
    "default_value",
    "fixture_hash",
    "fixture_value",
    "make_corpus",
    "synthetic_corpus",
    "synthetic_corpus_tables",
]


def synthetic_corpus_tables() -> dict[str, pa.Table]:
    return build_corpus(
        **{
            name: [{col.name: fixture_value(col) for col in columns}]
            for name, columns in schema.TABLES.items()
        }
    )


@pytest.fixture
def synthetic_corpus() -> dict[str, pa.Table]:
    return synthetic_corpus_tables()


@pytest.fixture
def make_corpus() -> Any:
    return build_corpus
