from pathlib import Path

from skilltrust.schemas import SCHEMAS, write_schemas


def test_committed_schemas_match_executable_models(tmp_path: Path) -> None:
    write_schemas(tmp_path)
    committed = Path("schemas")
    assert sorted(path.name for path in committed.glob("*.json")) == sorted(SCHEMAS)
    for filename in SCHEMAS:
        assert (committed / filename).read_bytes() == (tmp_path / filename).read_bytes()
