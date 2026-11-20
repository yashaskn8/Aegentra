from aegentra.db import Base


def test_scoped_foreign_key_is_explicit() -> None:
    asset = Base.metadata.tables["assets"]
    evidence = Base.metadata.tables["evidence"]
    assert list(asset.primary_key.columns.keys()) == ["org_id", "id"]
    assert list(evidence.primary_key.columns.keys()) == ["org_id", "id"]
    assert any(
        {column.name for column in constraint.columns} == {"org_id", "asset_id"}
        for constraint in evidence.foreign_key_constraints
    )
