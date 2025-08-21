from supertokens_python.recipe.multifactorauth.types import FactorIds


def test_get_all_factors():
    """Test that FactorIds.get_all_factors returns all factors defined in FactorIds class."""
    factors_from_dict: list[str] = []
    for k, v in FactorIds.__dict__.items():
        if (
            (not k.startswith("__") or not k.endswith("__"))
            and not k.startswith("<")
            and isinstance(v, str)
        ):
            factors_from_dict.append(v)

    assert factors_from_dict == FactorIds.get_all_factors()
