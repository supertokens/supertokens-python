def str_to_bool(val: str) -> bool:
    """
    Convert ENV values to boolean
    """
    return val.lower() in ("true", "t", "1")
