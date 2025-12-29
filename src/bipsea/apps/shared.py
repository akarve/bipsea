def hardened_int(segment: str) -> int:
    if not segment.endswith("'"):
        raise ValueError(f"Expected hardened segment, got {segment}")
    return int(segment[:-1])
