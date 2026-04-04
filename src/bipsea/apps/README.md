# Adding a BIP-85 app

Each app lives in its own directory under `src/bipsea/apps/` and implements the
`BIP85App` protocol defined in [`app_protocol.py`](../app_protocol.py).


## Protocol

Implement [`BIP85App`](../app_protocol.py). `apply()` must return
`{"entropy": bytes, "application": str}`.


## Param

Params declare the app's CLI options as pure data. The CLI adapter converts
them to Click options automatically.

```python
Param(
    name="length",          # kwarg name passed to path_segments() and apply()
    flags=("-n", "--length"),
    type=int,
    required=True,
    range=(20, 86),         # becomes click.IntRange
    help="Password length in characters",
    role="number",          # "number" = the primary numeric param
)
```

- `choices` becomes `click.Choice`
- `range` becomes `click.IntRange`
- `role="number"` identifies the param used for output length (used by range validation)


## Steps

1. Create `src/bipsea/apps/yourapp/app.py`
2. Implement the protocol (see `base64/app.py` for a minimal example)
3. Export a module-level `app` instance
4. Register in `src/bipsea/apps/__init__.py`
5. Add test vectors from the BIP-85 spec
6. Run `make test lint`


## Example

```python
from typing import Any

from bipsea.app_protocol import Param, TestVector


class MyApp:
    name = "myapp"
    code = "12345'"

    @property
    def params(self) -> list[Param]:
        return [
            Param("length", ("-n", "--length"), int, required=True,
                  range=(1, 64), help="Output length", role="number"),
        ]

    def path_segments(self, index: int, length: int, **_) -> list[str]:
        return [f"{length}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        from bipsea.apps.shared import hardened_int
        return {"length": hardened_int(segments[0])}

    def apply(self, entropy: bytes, length: int, **_) -> dict[str, Any]:
        return {
            "entropy": entropy,
            "application": entropy.hex()[:length],
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv...",
                path="m/83696968'/12345'/32'/0'",
                entropy="abcd...",
                output="abcd...",
            ),
        ]


app = MyApp()
```
