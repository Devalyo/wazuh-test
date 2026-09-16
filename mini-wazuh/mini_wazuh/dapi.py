"""DAPI-compatible deserialization for the local cluster simulator."""

import json
from importlib import import_module
from typing import Any


def as_wazuh_object(dct: dict[str, Any]) -> Any:
    """Reconstruct encoded callables from the compatible request format."""
    if "__callable__" not in dct:
        return dct
    encoded = dct["__callable__"]
    funcname = encoded["__name__"]
    qualname = encoded["__qualname__"].split(".")
    classname = qualname[0] if len(qualname) > 1 else None
    module = import_module(encoded["__module__"])
    if classname is None:
        return getattr(module, funcname)
    return getattr(getattr(module, classname), funcname)


def deserialize_request(raw: str) -> dict[str, Any]:
    """Deserialize a request using the compatible object hook."""
    request = json.loads(raw, object_hook=as_wazuh_object)
    if not isinstance(request, dict):
        raise TypeError("top-level request must be a dictionary")
    return request


def run_local(request: dict[str, Any]) -> dict[str, Any]:
    """Run a reconstructed local callable without authorizing its identity."""
    if request.get("request_type") != "local_master":
        raise ValueError("request_type must be local_master")

    function = request.get("f")
    if not callable(function):
        raise TypeError("f must be callable")

    kwargs = request.get("f_kwargs")
    if not isinstance(kwargs, dict):
        raise TypeError("f_kwargs must be a dictionary")

    try:
        result = function(**kwargs)
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}
    return {"status": "success", "result": result}
