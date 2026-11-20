"""Test setup.

The handler imports boto3 and botocore. In CI they are installed; if they are
missing locally, small stand-ins are registered so the tests still run. The
tests never call AWS: they pass fake clients into the handler.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:  # pragma: no cover - depends on the environment
    import boto3  # noqa: F401
    import botocore.exceptions  # noqa: F401
except ImportError:  # pragma: no cover
    class ClientError(Exception):
        def __init__(self, error_response, operation_name):
            self.response = error_response
            self.operation_name = operation_name
            code = error_response.get("Error", {}).get("Code", "")
            super().__init__(f"An error occurred ({code}) when calling the {operation_name} operation")

    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = ClientError
    botocore.exceptions = exceptions
    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = exceptions

    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no AWS in tests"))
    sys.modules["boto3"] = boto3
