"""
Lightweight JSON Schema Validator v1.0
======================================
Validates API request bodies against registered schemas WITHOUT
requiring the heavy `jsonschema` library.

Features:
- Type checking (string, number, integer, boolean, array, object, null)
- Required fields enforcement
- String constraints: minLength, maxLength, pattern (regex)
- Number constraints: minimum, maximum
- Array constraints: minItems, maxItems, item type validation
- Nested object validation (recursive)
- Enum value validation
- Per-endpoint schema registration
- Schema loading from JSON files

Schema Format (subset of JSON Schema):
{
    "type": "object",
    "required": ["field1", "field2"],
    "properties": {
        "field1": {"type": "string", "maxLength": 100},
        "field2": {"type": "integer", "minimum": 0},
        "field3": {
            "type": "object",
            "properties": {
                "nested": {"type": "string"}
            }
        }
    }
}
"""
import os
import re
import json
from typing import List, Dict, Optional, Any, Tuple


class ValidationError:
    """A single validation error"""

    def __init__(self, path: str, message: str, value: Any = None):
        self.path = path       # JSON path to the error (e.g., "data.users[0].name")
        self.message = message
        self.value = value

    def __str__(self):
        return f"{self.path}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "message": self.message}


def _validate_value(
    value: Any,
    schema: Dict[str, Any],
    path: str = "$",
    errors: List[ValidationError] = None,
) -> List[ValidationError]:
    """
    Recursively validate a value against a schema definition.

    Args:
        value: The value to validate
        schema: Schema definition dict
        path: Current JSON path for error reporting
        errors: Accumulation list

    Returns:
        List of ValidationError objects
    """
    if errors is None:
        errors = []

    expected_type = schema.get("type")

    # Handle nullable
    if value is None:
        if expected_type == "null" or schema.get("nullable", False):
            return errors
        if expected_type:
            errors.append(ValidationError(path, f"Expected {expected_type}, got null"))
        return errors

    # Type validation
    if expected_type:
        if not _check_type(value, expected_type):
            errors.append(
                ValidationError(
                    path,
                    f"Expected type '{expected_type}', got '{type(value).__name__}'",
                    value,
                )
            )
            return errors  # Stop validating if type is wrong

    # Enum validation
    if "enum" in schema:
        if value not in schema["enum"]:
            errors.append(
                ValidationError(
                    path,
                    f"Value must be one of {schema['enum']}, got '{value}'",
                    value,
                )
            )

    # String constraints
    if isinstance(value, str):
        _validate_string(value, schema, path, errors)

    # Number constraints
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _validate_number(value, schema, path, errors)

    # Object constraints
    if isinstance(value, dict) and expected_type == "object":
        _validate_object(value, schema, path, errors)

    # Array constraints
    if isinstance(value, list) and expected_type == "array":
        _validate_array(value, schema, path, errors)

    return errors


def _check_type(value: Any, expected: str) -> bool:
    """Check if value matches the expected JSON Schema type"""
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }

    expected_types = type_map.get(expected)
    if expected_types is None:
        return True  # Unknown type — skip check

    # Special case: booleans should not match integer
    if expected == "integer" and isinstance(value, bool):
        return False
    if expected == "number" and isinstance(value, bool):
        return False

    return isinstance(value, expected_types)


def _validate_string(
    value: str,
    schema: Dict[str, Any],
    path: str,
    errors: List[ValidationError],
):
    """Validate string-specific constraints"""
    min_len = schema.get("minLength")
    max_len = schema.get("maxLength")
    pattern = schema.get("pattern")

    if min_len is not None and len(value) < min_len:
        errors.append(
            ValidationError(
                path, f"String too short: {len(value)} < {min_len}", value
            )
        )

    if max_len is not None and len(value) > max_len:
        errors.append(
            ValidationError(
                path, f"String too long: {len(value)} > {max_len}", value
            )
        )

    if pattern is not None:
        try:
            if not re.search(pattern, value):
                errors.append(
                    ValidationError(
                        path,
                        f"String does not match pattern: {pattern}",
                        value,
                    )
                )
        except re.error:
            pass  # Invalid regex in schema — skip


def _validate_number(
    value: float,
    schema: Dict[str, Any],
    path: str,
    errors: List[ValidationError],
):
    """Validate number-specific constraints"""
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")

    if minimum is not None and value < minimum:
        errors.append(
            ValidationError(path, f"Value {value} < minimum {minimum}", value)
        )

    if maximum is not None and value > maximum:
        errors.append(
            ValidationError(path, f"Value {value} > maximum {maximum}", value)
        )


def _validate_object(
    value: Dict,
    schema: Dict[str, Any],
    path: str,
    errors: List[ValidationError],
):
    """Validate object-specific constraints"""
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    additional = schema.get("additionalProperties", True)
    max_properties = schema.get("maxProperties")

    # Check required fields
    for field_name in required:
        if field_name not in value:
            errors.append(
                ValidationError(
                    f"{path}.{field_name}", f"Required field '{field_name}' is missing"
                )
            )

    # Check max properties
    if max_properties is not None and len(value) > max_properties:
        errors.append(
            ValidationError(
                path,
                f"Too many properties: {len(value)} > {max_properties}",
            )
        )

    # Validate each property
    for field_name, field_value in value.items():
        field_path = f"{path}.{field_name}"

        if field_name in properties:
            _validate_value(field_value, properties[field_name], field_path, errors)
        elif additional is False:
            errors.append(
                ValidationError(
                    field_path,
                    f"Additional property '{field_name}' not allowed",
                    field_value,
                )
            )


def _validate_array(
    value: List,
    schema: Dict[str, Any],
    path: str,
    errors: List[ValidationError],
):
    """Validate array-specific constraints"""
    min_items = schema.get("minItems")
    max_items = schema.get("maxItems")
    items_schema = schema.get("items")

    if min_items is not None and len(value) < min_items:
        errors.append(
            ValidationError(path, f"Too few items: {len(value)} < {min_items}")
        )

    if max_items is not None and len(value) > max_items:
        errors.append(
            ValidationError(path, f"Too many items: {len(value)} > {max_items}")
        )

    # Validate each item
    if items_schema:
        for i, item in enumerate(value):
            _validate_value(item, items_schema, f"{path}[{i}]", errors)


# =============================================================================
# Schema Registry — register and validate per-endpoint
# =============================================================================

class SchemaValidator:
    """
    Per-endpoint JSON schema validation.

    Usage:
        validator = SchemaValidator()
        validator.register("POST /api/login", {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": {"type": "string", "maxLength": 100},
                "password": {"type": "string", "minLength": 8}
            }
        })

        errors = validator.validate("POST /api/login", body_dict)
        if errors:
            return 400, errors
    """

    def __init__(self, schemas_dir: str = None):
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._schemas_dir = schemas_dir

        if schemas_dir and os.path.isdir(schemas_dir):
            self._load_schemas_from_dir(schemas_dir)

    def register(self, endpoint_key: str, schema: Dict[str, Any]):
        """
        Register a schema for an endpoint.

        Args:
            endpoint_key: "METHOD /path" or just "/path"
            schema: JSON Schema definition dict
        """
        self._schemas[endpoint_key] = schema

    def validate(
        self,
        endpoint_key: str,
        body: Any,
    ) -> List[ValidationError]:
        """
        Validate a request body against the registered schema.

        Args:
            endpoint_key: "METHOD /path"
            body: Parsed JSON body

        Returns:
            List of ValidationError objects (empty if valid)
            Returns empty list if no schema registered for this endpoint
        """
        schema = self._schemas.get(endpoint_key)
        if schema is None:
            # Try without method prefix
            for key, s in self._schemas.items():
                if endpoint_key.endswith(key) or key.endswith(
                    endpoint_key.split(" ", 1)[-1] if " " in endpoint_key else endpoint_key
                ):
                    schema = s
                    break

        if schema is None:
            return []  # No schema registered — skip validation

        return _validate_value(body, schema)

    def has_schema(self, endpoint_key: str) -> bool:
        """Check if a schema is registered for an endpoint"""
        if endpoint_key in self._schemas:
            return True
        # Try path-only match
        path = endpoint_key.split(" ", 1)[-1] if " " in endpoint_key else endpoint_key
        return any(k.endswith(path) for k in self._schemas)

    def get_registered_endpoints(self) -> List[str]:
        """Get list of endpoints with registered schemas"""
        return list(self._schemas.keys())

    def _load_schemas_from_dir(self, directory: str):
        """Load all JSON schema files from a directory"""
        for filename in os.listdir(directory):
            if filename.endswith(".json"):
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        schema_data = json.load(f)

                    # Extract endpoint key from schema or filename
                    endpoint = schema_data.get("endpoint")
                    if not endpoint:
                        # Derive from filename: api_login.json → /api/login
                        endpoint = "/" + filename.replace(".json", "").replace("_", "/")

                    method = schema_data.get("method", "POST")
                    key = f"{method} {endpoint}"

                    # The actual schema is in the "schema" key or is the whole file
                    schema = schema_data.get("schema", schema_data)
                    self._schemas[key] = schema

                except (json.JSONDecodeError, OSError) as e:
                    print(f"[SchemaValidator] Error loading {filepath}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        return {
            "registered_schemas": len(self._schemas),
            "endpoints": self.get_registered_endpoints(),
        }
