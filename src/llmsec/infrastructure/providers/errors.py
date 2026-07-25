class ModelGatewayError(RuntimeError):
    """Safe provider failure that can be returned without exposing credentials."""
