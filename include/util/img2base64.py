import base64


def convertFile2Base64(filepath: str) -> bytes:
    """
    This function plays a role in converting a file to base64 format
    without a fixed header like data:image/jpeg;base64.

    A file path is required for the function to perform its operation.
    """

    # We do not judge in advance whether the file exists
    with open(filepath, "rb") as f:
        converted_data = base64.standard_b64encode(f.read())

    return converted_data
