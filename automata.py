def is_valid_http_request(payload):
    """
    Simple Automata to check if HTTP request starts with a valid method.
    """
    valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    try:
        # Split the payload into lines
        request_line = payload.split("\\r\\n")[0]
        method = request_line.split(" ")[0]

        if method in valid_methods:
            return True
        else:
            return False

    except Exception as e:
        print(f"Error in Automata Parsing: {e}")
        return False
