import re

def is_valid_http_request(payload):
    lines = payload.split('\r\n')

    
    state = "Start"

    for line in lines:
        if state == "Start":
            if re.match(r"^(GET|POST|PUT|DELETE) \/.* HTTP\/1\.1$", line):
                state = "HeaderCheck"
            else:
                return False

        elif state == "HeaderCheck":
            if line.startswith("Host:"):
                state = "ContinueHeaders"
            elif line == '':
                
                return False

        elif state == "ContinueHeaders":
            if line == '':
                state = "BodyCheck"
                continue
            if ":" not in line:
                
                return False

        elif state == "BodyCheck":
            
            if "POST" in lines[0]:
                content_length = None
                for l in lines:
                    if l.startswith("Content-Length:"):
                        content_length = int(l.split(":")[1].strip())
                        break
                if content_length is None:
                    return False
                
                body_index = lines.index('') + 1
                body_data = '\r\n'.join(lines[body_index:])
                if len(body_data) != content_length:
                    return False
            break  

    return True
