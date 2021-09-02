def extract_all_cookies(response):
    cookie_headers = response.headers.getlist('Set-Cookie')
    cookies = dict()
    for header in cookie_headers:
        attributes = header.split(';')
        cookie = {}
        is_name = True
        name = None
        for attr in attributes:
            split = attr.split('=')
            if is_name:
                name = split[0].strip()
                cookie['value'] = split[1]
                is_name = False
            else:
                cookie[split[0].strip().lower()] = split[1] if len(
                    split) > 1 else True
        cookies[name] = cookie
    return cookies
