from http.client import responses
from http.cookies import SimpleCookie


class HttpResponseBase:
    """
    An HTTP response base class with dictionary-accessed headers.

    This class doesn't handle content. It should not be used directly.
    Use the HttpResponse and StreamingHttpResponse subclasses instead.
    """

    status_code = 200

    def __init__(self, content_type=None, status=None, reason=None, charset=None, headers=None):
        self.headers =None
        self._charset = charset
        if content_type and 'Content-Type' in self.headers:
            raise ValueError(
                "'headers' must not contain 'Content-Type' when the "
                "'content_type' parameter is provided."
            )
        if 'Content-Type' not in self.headers:
            if content_type is None:
                content_type = 'text/html; charset=%s' % self.charset
            self.headers['Content-Type'] = content_type
        self._resource_closers = []
        # This parameter is set by the handler. It's necessary to preserve the
        # historical behavior of request_finished.
        self._handler_class = None
        self.cookies = SimpleCookie()
        self.closed = False
        if status is not None:
            try:
                self.status_code = int(status)
            except (ValueError, TypeError):
                raise TypeError('HTTP status code must be an integer.')

            if not 100 <= self.status_code <= 599:
                raise ValueError('HTTP status code must be an integer from 100 to 599.')
        self._reason_phrase = reason

    @property
    def reason_phrase(self):
        if self._reason_phrase is not None:
            return self._reason_phrase
        # Leave self._reason_phrase unset in order to use the default
        # reason phrase for status code.
        return responses.get(self.status_code, 'Unknown Status Code')

    @reason_phrase.setter
    def reason_phrase(self, value):
        self._reason_phrase = value

    @property
    def charset(self):
        if self._charset is not None:
            return self._charset
        content_type = self.get('Content-Type', '')
        matched = _charset_from_content_type_re.search(content_type)
        if matched:
            # Extract the charset and strip its double quotes
            return matched['charset'].replace('"', '')
        return settings.DEFAULT_CHARSET

    @charset.setter
    def charset(self, value):
        self._charset = value

    def serialize_headers(self):
        """HTTP headers as a bytestring."""
        def to_bytes(val, encoding):
            return val if isinstance(val, bytes) else val.encode(encoding)

        headers = [
            (to_bytes(key, 'ascii') + b': ' + to_bytes(value, 'latin-1'))
            for key, value in self.headers.items()
        ]
        return b'\r\n'.join(headers)

    __bytes__ = serialize_headers

    @property
    def _content_type_for_repr(self):
        return ', "%s"' % self.headers['Content-Type'] if 'Content-Type' in self.headers else ''

    def __setitem__(self, header, value):
        self.headers[header] = value

    def __delitem__(self, header):
        del self.headers[header]

    def __getitem__(self, header):
        return self.headers[header]

    def has_header(self, header):
        """Case-insensitive check for a header."""
        return header in self.headers

    __contains__ = has_header

    def items(self):
        return self.headers.items()

    def get(self, header, alternate=None):
        return self.headers.get(header, alternate)

    def set_cookie(self, key, value='', max_age=None, expires=None, path='/',
                   domain=None, secure=False, httponly=False, samesite=None):
        """
        Set a cookie.

        ``expires`` can be:
        - a string in the correct format,
        - a naive ``datetime.datetime`` object in UTC,
        - an aware ``datetime.datetime`` object in any time zone.
        If it is a ``datetime.datetime`` object then calculate ``max_age``.
        """
        self.cookies[key] = value
        if expires is not None:
            if isinstance(expires, datetime.datetime):
                if timezone.is_aware(expires):
                    expires = timezone.make_naive(expires, timezone.utc)
                delta = expires - expires.utcnow()
                # Add one second so the date matches exactly (a fraction of
                # time gets lost between converting to a timedelta and
                # then the date string).
                delta = delta + datetime.timedelta(seconds=1)
                # Just set max_age - the max_age logic will set expires.
                expires = None
                max_age = max(0, delta.days * 86400 + delta.seconds)
            else:
                self.cookies[key]['expires'] = expires
        else:
            self.cookies[key]['expires'] = ''
        if max_age is not None:
            self.cookies[key]['max-age'] = int(max_age)
            # IE requires expires, so set it if hasn't been already.
            if not expires:
                self.cookies[key]['expires'] = http_date(time.time() + max_age)
        if path is not None:
            self.cookies[key]['path'] = path
        if domain is not None:
            self.cookies[key]['domain'] = domain
        if secure:
            self.cookies[key]['secure'] = True
        if httponly:
            self.cookies[key]['httponly'] = True
        if samesite:
            if samesite.lower() not in ('lax', 'none', 'strict'):
                raise ValueError('samesite must be "lax", "none", or "strict".')
            self.cookies[key]['samesite'] = samesite

    def setdefault(self, key, value):
        """Set a header unless it has already been set."""
        self.headers.setdefault(key, value)

    def set_signed_cookie(self, key, value, salt='', **kwargs):
        value = signing.get_cookie_signer(salt=key + salt).sign(value)
        return self.set_cookie(key, value, **kwargs)

    def delete_cookie(self, key, path='/', domain=None, samesite=None):
        # Browsers can ignore the Set-Cookie header if the cookie doesn't use
        # the secure flag and:
        # - the cookie name starts with "__Host-" or "__Secure-", or
        # - the samesite is "none".
        secure = (
            key.startswith(('__Secure-', '__Host-')) or
            (samesite and samesite.lower() == 'none')
        )
        self.set_cookie(
            key, max_age=0, path=path, domain=domain, secure=secure,
            expires='Thu, 01 Jan 1970 00:00:00 GMT', samesite=samesite,
        )

    # Common methods used by subclasses

    def make_bytes(self, value):
        """Turn a value into a bytestring encoded in the output charset."""
        # Per PEP 3333, this response body must be bytes. To avoid returning
        # an instance of a subclass, this function returns `bytes(value)`.
        # This doesn't make a copy when `value` already contains bytes.

        # Handle string types -- we can't rely on force_bytes here because:
        # - Python attempts str conversion first
        # - when self._charset != 'utf-8' it re-encodes the content
        if isinstance(value, (bytes, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            return bytes(value.encode(self.charset))
        # Handle non-string types.
        return str(value).encode(self.charset)

    # These methods partially implement the file-like object interface.
    # See https://docs.python.org/library/io.html#io.IOBase

    # The WSGI server must call this method upon completion of the request.
    # See http://blog.dscpl.com.au/2012/10/obligations-for-calling-close-on.html
    def close(self):
        for closer in self._resource_closers:
            try:
                closer()
            except Exception:
                pass
        # Free resources that were still referenced.
        self._resource_closers.clear()
        self.closed = True
        signals.request_finished.send(sender=self._handler_class)

    def write(self, content):
        raise OSError('This %s instance is not writable' % self.__class__.__name__)

    def flush(self):
        pass

    def tell(self):
        raise OSError('This %s instance cannot tell its position' % self.__class__.__name__)

    # These methods partially implement a stream-like object interface.
    # See https://docs.python.org/library/io.html#io.IOBase

    def readable(self):
        return False

    def seekable(self):
        return False

    def writable(self):
        return False

    def writelines(self, lines):
        raise OSError('This %s instance is not writable' % self.__class__.__name__)
