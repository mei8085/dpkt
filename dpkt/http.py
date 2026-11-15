# $Id: http.py 86 2013-03-05 19:25:19Z andrewflnr@gmail.com $
# -*- coding: utf-8 -*-
"""Hypertext Transfer Protocol."""
from __future__ import print_function
from __future__ import absolute_import
from collections import OrderedDict
from . import dpkt
from .compat import BytesIO, iteritems


# Characters that terminate an RFC 7230 token (header field-name) besides
# whitespace and control characters.
_TOKEN_SEPARATORS = frozenset('()<>@,;:\\"/[]?={} \t')
_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')
_DECIMAL_DIGITS = frozenset('0123456789')

# Trailer fields that control message framing, routing or the connection
# itself.  They are not allowed in a chunked trailer section (RFC 7230,
# section 4.1.2) because a parser that honours them could disagree with one
# that ignores them about the message boundary.
_FORBIDDEN_TRAILER_FIELDS = frozenset((
    'content-length', 'transfer-encoding', 'host', 'connection',
    'keep-alive', 'te', 'trailer', 'upgrade', 'proxy-authorization',
    'proxy-authenticate', 'content-encoding', 'content-range', 'content-type',
))


def _is_token(s):
    """Return True if s is a valid RFC 7230 token, e.g. a header field-name."""
    if not s:
        return False
    for ch in s:
        if ch in _TOKEN_SEPARATORS or ord(ch) < 0x21 or ord(ch) > 0x7e:
            return False
    return True


def parse_headers(f):
    """Return dict of HTTP headers parsed from a file object."""
    d = OrderedDict()
    while 1:
        # The following logic covers two kinds of loop exit criteria.
        # 1) If the header is valid, when we reached the end of the header,
        #    f.readline() would return with '\r\n', then after stripping the
        #    line terminator, we can break the loop.
        # 2) If this is a weird header, which do not ends with '\r\n',
        #    f.readline() would return with '', also break the loop.
        raw = f.readline()
        if not raw:
            break
        # Only strip the line terminator: leading whitespace is not allowed in
        # a header field-name and would otherwise let "Content-Length : 5"
        # slip through as a header the parser does not recognize.
        line = raw.rstrip(b'\r\n').decode('latin-1')
        if not line:
            break
        l_ = line.split(':', 1)
        if len(l_) != 2 or not _is_token(l_[0]):
            raise dpkt.UnpackError('invalid header: %r' % line)

        k = l_[0].lower()
        v = l_[1].lstrip()
        if k in d:
            if not type(d[k]) is list:
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def _header_values(value):
    """Return the value of a possibly repeated header as a list."""
    if isinstance(value, list):
        return value
    return [value]


def _parse_content_length(value):
    """Validate Content-Length header value(s) and return the body length.

    Repeated values are only accepted when they are identical.  Anything
    ambiguous (conflicting values, signs, spaces or non-digits) is rejected so
    that two parsers cannot disagree about where the message body ends.
    """
    lengths = []
    for v in _header_values(value):
        v = v.strip()
        if not v or any(c not in _DECIMAL_DIGITS for c in v):
            raise dpkt.UnpackError('invalid content-length: %r' % (v,))
        try:
            lengths.append(int(v))
        except ValueError:
            # e.g. int-to-str conversion limit for absurdly long values
            raise dpkt.UnpackError('invalid content-length: %r' % (v,))
    if lengths.count(lengths[0]) != len(lengths):
        raise dpkt.UnpackError('conflicting content-length values: %r' % (lengths,))
    return lengths[0]


def _parse_transfer_encoding(value):
    """Validate Transfer-Encoding header value(s).

    Only a single, final "chunked" coding is accepted; any other value leaves
    the message boundary undetermined and is therefore rejected.
    """
    codings = []
    for v in _header_values(value):
        for coding in v.split(','):
            coding = coding.strip().lower()
            if not coding:
                raise dpkt.UnpackError('invalid transfer-encoding: %r' % (value,))
            codings.append(coding)
    if codings[-1:] != ['chunked'] or 'chunked' in codings[:-1]:
        raise dpkt.UnpackError('unsupported transfer-encoding: %r' % (value,))


def _parse_chunk_size(line):
    """Return the size of a chunk from its size line (including extensions)."""
    text = line.rstrip(b'\r\n')
    try:
        size = text.split(b';', 1)[0].decode('ascii')
    except UnicodeDecodeError:
        raise dpkt.UnpackError('invalid chunk size: %r' % (text,))
    if not size:
        raise dpkt.UnpackError('missing chunk size')
    if any(c not in _HEX_DIGITS for c in size):
        raise dpkt.UnpackError('invalid chunk size: %r' % (size,))
    return int(size, 16)


def _read_chunk_terminator(f):
    """Read and validate the CRLF that terminates a chunk's data."""
    line = f.readline()
    if line == b'\r\n':
        return
    if not line.endswith(b'\r\n'):
        raise dpkt.NeedData('premature end of chunked body')
    raise dpkt.UnpackError('invalid chunk terminator: %r' % (line,))


def _read_chunked_trailer(f):
    """Read and validate the (possibly empty) trailer section of a body."""
    while 1:
        line = f.readline()
        if line == b'\r\n':
            return
        if not line.endswith(b'\r\n'):
            raise dpkt.NeedData('premature end of chunked body')
        trailer = line.rstrip(b'\r\n').decode('latin-1')
        parts = trailer.split(':', 1)
        if len(parts) != 2 or not _is_token(parts[0]) or parts[0].lower() in _FORBIDDEN_TRAILER_FIELDS:
            raise dpkt.UnpackError('invalid trailer: %r' % (trailer,))


def _parse_chunked_body(f):
    """Return the decoded body of a chunked transfer-encoding message."""
    chunks = []
    while 1:
        line = f.readline()
        if not line:
            raise dpkt.UnpackError('missing chunk size')
        if not line.endswith(b'\r\n'):
            # A size line without its CRLF means the stream was cut short.
            raise dpkt.NeedData('premature end of chunked body')
        n = _parse_chunk_size(line)
        if n == 0:
            _read_chunked_trailer(f)
            break
        try:
            buf = f.read(n)
        except (OverflowError, MemoryError):
            # The declared chunk cannot possibly be present; do not let an
            # absurd size line exhaust memory.
            raise dpkt.NeedData('premature end of chunked body')
        if len(buf) != n:
            raise dpkt.NeedData('premature end of chunked body')
        chunks.append(buf)
        _read_chunk_terminator(f)
    return b''.join(chunks)


def parse_body(f, headers, is_request=False):
    """Return HTTP body parsed from a file object, given HTTP header dict.

    Message framing is validated strictly so that a proxy and an origin
    server cannot disagree about the request boundary (request smuggling).
    Ambiguous framing (conflicting Content-Length, Transfer-Encoding together
    with Content-Length, malformed chunk sizes or terminators) raises
    dpkt.UnpackError instead of merging bytes from the next message into this
    body.

    Requests without Content-Length or Transfer-Encoding carry no body
    (RFC 7230, section 3.3.3); otherwise the remaining bytes, which may include
    the next request, would be swallowed as this body.
    """
    transfer_encoding = headers.get('transfer-encoding')
    content_length = headers.get('content-length')

    if transfer_encoding is not None:
        if content_length is not None:
            # RFC 7230, section 3.3.3: a message with both headers must be
            # treated as unrecoverable rather than risking a framing mismatch.
            raise dpkt.UnpackError('both transfer-encoding and content-length present')
        _parse_transfer_encoding(transfer_encoding)
        return _parse_chunked_body(f)
    elif content_length is not None:
        n = _parse_content_length(content_length)
        try:
            body = f.read(n)
        except (OverflowError, MemoryError):
            # The declared body cannot possibly be present.
            raise dpkt.NeedData('short body (missing %d bytes)' % n)
        if len(body) != n:
            raise dpkt.NeedData('short body (missing %d bytes)' % (n - len(body)))
        return body
    elif 'content-type' in headers and not is_request:
        # Response body delimited by the connection close.
        return f.read()
    else:
        # XXX - need to handle HTTP/0.9
        return b''


class Message(dpkt.Packet):
    """Hypertext Transfer Protocol headers + body.

    HTTP messages are how data is exchanged between a server and a client. There are two types of messages: requests
    sent by the client to trigger an action on the server, and responses, the answer from the server. HTTP messages are
     composed of textual information encoded in ASCII, and span over multiple lines.

    Attributes:
        __hdr__: Header fields of HTTP.
            The start-line and HTTP headers of the HTTP message are collectively known as the head of the requests,
            whereas its payload is known as the body.
    """

    __metaclass__ = type
    __hdr_defaults__ = {}
    headers = None
    body = None

    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = OrderedDict()
            self.body = b''
            self.data = b''
            # NOTE: changing this to iteritems breaks py3 compatibility
            for k, v in self.__hdr_defaults__.items():
                setattr(self, k, v)
            for k, v in iteritems(kwargs):
                setattr(self, k, v)

    def unpack(self, buf, is_body_allowed=True, is_request=False):
        f = BytesIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Parse body
        if is_body_allowed:
            self.body = parse_body(f, self.headers, is_request)
        else:
            self.body = b''
        # Save the rest
        self.data = f.read()

    def pack_hdr(self):
        return ''.join(['%s: %s\r\n' % t for t in iteritems(self.headers)])

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return '%s\r\n%s' % (self.pack_hdr(), self.body.decode("utf8", "ignore"))

    def __bytes__(self):
        return self.pack_hdr().encode("ascii", "ignore") + b'\r\n' + (self.body or b'')


class Request(Message):
    """Hypertext Transfer Protocol Request.

    HTTP requests are messages sent by the client to initiate an action on the server. Their start-line contain three
    elements. An HTTP method, a verb (like GET, PUT or POST) or a noun (like HEAD or OPTIONS), The request target,
    usually a URL, or the absolute path of the protocol, port, and domain are usually characterized by the request
    context and The HTTP version, which defines the structure of the remaining message, acting as an indicator of the
    expected version to use for the response.

    Attributes:
        __hdr__: Header fields of HTTP request.
            Many headers can appear in requests. They can be divided in several groups:
                General headers, like Via, apply to the message as a whole.
                Request headers, like User-Agent or Accept, modify the request by specifying it further (like Accept-
                    Language), by giving context (like Referer), or by conditionally restricting it (like If-None).
                Representation headers like Content-Type that describe the original format of the message data and
                    any encoding applied (only present if the message has a body).
    """

    __hdr_defaults__ = {
        'method': 'GET',
        'uri': '/',
        'version': '1.0',
    }
    __methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
    ))
    __proto = 'HTTP'

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline().decode("ascii", "ignore")
        l_ = line.strip().split()
        if len(l_) < 2:
            raise dpkt.UnpackError('invalid request: %r' % line)
        if l_[0] not in self.__methods:
            raise dpkt.UnpackError('invalid http method: %r' % l_[0])
        if len(l_) == 2:
            # HTTP/0.9 does not specify a version in the request line
            self.version = '0.9'
        else:
            if not l_[2].startswith(self.__proto):
                raise dpkt.UnpackError('invalid http version: %r' % l_[2])
            self.version = l_[2][len(self.__proto) + 1:]
        self.method = l_[0]
        self.uri = l_[1]
        Message.unpack(self, f.read(), is_request=True)

    def __str__(self):
        return '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                    self.version) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                       self.version)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


class Response(Message):
    """Hypertext Transfer Protocol Response.

    The start line of an HTTP response, called the status line, contains the following information. The protocol
    version, usually HTTP/1.1, a status code, indicating success or failure of the request. Common status codes are 200,
     404, or 302, a status text. A brief, purely informational, textual description of the status code to help a human
     understand the HTTP message. A typical status line looks like: HTTP/1.1 404 Not Found.

    Attributes:
        __hdr__: Header fields of HTTP Response.
            Many headers can appear in responses. These can be divided into several groups:
                General headers, like Via, apply to the whole message.
                Response headers, like Vary and Accept-Ranges, give additional information about the server which
                    doesn't fit in the status line.
                Representation headers like Content-Type that describe the original format of the message data and any
                    encoding applied (only present if the message has a body).
    """

    __hdr_defaults__ = {
        'version': '1.0',
        'status': '200',
        'reason': 'OK'
    }
    __proto = 'HTTP'

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline()
        l_ = line.strip().decode("ascii", "ignore").split(None, 2)
        if len(l_) < 2 or not l_[0].startswith(self.__proto) or not l_[1].isdigit():
            raise dpkt.UnpackError('invalid response: %r' % line)
        self.version = l_[0][len(self.__proto) + 1:]
        self.status = l_[1]
        self.reason = l_[2] if len(l_) > 2 else ''
        # RFC Sec 4.3.
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3.
        # For response messages, whether or not a message-body is included with
        # a message is dependent on both the request method and the response
        # status code (section 6.1.1). All responses to the HEAD request method
        # MUST NOT include a message-body, even though the presence of entity-
        # header fields might lead one to believe they do. All 1xx
        # (informational), 204 (no content), and 304 (not modified) responses
        # MUST NOT include a message-body. All other responses do include a
        # message-body, although it MAY be of zero length.
        is_body_allowed = int(self.status) >= 200 and 204 != int(self.status) != 304
        Message.unpack(self, f.read(), is_body_allowed)

    def __str__(self):
        return '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                    self.reason) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                       self.reason)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


def test_parse_request():
    s = (b"""POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\nReferer: http://www.email.com/login/snap/login.jhtml\r\n"""
         b"""Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n"""
         b"""Host: ltd.snap.com\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n"""
         b"""Accept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n"""
         b"""Content-type: application/x-www-form-urlencoded\r\nContent-length: 61\r\n\r\n"""
         b"""sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www""")
    r = Request(s)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.body == b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'

    Request(s[:60])


def test_format_request():
    r = Request()
    assert str(r) == 'GET / HTTP/1.0\r\n\r\n'
    r.method = 'POST'
    r.uri = '/foo/bar/baz.html'
    r.headers['content-type'] = 'text/plain'
    r.headers['content-length'] = '5'
    r.body = b'hello'
    s = str(r)
    assert s.startswith('POST /foo/bar/baz.html HTTP/1.0\r\n')
    assert s.endswith('\r\n\r\nhello')
    assert '\r\ncontent-length: 5\r\n' in s
    assert '\r\ncontent-type: text/plain\r\n' in s
    s = bytes(r)
    assert s.startswith(b'POST /foo/bar/baz.html HTTP/1.0\r\n')
    assert s.endswith(b'\r\n\r\nhello')
    assert b'\r\ncontent-length: 5\r\n' in s
    assert b'\r\ncontent-type: text/plain\r\n' in s
    r = Request(bytes(r))
    assert bytes(r) == s


def test_chunked_response():
    from binascii import unhexlify
    header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Cache-control: no-cache\r\n"
        b"Pragma: no-cache\r\n"
        b"Content-Type: text/javascript; charset=utf-8\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Set-Cookie: S=gmail=agg:gmail_yj=v2s:gmproxy=JkU; Domain=.google.com; Path=/\r\n"
        b"Server: GFE/1.3\r\n"
        b"Date: Mon, 12 Dec 2005 22:33:23 GMT\r\n"
        b"\r\n"
    )
    body = unhexlify(
        '610d0a1f8b08000000000000000d0a3135320d0a6d914d4fc4201086effe0a82c99e58'
        '4a4be9b6eec1e81e369e34f1e061358652da12596880bafaef85ee1a2ff231990cef30'
        '3cc381a0c301e610c13ca765595435a1a4ace1db153aa49d0cfa354b00f62eaaeb86d5'
        '79cd485995348ebc2a688c8e214c3759e627eb82575acf3e381e6487853158d863e6bc'
        '175a898fac208465de0a215d961769b5027b7bc27a301e0f23379c77337699329dfcc2'
        '6338ea5b2f4550d6bcce84d0ceabf760271fac53d2c7d2fb94024edc040feeba195803'
        '547457d7b4d9920abc58a73bb09b2710243f46fdf3437a50748a55efb8c88b2d18edec'
        '3ce083850821f8225bb0d36a826893b8cfd89bbadad09214a4610d630d654dfd873d58'
        '3b68d96a3be0646217c202bdb046c2696e23fb3ab6c47815d69f8aafcf290b5ebce769'
        '11808b004401d82f8278f6d8f74a28ae2f11701f2bc470093afefddfa359faae347f00'
        'c5a595a1e20100000d0a300d0a0d0a'
    )
    buf = header + body
    r = Response(buf)
    assert r.version == '1.1'
    assert r.status == '200'
    assert r.reason == 'OK'


def test_multicookie_response():
    s = (b"""HTTP/1.x 200 OK\r\nSet-Cookie: first_cookie=cookie1; path=/; domain=.example.com\r\n"""
         b"""Set-Cookie: second_cookie=cookie2; path=/; domain=.example.com\r\nContent-Length: 0\r\n\r\n""")
    r = Response(s)
    assert type(r.headers['set-cookie']) is list
    assert len(r.headers['set-cookie']) == 2


def test_noreason_response():
    s = b"""HTTP/1.1 200 \r\n\r\n"""
    r = Response(s)
    assert r.reason == ''
    assert bytes(r) == s


def test_response_with_body():
    r = Response()
    r.body = b'foo'
    assert str(r) == 'HTTP/1.0 200 OK\r\n\r\nfoo'
    assert bytes(r) == b'HTTP/1.0 200 OK\r\n\r\nfoo'
    repr(r)


def test_body_forbidden_response():
    s = b'HTTP/1.1 304 Not Modified\r\n'\
        b'Content-Type: text/css\r\n'\
        b'Last-Modified: Wed, 14 Jan 2009 16:42:11 GMT\r\n'\
        b'ETag: "3a7-496e15e3"\r\n'\
        b'Cache-Control: private, max-age=414295\r\n'\
        b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
        b'Connection: keep-alive\r\n'\
        b'Vary: Accept-Encoding\r\n\r\n'\
        b'HTTP/1.1 200 OK\r\n'\
        b'Server: Sun-ONE-Web-Server/6.1\r\n'\
        b'ntCoent-length: 257\r\n'\
        b'Content-Type: application/x-javascript\r\n'\
        b'Last-Modified: Wed, 06 Jan 2010 19:34:06 GMT\r\n'\
        b'ETag: "101-4b44e5ae"\r\n'\
        b'Accept-Ranges: bytes\r\n'\
        b'Content-Encoding: gzip\r\n'\
        b'Cache-Control: private, max-age=439726\r\n'\
        b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
        b'Connection: keep-alive\r\n'\
        b'Vary: Accept-Encoding\r\n'
    result = []
    while s:
        msg = Response(s)
        s = msg.data
        result.append(msg)

    # the second HTTP response should be an standalone message
    assert len(result) == 2


def test_request_version():
    s = b"""GET / HTTP/1.0\r\n\r\n"""
    r = Request(s)
    assert r.method == 'GET'
    assert r.uri == '/'
    assert r.version == '1.0'

    s = b"""GET /\r\n\r\n"""
    r = Request(s)
    assert r.method == 'GET'
    assert r.uri == '/'
    assert r.version == '0.9'

    import pytest
    s = b"""GET / CHEESE/1.0\r\n\r\n"""
    with pytest.raises(dpkt.UnpackError, match="invalid http version: u?'CHEESE/1.0'"):
        Request(s)


def test_valid_header():
    # valid header.
    s = b'POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\n' \
        b'Referer: http://www.email.com/login/snap/login.jhtml\r\n' \
        b'Connection: Keep-Alive\r\n' \
        b'User-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n' \
        b'Host: ltd.snap.com\r\n' \
        b'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' \
        b'Accept-Encoding: gzip\r\n' \
        b'Accept-Language: en\r\n' \
        b'Accept-Charset: iso-8859-1,*,utf-8\r\n' \
        b'Content-type: application/x-www-form-urlencoded\r\n' \
        b'Content-length: 61\r\n\r\n' \
        b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    r = Request(s)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.body == b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'


def test_weird_end_header():
    s_weird_end = b'POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\n' \
        b'Referer: http://www.email.com/login/snap/login.jhtml\r\n' \
        b'Connection: Keep-Alive\r\n' \
        b'User-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n' \
        b'Host: ltd.snap.com\r\n' \
        b'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' \
        b'Accept-Encoding: gzip\r\n' \
        b'Accept-Language: en\r\n' \
        b'Accept-Charset: iso-8859-1,*,utf-8\r\n' \
        b'Content-type: application/x-www-form-urlencoded\r\n' \
        b'Cookie: TrackID=1PWdcr3MO_C611BGW'
    r = Request(s_weird_end)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'


def test_gzip_response():
    import zlib
    # valid response, compressed using gzip
    s = b'HTTP/1.0 200 OK\r\n' \
        b'Server: SimpleHTTP/0.6 Python/2.7.12\r\n' \
        b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n' \
        b'Content-type: text/plain\r\n' \
        b'Content-Encoding: gzip\r\n' \
        b'Content-Length: 68\r\n' \
        b'Last-Modified: Fri, 10 Mar 2017 20:40:43 GMT\r\n\r\n' \
        b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x0b\xc9\xc8,V\x00\xa2D' \
        b'\x85\xb2\xd4\xa2J\x85\xe2\xdc\xc4\x9c\x1c\x85\xb4\xcc\x9cT\x85\x92' \
        b'|\x85\x92\xd4\xe2\x12\x85\xf4\xaa\xcc\x02\x85\xa2\xd4\xe2\x82\xfc' \
        b'\xbc\xe2\xd4b=.\x00\x01(m\xad2\x00\x00\x00'
    r = Response(s)
    assert r.version == '1.0'
    assert r.status == '200'
    assert r.reason == 'OK'
    # Make a zlib compressor with the appropriate gzip options
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    body = decompressor.decompress(r.body)
    assert body.startswith(b'This is a very small file')


def test_message():
    # s = b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n'  # FIXME - unused
    r = Message(content_length=68)
    assert r.content_length == 68
    assert len(r) == 2


def test_invalid():
    import pytest

    s = b'INVALID / HTTP/1.0\r\n'
    with pytest.raises(dpkt.UnpackError, match="invalid http method: u?'INVALID'"):
        Request(s)

    s = b'A'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'A'"):
        Response(s)

    s = b'HTTT 200 OK'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'HTTT 200 OK'"):
        Response(s)

    s = b'HTTP TWO OK'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'HTTP TWO OK'"):
        Response(s)

    s = (
        b'HTTP/1.0 200 OK\r\n'
        b'Invalid Header: invalid\r\n'
    )
    with pytest.raises(dpkt.UnpackError, match="invalid header: "):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"\r\n"
    )
    with pytest.raises(dpkt.UnpackError, match="missing chunk size"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"\x01\r\na"
    )
    with pytest.raises(dpkt.UnpackError, match="invalid chunk size"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\n"
        b"abcd"
    )
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 68\r\n"
        b"\r\n"
        b"a\r\n"
    )
    with pytest.raises(dpkt.NeedData, match=r"short body \(missing 65 bytes\)"):
        Response(s)

    # messy header.
    s_messy_header = b'aaaaaaaaa\r\nbbbbbbbbb'
    with pytest.raises(dpkt.UnpackError, match="invalid request: u?'aaaaaaaa"):
        Request(s_messy_header)


def test_response_str():
    s = (
        b'HTTP/1.0 200 OK\r\n'
        b'Server: SimpleHTTP/0.6 Python/2.7.12\r\n'
        b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n'
        b'Content-type: text/plain\r\n'
    )

    # the headers are processed to lowercase keys
    resp = [
        'HTTP/1.0 200 OK',
        'server: SimpleHTTP/0.6 Python/2.7.12',
        'date: Fri, 10 Mar 2017 20:43:08 GMT',
        'content-type: text/plain',
        '',
        '',
    ]

    r_str = str(Response(s))

    s_arr = sorted(resp)
    resp_arr = sorted(r_str.split('\r\n'))

    for line1, line2 in zip(s_arr, resp_arr):
        assert line1 == line2


def test_request_str():
    s = b'GET / HTTP/1.0\r\n'
    r = Request(s)
    req = 'GET / HTTP/1.0\r\n\r\n'
    assert req == str(r)


def test_parse_body():
    import pytest
    from .compat import BytesIO
    buf = BytesIO(
        b'05\r\n'  # size
        b'ERR'     # longer than size
    )
    buf.seek(0)
    headers = {
        'transfer-encoding': 'chunked',
    }
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        parse_body(buf, headers)


def test_duplicate_content_length_kept_in_order():
    s = (b'POST / HTTP/1.1\r\n'
         b'Host: a\r\n'
         b'X-Dup: first\r\n'
         b'X-Dup: second\r\n'
         b'Content-Length: 5\r\n'
         b'Content-Length: 5\r\n'
         b'\r\n'
         b'helloGET /next HTTP/1.1\r\n\r\n')
    r = Request(s)
    assert r.body == b'hello'
    # the next request starts where the buffer says it does
    assert r.data == b'GET /next HTTP/1.1\r\n\r\n'
    # duplicate headers are preserved in their original order
    assert r.headers['x-dup'] == ['first', 'second']
    assert r.headers['content-length'] == ['5', '5']


def test_conflicting_content_length_rejected():
    import pytest
    s = (b'POST / HTTP/1.1\r\n'
         b'Content-Length: 5\r\n'
         b'Content-Length: 6\r\n'
         b'\r\n'
         b'helloGET /next HTTP/1.1\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="conflicting content-length values: .*5, 6"):
        Request(s)

    # a body is still rejected when the values are split across a list
    from .compat import BytesIO
    buf = BytesIO(b'helloGET /next HTTP/1.1\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="conflicting content-length values"):
        parse_body(buf, {'content-length': ['5', '6']})


def test_transfer_encoding_with_content_length_rejected():
    import pytest
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'Content-Length: 5\r\n'
         b'\r\n'
         b'0\r\n'
         b'\r\n'
         b'GET /next HTTP/1.1\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="both transfer-encoding and content-length present"):
        Request(s)


def test_invalid_transfer_encoding_rejected():
    import pytest
    for te in (b'identity', b'gzip', b'chunked, chunked', b'', b'chunkedx'):
        s = b'POST / HTTP/1.1\r\nTransfer-Encoding: ' + te + b'\r\n\r\n0\r\n\r\n'
        with pytest.raises(dpkt.UnpackError, match="transfer-encoding"):
            Request(s)

    # only a single final "chunked" coding is supported
    s = b'POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n'
    r = Request(s)
    assert r.body == b''

    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n0\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="transfer-encoding"):
        Request(s)


def test_negative_and_signless_content_length_rejected():
    import pytest
    for cl in (b'-5', b'+5', b'--5', b'5.0', b'0x5', b'', b'5 5', b'5,5'):
        s = (b'POST / HTTP/1.1\r\n'
             b'Content-Length: ' + cl + b'\r\n'
             b'\r\n'
             b'helloGET /next HTTP/1.1\r\n\r\n')
        with pytest.raises(dpkt.UnpackError, match="(invalid|conflicting) content-length"):
            Request(s)


def test_header_name_with_whitespace_rejected():
    import pytest
    s = (b'POST / HTTP/1.1\r\n'
         b'Content-Length : 5\r\n'
         b'\r\n'
         b'helloGET /next HTTP/1.1\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="invalid header"):
        Request(s)

    # obsolete line folding must not be able to append to a header value
    s = (b'POST / HTTP/1.1\r\n'
         b'Content-Length: 5\r\n'
         b' 5\r\n'
         b'\r\n'
         b'helloGET /next HTTP/1.1\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="invalid header"):
        Request(s)


def test_invalid_chunk_size_rejected():
    import pytest
    for size in (b'-5', b'+5', b'0x5', b'5.5', b'5 0', b'zz'):
        s = (b'POST / HTTP/1.1\r\n'
             b'Transfer-Encoding: chunked\r\n'
             b'\r\n' + size + b'\r\n'
             b'hello\r\n'
             b'0\r\n\r\n'
             b'GET /next HTTP/1.1\r\n\r\n')
        with pytest.raises(dpkt.UnpackError, match="invalid chunk size"):
            Request(s)


def test_absurd_chunk_size_rejected():
    import pytest
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'ffffffffffffffff\r\n'
         b'x')
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        Request(s)


def test_chunk_terminator_required():
    import pytest
    # chunk data not followed by CRLF: the rest of the buffer does not become
    # part of the body.
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'5\r\n'
         b'helloXX'
         b'0\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="invalid chunk terminator"):
        Request(s)

    # chunk data cut by the end of the stream
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'5\r\n'
         b'hello')
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        Request(s)


def test_chunked_message_terminator_required():
    import pytest
    # no CRLF after the last chunk: the next request must not be mistaken
    # for a trailer.
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'5\r\n'
         b'hello\r\n'
         b'0\r\n'
         b'GET /next HTTP/1.1\r\n'
         b'Host: b\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="invalid trailer"):
        Request(s)

    # truncated trailer section
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'0\r\n'
         b'X-Trailer: value')
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        Request(s)

    # framing headers may not be smuggled through the trailer section
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'0\r\n'
         b'Content-Length: 5\r\n'
         b'\r\n')
    with pytest.raises(dpkt.UnpackError, match="invalid trailer"):
        Request(s)


def test_valid_chunked_request_boundary_preserved():
    s = (b'POST / HTTP/1.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'5;ext=1\r\n'
         b'hello\r\n'
         b'6\r\n'
         b' world\r\n'
         b'0\r\n'
         b'X-Trailer: value\r\n'
         b'\r\n'
         b'GET /next HTTP/1.1\r\n'
         b'Host: b\r\n\r\n')
    r = Request(s)
    assert r.body == b'hello world'
    assert r.data == b'GET /next HTTP/1.1\r\nHost: b\r\n\r\n'
    assert list(r.headers) == ['transfer-encoding']


def test_valid_content_length_request_boundary_preserved():
    s = (b'POST / HTTP/1.1\r\n'
         b'Content-Length: 5\r\n'
         b'\r\n'
         b'hello'
         b'GET /next HTTP/1.1\r\n'
         b'Host: b\r\n\r\n')
    r = Request(s)
    assert r.body == b'hello'
    assert r.data == b'GET /next HTTP/1.1\r\nHost: b\r\n\r\n'


def test_request_without_framing_headers_has_empty_body():
    # RFC 7230, section 3.3.3: a request without Content-Length or
    # Transfer-Encoding has no body, so the following request must not be
    # swallowed as body bytes.
    s = (b'GET /a HTTP/1.1\r\n'
         b'Content-Type: text/plain\r\n'
         b'\r\n'
         b'GET /b HTTP/1.1\r\n'
         b'Host: example\r\n\r\n')
    r = Request(s)
    assert r.body == b''
    assert r.data == b'GET /b HTTP/1.1\r\nHost: example\r\n\r\n'

    # responses may still be delimited by the connection close
    s = (b'HTTP/1.0 200 OK\r\n'
         b'Content-Type: text/plain\r\n'
         b'\r\n'
         b'hello')
    r = Response(s)
    assert r.body == b'hello'


def test_duplicate_te_cl_rejected_on_response():
    import pytest
    s = (b'HTTP/1.1 200 OK\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'Content-Length: 5\r\n'
         b'\r\n'
         b'0\r\n\r\n')
    with pytest.raises(dpkt.UnpackError, match="both transfer-encoding and content-length present"):
        Response(s)
