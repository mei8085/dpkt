# $Id: dpkt.py 43 2007-08-02 22:42:59Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Simple packet creation and parsing.

The dpkt project is a python module for fast, simple packet parsing, with definitions for the basic TCP/IP protocols.
"""
from __future__ import absolute_import, print_function

import copy
import struct
from functools import partial
from itertools import chain

from .compat import compat_ord, compat_izip, iteritems, ntole


class Error(Exception):
    pass


class UnpackError(Error):
    pass


class NeedData(UnpackError):
    pass


class PackError(Error):
    pass


class TruncatedPacket(NeedData):
    """The buffer ends before the length the protocol announced.

    This is the "captured fewer bytes than the header claims" case:  the outer
    header parsed, but the layer declares a length (or an offset to the next
    header) that runs past the end of the buffer that was handed to it.  It is
    a :class:`NeedData` subclass, so existing ``except UnpackError`` handlers
    keep working.
    """


class InvalidPacket(UnpackError):
    """The bytes contradict the lengths/offsets the protocol announces.

    Unlike :class:`TruncatedPacket` this is not a "need more data" condition:
    the packet is self-inconsistent (for example an IPv4 total length smaller
    than its own header, a header offset that leaves no room for the fixed
    header, or a checksum that does not cover what it claims to cover).
    """


# ---------------------------------------------------------------------------
# Received-packet consistency reporting
#
# Every parser records what it observed while unpacking (announced lengths vs.
# captured bytes, contradictory offsets, inner decodes that were rejected) in
# ``Packet.issues``.  ``dpkt.validation`` turns that into a verdict and is able
# to re-verify the checksums of the whole layer stack.  Keeping the reporting
# objects here avoids a dependency cycle (validation imports dpkt, not the
# other way round) and exports them from the ``dpkt`` package namespace.
# ---------------------------------------------------------------------------

# issue codes (stable, machine readable)
ISSUE_TRUNCATED = 'truncated'                 # announced length > captured bytes
ISSUE_TRAILING = 'trailing'                   # extra bytes beyond announced length
ISSUE_LENGTH = 'length'                       # nested length fields disagree
ISSUE_CHECKSUM = 'checksum'                   # checksum does not verify
ISSUE_INVALID_HEADER = 'invalid-header'       # header offset/length impossible
ISSUE_UNDECODED = 'undecoded'                 # payload was not inserted into a decoder
ISSUE_PADDING = 'padding'                     # tolerated link-layer padding (informational)
ISSUE_FRAGMENT = 'fragment'                   # length only meaningful after reassembly

_ERROR_CODES = frozenset([ISSUE_TRUNCATED, ISSUE_TRAILING, ISSUE_LENGTH,
                          ISSUE_CHECKSUM, ISSUE_INVALID_HEADER])


class Issue(object):
    """One consistency problem, tied to the layer that observed it.

    Attributes:
        code: stable identifier, one of the ``ISSUE_*`` constants.
        layer: class of the packet layer that observed the problem.
        message: human readable description.
        details: dict of extra values (lengths, offsets, protocol names, ...).
    """

    __slots__ = ('code', 'layer', 'message', 'details')

    def __init__(self, code, layer, message, **details):
        self.code = code
        self.layer = layer
        self.message = message
        self.details = details

    @property
    def severity(self):
        return 'error' if self.code in _ERROR_CODES else 'info'

    @property
    def is_error(self):
        return self.code in _ERROR_CODES

    @property
    def layer_name(self):
        return getattr(self.layer, '__name__', str(self.layer))

    def __repr__(self):
        return 'Issue(%r, %r, %r)' % (self.code, self.layer_name, self.message)

    def __str__(self):
        return '%s: %s: %s' % (self.layer_name, self.code, self.message)


class Report(object):
    """Result of a consistency check: an ordered collection of :class:`Issue`.

    ``bool(report)`` is ``True`` for a trustworthy packet.  ``status`` is
    ``'ok'`` or the code of the first error-level issue.
    """

    __slots__ = ('issues',)

    def __init__(self, issues=None):
        self.issues = list(issues or [])

    def add(self, issue):
        self.issues.append(issue)
        return issue

    def extend(self, issues):
        self.issues.extend(issues)
        return self

    @property
    def errors(self):
        return [i for i in self.issues if i.is_error]

    @property
    def informational(self):
        return [i for i in self.issues if not i.is_error]

    @property
    def valid(self):
        return not self.errors

    # alias used by callers that think in terms of consistency
    consistent = valid

    @property
    def ok(self):
        return self.valid

    @property
    def status(self):
        for issue in self.issues:
            if issue.is_error:
                return issue.code
        return 'ok'

    @property
    def reasons(self):
        return [i.message for i in self.errors]

    @property
    def reason(self):
        for issue in self.issues:
            if issue.is_error:
                return issue.message
        return None

    @property
    def codes(self):
        return [i.code for i in self.issues]

    def to_dict(self):
        return {
            'status': self.status,
            'valid': self.valid,
            'issues': [{'code': i.code, 'layer': i.layer_name,
                        'message': i.message, 'details': dict(i.details)}
                       for i in self.issues],
        }

    def raise_if_invalid(self, packet=None):
        """Raise the matching :class:`ConsistencyError` subclass if invalid."""
        if not self.valid:
            raise _error_from_report(self, packet)
        return self

    def __bool__(self):
        return self.valid

    # Python 2 compatible truthiness
    __nonzero__ = __bool__

    def __repr__(self):
        return 'Report(status=%r, issues=%r)' % (self.status, self.issues)


class ConsistencyError(UnpackError):
    """A received packet failed the consistency check.

    The full :class:`Report` is available as :attr:`report`.
    """

    def __init__(self, message=None, report=None, layer=None):
        self.report = report if report is not None else Report()
        self.layer = layer
        if message is None:
            message = self.report.reason or 'packet is inconsistent'
        super(ConsistencyError, self).__init__(message)

    @property
    def issues(self):
        return self.report.issues


class TruncationError(ConsistencyError):
    """The captured buffer is shorter than the announced length."""


class TrailingDataError(ConsistencyError):
    """Bytes follow the announced end of a packet."""


class LengthMismatchError(ConsistencyError):
    """Nested length fields contradict each other."""


class ChecksumError(ConsistencyError):
    """A checksum does not verify over its advertised coverage."""


class ReassemblyError(ConsistencyError):
    """A reassembled datagram is illegal (or the fragment set is ambiguous)."""


_CODE_ERRORS = {
    ISSUE_TRUNCATED: TruncationError,
    ISSUE_TRAILING: TrailingDataError,
    ISSUE_LENGTH: LengthMismatchError,
    ISSUE_CHECKSUM: ChecksumError,
    ISSUE_INVALID_HEADER: LengthMismatchError,
}


def _error_from_report(report, packet=None):
    """Map the first error-level issue of a report to a ConsistencyError."""
    layer = getattr(packet, '__class__', None)
    for issue in report.issues:
        if issue.is_error:
            cls = _CODE_ERRORS.get(issue.code, ConsistencyError)
            return cls('%s: %s' % (issue.layer_name, issue.message),
                       report=report, layer=issue.layer)
    return ConsistencyError(report=report, layer=layer)


# See the "creating parsers" documentation for how all of this works


class _MetaPacket(type):
    def __new__(cls, clsname, clsbases, clsdict):
        t = type.__new__(cls, clsname, clsbases, clsdict)
        byte_order = getattr(t, '__byte_order__', '>')
        st = getattr(t, '__hdr__', None)
        if st is not None:
            # XXX - __slots__ only created in __new__()
            clsdict['__slots__'] = [x[0] for x in st] + ['data']
            t = type.__new__(cls, clsname, clsbases, clsdict)
            t.__hdr_fields__ = [x[0] for x in st]
            t.__hdr_fmt__ = byte_order + ''.join(x[1] for x in st)
            t.__hdr_len__ = struct.calcsize(t.__hdr_fmt__)
            t.__hdr_defaults__ = dict(compat_izip(
                t.__hdr_fields__, (x[2] for x in st)))

        # process __bit_fields__
        bit_fields = getattr(t, '__bit_fields__', None)
        if bit_fields:
            t.__bit_fields_defaults__ = {}  # bit fields equivalent of __hdr_defaults__

            for (ph_name, ph_struct, ph_default) in t.__hdr__:  # ph: placeholder variable for the bit field
                if ph_name in bit_fields:
                    field_defs = bit_fields[ph_name]

                    bits_total = sum(bf[1] for bf in field_defs)  # total size in bits
                    bits_used = 0

                    # make sure the sum of bits matches the overall size of the placeholder field
                    # prepending ph_struct with byte_order implies standard size for the byte orders `=`, `<`, `>` and `!`
                    assert bits_total == struct.calcsize('%s%s' % (byte_order, ph_struct)) * 8, \
                        "the overall count of bits in [%s] as declared in __bit_fields__ " \
                        "does not match its struct size in __hdr__" % ph_name

                    for (bf_name, bf_size) in field_defs:
                        if bf_name.startswith('_'):  # do not create properties for _private fields
                            bits_used += bf_size
                            continue

                        shift = bits_total - bits_used - bf_size
                        mask = (2**bf_size - 1) << shift  # all zeroes except the field bits
                        mask_inv = (2**bits_total - 1) - mask  # inverse mask
                        bits_used += bf_size

                        # calculate the default value for the bit field
                        bf_default = (t.__hdr_defaults__[ph_name] & mask) >> shift
                        t.__bit_fields_defaults__[bf_name] = bf_default

                        # create getter, setter and delete properties for the bit fields

                        def make_getter(ph_name=ph_name, mask=mask, shift=shift):
                            def getter_func(self):
                                ph_val = getattr(self, ph_name)
                                return (ph_val & mask) >> shift
                            return getter_func

                        def make_setter(ph_name=ph_name, mask_inv=mask_inv, shift=shift, bf_name=bf_name, max_val=2**bf_size):
                            def setter_func(self, bf_val):
                                # ensure the given value fits into the number of bits available
                                if bf_val >= max_val:
                                    raise ValueError('value %s is too large for field %s' % (bf_val, bf_name))

                                ph_val = getattr(self, ph_name)
                                ph_val_new = (bf_val << shift) | (ph_val & mask_inv)
                                setattr(self, ph_name, ph_val_new)
                            return setter_func

                        # delete property to set the bit field back to its default value
                        def make_delete(bf_name=bf_name, bf_default=bf_default):
                            def delete_func(self):
                                setattr(self, bf_name, bf_default)
                            return delete_func

                        setattr(t, bf_name, property(make_getter(), make_setter(), make_delete()))

        # optional map of functions for pretty printing
        # {field_name: callable(field_value) -> str, ..}
        # define as needed in the child protocol classes
        #t.__pprint_funcs__ = {}  - disabled here to keep the base class lightweight

        # placeholder for __public_fields__, a class attribute used in __repr__ and pprint()
        t.__public_fields__ = None

        return t


class Packet(_MetaPacket("Temp", (object,), {})):
    r"""Base packet class, with metaclass magic to generate members from self.__hdr__.

    Attributes:
        __hdr__: Packet header should be defined as a list of
                 (name, structfmt, default) tuples.
        __byte_order__: Byte order, can be set to override the default ('>')

    Example:
    >>> class Foo(Packet):
    ...   __hdr__ = (('foo', 'I', 1), ('bar', 'H', 2), ('baz', '4s', 'quux'))
    ...
    >>> foo = Foo(bar=3)
    >>> foo
    Foo(bar=3)
    >>> str(foo)
    '\x00\x00\x00\x01\x00\x03quux'
    >>> foo.bar
    3
    >>> foo.baz
    'quux'
    >>> foo.foo = 7
    >>> foo.baz = 'whee'
    >>> foo
    Foo(baz='whee', foo=7, bar=3)
    >>> Foo('hello, world!')
    Foo(baz=' wor', foo=1751477356L, bar=28460, data='ld!')
    """
    def __init__(self, *args, **kwargs):
        """Packet constructor with ([buf], [field=val,...]) prototype.

        Arguments:

        buf -- optional packet buffer to unpack

        Optional keyword arguments correspond to members to set
        (matching fields in self.__hdr__, or 'data').
        """
        self.data = b''
        # consistency problems observed while unpacking (see dpkt.validation);
        # kept private so it does not alter __repr__/__dict__ of parsed packets
        self._issues = []
        # the exact bytes this layer was parsed from; used by dpkt.validation
        # to verify checksums over their true coverage.  None for packets that
        # were built programmatically rather than parsed from a buffer.
        self._raw_buf = None
        if args:
            buf = args[0]
            if isinstance(buf, (bytes, bytearray, memoryview)):
                self._raw_buf = bytes(buf)
            try:
                self.unpack(buf)
            except struct.error:
                if len(buf) < self.__hdr_len__:
                    raise TruncatedPacket('got %d, %d needed at least' % (len(buf), self.__hdr_len__))
                raise UnpackError('invalid %s: %r' %
                                  (self.__class__.__name__, buf))
        else:
            if hasattr(self, '__hdr_fields__'):
                for k in self.__hdr_fields__:
                    setattr(self, k, copy.copy(self.__hdr_defaults__[k]))

            for k, v in iteritems(kwargs):
                setattr(self, k, v)

        if hasattr(self, '__hdr_fmt__'):
            self._pack_hdr = partial(struct.pack, self.__hdr_fmt__)

    # -- received-packet consistency bookkeeping ---------------------------
    @property
    def issues(self):
        """Consistency problems observed while unpacking this layer."""
        return self._issues

    def add_issue(self, code, message, **details):
        """Record a consistency problem observed while unpacking this layer."""
        issue = Issue(code, self.__class__, message, **details)
        self._issues.append(issue)
        return issue

    def _note_truncated(self, announced, captured, what='payload'):
        return self.add_issue(
            ISSUE_TRUNCATED,
            '%s announces %d bytes but only %d were captured' %
            (what, announced, captured),
            announced=announced, captured=captured, what=what)

    def _note_trailing(self, tail, what='payload'):
        """Record bytes found past the announced end of this layer.

        ``tail`` is the leftover buffer (or an integer count when the caller has
        already sliced it away).  All-zero tails are tolerated at the link
        layer as padding and only reported as informational; any other trailing
        bytes are a consistency error, because they belong to neither this
        datagram nor the next one.
        """
        if isinstance(tail, (bytes, bytearray, memoryview)):
            count = len(tail)
            nonpadding = any(tail)
        else:
            count = int(tail)
            nonpadding = count > 0
        if count and not nonpadding:
            return self.add_issue(
                ISSUE_PADDING,
                '%d zero padding bytes follow the %s' % (count, what),
                trailing=count, what=what)
        return self.add_issue(
            ISSUE_TRAILING,
            '%d unexpected bytes follow the %s' % (count, what),
            trailing=count, what=what)

    def _note_length(self, message, **details):
        return self.add_issue(ISSUE_LENGTH, message, **details)

    def _demote_issues(self, code, message, **details):
        """Downgrade length/checksum errors on a fragment to informational.

        Transport headers in the first fragment of a fragmented datagram
        announce a length and checksum that cover the *whole* datagram; the
        bytes that would confirm them arrive in later fragments.  Those errors
        are therefore not errors yet - they can only be judged after
        reassembly (which is what :class:`dpkt.defrag.Defragmenter` does).
        """
        demoted = []
        for issue in self._issues:
            if issue.is_error and issue.code != ISSUE_FRAGMENT:
                info = dict(issue.details, original_code=issue.code)
                info.update(details)
                demoted.append(Issue(code, issue.layer, message, **info))
            else:
                demoted.append(issue)
        self._issues = demoted

    def _note_undecoded(self, payload_proto, reason, error=None):
        """Record that the payload could not be handed to its decoder.

        The raw bytes stay in :attr:`data`; they are never relabeled as a
        successfully parsed upper layer.
        """
        details = {'protocol': payload_proto, 'reason': str(reason)}
        code = ISSUE_UNDECODED
        if isinstance(error, TruncatedPacket):
            code = ISSUE_TRUNCATED
        elif isinstance(error, InvalidPacket):
            code = ISSUE_INVALID_HEADER
        return self.add_issue(code, reason, **details)

    def _decode_payload(self, dispatch, payload, proto, fallback=None):
        """Decode ``payload`` through ``dispatch``, recording failures.

        Mirrors the historical ``try: self.data = table[key](buf) except
        (KeyError, UnpackError): self.data = buf`` behaviour, but records why
        the payload was not inserted into the next parser.  Returns the decoded
        inner packet, or ``None`` with :attr:`data` left as the raw fallback.

        A decoder that rejects the bytes (truncated or impossible header) is
        never inserted, so a malformed payload cannot be presented to an
        upper-layer parser as though its header were trustworthy.
        """
        try:
            inner_cls = dispatch()
        except KeyError:
            self.data = payload if fallback is None else fallback
            self._note_undecoded(proto, 'no decoder registered for protocol %r' % (proto,))
            return None
        try:
            inner = inner_cls(payload)
        except KeyError:
            self.data = payload if fallback is None else fallback
            self._note_undecoded(proto, 'no decoder registered for protocol %r' % (proto,))
            return None
        except (UnpackError, struct.error) as e:
            self.data = payload if fallback is None else fallback
            reason = '%s could not be decoded: %s' % (
                getattr(inner_cls, '__name__', proto), e)
            self._note_undecoded(getattr(inner_cls, '__name__', proto),
                                 reason, error=e)
            return None
        # A layer that parsed but whose *own header* contradicts the outer
        # length fields is not trustworthy as the next layer.  Keep the raw
        # bytes so an upper-layer parser never consumes a bad header.
        bad_header = [i for i in getattr(inner, '_issues', ())
                      if i.is_error and i.code in (ISSUE_LENGTH, ISSUE_INVALID_HEADER)]
        if bad_header:
            self.data = payload if fallback is None else fallback
            self.add_issue(
                bad_header[0].code,
                '%s header is inconsistent (%s); payload kept raw' %
                (getattr(inner_cls, '__name__', proto), bad_header[0].message),
                protocol=getattr(inner_cls, '__name__', proto))
            return None
        self.data = inner
        setattr(self, inner.__class__.__name__.lower(), inner)
        return inner

    def __len__(self):
        return self.__hdr_len__ + len(self.data)

    # legacy
    def __iter__(self):
        return iter((fld, getattr(self, fld)) for fld in self.__class__.__hdr_fields__)

    def __getitem__(self, kls):
        """Return the 1st occurrence of the underlying <kls> data layer, raise KeyError otherwise."""
        dd = self.data
        while isinstance(dd, Packet):
            if dd.__class__ == kls:
                return dd
            dd = dd.data
        raise KeyError(kls)

    def __contains__(self, kls):
        """Return True is the given <kls> data layer is present in the stack."""
        try:
            return bool(self.__getitem__(kls))
        except KeyError:
            return False

    def _create_public_fields(self):
        """Construct __public_fields__ to be used inside __repr__ and pprint"""
        l_ = []
        for field_name, _, _ in getattr(self, '__hdr__', []):
            # public fields defined in __hdr__; "public" means not starting with an underscore
            if field_name[0] != '_':
                l_.append(field_name)  # (1)

            # if a field name starts with an underscore, and does NOT contain more underscores,
            # it is considered hidden and is ignored (good for fields reserved for future use)

            # if a field name starts with an underscore, and DOES contain more underscores,
            # it is viewed as a complex field where underscores separate the named properties
            # of the class;
            elif '_' in field_name[1:]:
                # (1) search for these properties in __bit_fields__ where they are explicitly defined
                if field_name in getattr(self, '__bit_fields__', {}):
                    for (prop_name, _) in self.__bit_fields__[field_name]:
                        if isinstance(getattr(self.__class__, prop_name, None), property):
                            l_.append(prop_name)

                # (2) split by underscore into 1- and 2-component names and look for properties with such names;
                # Example: _foo_bar_baz -> look for properties named "foo", "bar", "baz", "foo_bar" and "bar_baz"
                # (but not "foo_bar_baz" since it contains more than one underscore)
                else:
                    fns = field_name[1:].split('_')
                    for prop_name in chain(fns, ('_'.join(x) for x in zip(fns, fns[1:]))):
                        if isinstance(getattr(self.__class__, prop_name, None), property):
                            l_.append(prop_name)

        # check for duplicates, there shouldn't be any
        assert len(l_) == len(set(l_))
        self.__class__.__public_fields__ = l_  # store it in the class attribute

    def __repr__(self):
        if self.__public_fields__ is None:
            self._create_public_fields()

        # Collect and display protocol fields in order:
        # 1. public fields defined in __hdr__, unless their value is default
        # 2. properties derived from _private fields defined in __hdr__ and __bit_fields__
        # 3. dynamically added fields from self.__dict__, unless they are _private
        # 4. self.data when it's present
        l_ = []

        # (1) and (2) are done via __public_fields__; just filter out defaults here
        for field_name in self.__public_fields__:
            field_value = getattr(self, field_name)

            if (hasattr(self, '__hdr_defaults__') and
               field_name in self.__hdr_defaults__ and
               field_value == self.__hdr_defaults__[field_name]):
                continue

            if (hasattr(self, '__bit_fields_defaults__') and
               field_name in self.__bit_fields_defaults__ and
               field_value == self.__bit_fields_defaults__[field_name]):
                continue

            l_.append('%s=%r' % (field_name, field_value))

        # (3)
        l_.extend(
            ['%s=%r' % (attr_name, attr_value)
             for attr_name, attr_value in iteritems(self.__dict__)
             if attr_name[0] != '_' and                   # exclude _private attributes
                attr_name != self.data.__class__.__name__.lower()])  # exclude fields like ip.udp
        # (4)
        if self.data:
            l_.append('data=%r' % self.data)
        return '%s(%s)' % (self.__class__.__name__, ', '.join(l_))

    def pprint(self, indent=1):
        """Human friendly pretty-print."""
        if self.__public_fields__ is None:
            self._create_public_fields()

        l_ = []

        def add_field(fn, fv):
            """name=value,  # pretty-print form (if available)"""
            try:
                l_.append('%s=%r,  # %s' % (fn, fv, self.__pprint_funcs__[fn](fv)))
            except (AttributeError, KeyError):
                l_.append('%s=%r,' % (fn, fv))

        for field_name in self.__public_fields__:
            add_field(field_name, getattr(self, field_name))

        for attr_name, attr_value in iteritems(self.__dict__):
            if (attr_name[0] != '_' and                   # exclude _private attributes
               attr_name != self.data.__class__.__name__.lower()):  # exclude fields like ip.udp
                if type(attr_value) == list and attr_value:  # expand non-empty lists to print one item per line
                    l_.append('%s=[' % attr_name)
                    for av1 in attr_value:
                        l_.append('  ' + repr(av1) + ',')  # XXX - TODO: support pretty-print
                    l_.append('],')
                else:
                    add_field(attr_name, attr_value)

        print('%s(' % self.__class__.__name__)  # class name, opening brace
        for ii in l_:
            print(' ' * indent, '%s' % ii)

        if self.data:
            if isinstance(self.data, Packet):  # recursively descend to lower layers
                print(' ' * indent, 'data=', end='')
                self.data.pprint(indent=indent + 2)
            else:
                print(' ' * indent, 'data=%r' % self.data)
        print(' ' * (indent - 1), end='')
        print(')  # %s' % self.__class__.__name__)  # closing brace  # class name

    def __str__(self):
        return str(self.__bytes__())

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.data)

    def pack_hdr(self):
        """Return packed header string."""
        try:
            return self._pack_hdr(
                *[getattr(self, k) for k in self.__hdr_fields__]
            )
        except (TypeError, struct.error):
            vals = []
            for k in self.__hdr_fields__:
                v = getattr(self, k)
                if isinstance(v, tuple):
                    vals.extend(v)
                else:
                    vals.append(v)
            try:
                return struct.pack(self.__hdr_fmt__, *vals)
            except struct.error as e:
                raise PackError(str(e))

    def pack(self):
        """Return packed header + self.data string."""
        return bytes(self)

    def unpack(self, buf):
        """Unpack packet header fields from buf, and set self.data."""
        for k, v in compat_izip(self.__hdr_fields__,
                                struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
            setattr(self, k, v)
        self.data = buf[self.__hdr_len__:]


# XXX - ''.join([(len(`chr(x)`)==3) and chr(x) or '.' for x in range(256)])
__vis_filter = (
    b'................................ !"#$%&\'()*+,-./0123456789:;<=>?'
    b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~.'
    b'................................................................'
    b'................................................................')


def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % compat_ord(x) for x in line])
        line = line.translate(__vis_filter).decode('utf-8')
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)


def in_cksum_add(s, buf):
    n = len(buf)
    cnt = (n // 2) * 2
    a = struct.unpack('<{}H'.format(n // 2), buf[:cnt])  # unpack as little endian words
    res = s + sum(a)
    if cnt != n:
        res += compat_ord(buf[-1])
    return res


def in_cksum_done(s):
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ntole(~s & 0xffff)


def in_cksum(buf):
    """Return computed Internet checksum."""
    return in_cksum_done(in_cksum_add(0, buf))


def test_utils():
    __buf = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e'
    __hd = '  0000:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e     ...............'
    h = hexdump(__buf)
    assert (h == __hd)
    assert in_cksum_add(0, __buf) == 12600  # endianness
    c = in_cksum(__buf)
    assert (c == 51150)


# test Packet.__getitem__ and __contains__ methods
def test_getitem_contains():
    import pytest

    class Foo(Packet):
        __hdr__ = (('foo', 'I', 0),)

    class Bar(Packet):
        __hdr__ = (('bar', 'I', 0),)

    class Baz(Packet):
        __hdr__ = (('baz', 'I', 0),)

    class Zeb(Packet):
        pass

    ff = Foo(foo=1, data=Bar(bar=2, data=Baz(attr=Zeb())))

    # __contains__
    assert Bar in ff
    assert Baz in ff
    assert Baz in ff.data
    assert Zeb not in ff
    assert Zeb not in Baz()

    # __getitem__
    assert isinstance(ff[Bar], Bar)
    assert isinstance(ff[Baz], Baz)

    assert isinstance(ff[Bar][Baz], Baz)
    with pytest.raises(KeyError):
        ff[Baz][Bar]

    with pytest.raises(KeyError):
        ff[Zeb]

    with pytest.raises(KeyError):
        Bar()[Baz]


def test_pack_hdr_overflow():
    """Try to fit too much data into struct packing"""
    import pytest

    class Foo(Packet):
        __hdr__ = (
            ('foo', 'I', 1),
            ('bar', 'I', (1, 2)),
        )

    foo = Foo(foo=2**32)
    with pytest.raises(PackError):
        bytes(foo)


def test_bit_fields_overflow():
    """Try to fit too much data into too few bits"""
    import pytest

    class Foo(Packet):
        __hdr__ = (
            ('_a_b', 'B', 0),
        )
        __bit_fields__ = {
            '_a_b': (
                ('a', 2),
                ('b', 6),
            )
        }

    foo = Foo()
    with pytest.raises(ValueError):
        foo.a = 5


def test_bit_field_size_is_calculated_using_standard_size():
    class Foo(Packet):
        __hdr__ = (
            ("_a_b", "L", 0),
        )

        __bit_fields__ = {
            "_a_b": (
                ("a", 2*8),
                ("b", 2*8),
            ),
        }

        __byte_order__ = "<"

    foo = Foo()


def test_pack_hdr_tuple():
    """Test the unpacking of a tuple for a single format string"""
    class Foo(Packet):
        __hdr__ = (
            ('bar', 'II', (1, 2)),
        )

    foo = Foo()
    b = bytes(foo)
    assert b == b'\x00\x00\x00\x01\x00\x00\x00\x02'


def test_unpacking_failure():
    # during dynamic-sized unpacking in the subclass there may be struct.errors raised,
    # but if the header has unpacked correctly, a different error is raised by the superclass
    import pytest

    class TestPacket(Packet):
        __hdr__ = (('test', 'B', 0),)

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.attribute = struct.unpack('B', buf[1:])

    with pytest.raises(UnpackError, match="invalid TestPacket: "):
        TestPacket(b'\x00')  # header will unpack successfully


def test_repr():
    """complex test for __repr__, __public_fields__"""

    class TestPacket(Packet):
        __hdr__ = (
            ('_a_b', 'B', 1),     # 'a' and 'b' bit fields
            ('_rsv', 'B', 0),     # hidden reserved field
            ('_c_flag', 'B', 1),  # 'c_flag' property
            ('d', 'B', 0)         # regular field
        )

        __bit_fields__ = {
            '_a_b': (
                ('a', 4),
                ('b', 4),
            ),
        }

        @property
        def c_flag(self):
            return (self.a | self.b)

    # init with default values
    test_packet = TestPacket()

    # test repr with all default values so expect no output
    # (except for the explicitly defined property, where dpkt doesn't process defaults yet)
    assert repr(test_packet) == "TestPacket(c_flag=1)"

    # init with non-default values
    test_packet = TestPacket(b'\x12\x11\x00\x04')

    # ensure the display fields were cached and propagated via class attribute
    assert test_packet.__public_fields__ == ['a', 'b', 'c_flag', 'd']

    # verify repr
    assert repr(test_packet) == "TestPacket(a=1, b=2, c_flag=3, d=4)"


def test_issue_codes_and_severity():
    assert Issue(ISSUE_TRUNCATED, Packet, 'x').is_error
    assert Issue(ISSUE_CHECKSUM, Packet, 'x').is_error
    assert not Issue(ISSUE_PADDING, Packet, 'x').is_error
    assert not Issue(ISSUE_UNDECODED, Packet, 'x').is_error
    assert not Issue(ISSUE_FRAGMENT, Packet, 'x').is_error
    assert Issue(ISSUE_TRAILING, Packet, 'x').severity == 'error'
    assert Issue(ISSUE_FRAGMENT, Packet, 'x').severity == 'info'


def test_report_status_and_error_types():
    r = Report()
    assert r.valid and r.status == 'ok' and bool(r)

    r.add(Issue(ISSUE_PADDING, Packet, 'pad'))
    assert r.valid and r.status == 'ok' and r.informational and not r.errors

    r.add(Issue(ISSUE_TRAILING, Packet, 'extra'))
    assert not r.valid and r.status == ISSUE_TRAILING
    assert isinstance(_error_from_report(r), TrailingDataError)

    r2 = Report([Issue(ISSUE_CHECKSUM, Packet, 'bad')])
    assert isinstance(_error_from_report(r2), ChecksumError)
    r3 = Report([Issue(ISSUE_INVALID_HEADER, Packet, 'bad')])
    assert isinstance(_error_from_report(r3), LengthMismatchError)
    r4 = Report([Issue(ISSUE_TRUNCATED, Packet, 'short')])
    assert isinstance(_error_from_report(r4), TruncationError)


def test_packet_records_issues_privately():
    class Frag(Packet):
        __hdr__ = (('x', 'B', 0),)

    p = Frag()
    assert p.issues == []
    p.add_issue(ISSUE_TRUNCATED, 'short', announced=4, captured=1)
    assert len(p.issues) == 1 and p.issues[0].details['announced'] == 4
    # issue bookkeeping must not leak into __repr__ or the public packet dict
    assert 'issues' not in repr(p)
    assert '_issues' not in repr(p)


def test_decode_payload_never_exposes_rejected_layer():
    """A payload whose decoder raises is left raw with a recorded reason."""
    class Inner(Packet):
        __hdr__ = (('x', 'I', 0),)

    class Outer(Packet):
        __hdr__ = (('t', 'B', 0),)
        _typesw = {1: Inner}

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self._decode_payload(lambda: self._typesw[self.t], self.data, self.t)

    good = Outer(b'\x01\x00\x00\x00\x2a')
    assert isinstance(good.data, Inner) and good.data.x == 0x2a
    assert good.issues == []

    bad = Outer(b'\x01\x00\x00')  # Inner needs 4 bytes
    assert bad.data == b'\x00\x00'  # raw payload, not a half-decoded header
    codes = [i.code for i in bad.issues]
    assert ISSUE_TRUNCATED in codes
    assert bad.issues[0].is_error

    unknown = Outer(b'\x09xx')
    assert unknown.data == b'xx'
    assert unknown.issues[0].code == ISSUE_UNDECODED
    assert not unknown.issues[0].is_error
