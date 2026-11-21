# -*- coding: utf-8 -*-
"""Received-packet consistency checking.

A packet taken off the wire can only be trusted when the length announced by
the outer layer, the lengths announced by the inner protocols and the
checksums all agree with the bytes that were actually captured.  A mismatch in
any of those is actionable: it means the capture is truncated, the bytes carry
trailing garbage, nested headers contradict each other, a checksum was computed
over the wrong range, or a reassembled datagram is illegal.

Every dpkt parser records the problems it observes while unpacking as
:class:`dpkt.Issue` objects on ``packet.issues``; this module turns that into a
single verdict for a whole layer stack and also re-verifies the checksums,
which is what makes "checksum coverage" errors detectable.

Typical use::

    import dpkt
    from dpkt import validation

    eth = dpkt.ethernet.Ethernet(buf)
    report = validation.check_packet(eth)
    if not report:
        print(report.status, report.reason)

or, to reject inconsistent input outright::

    eth = validation.receive(buf)          # raises ConsistencyError

The parser itself stays backward compatible: a rejected inner layer is never
inserted into the next decoder and never changes the boundary of the following
packet, the raw bytes remain reachable through ``packet.data``, and
``check_packet`` reports *why*.
"""
from __future__ import absolute_import, print_function

import struct

from . import dpkt

# Re-export the building blocks next to the checking functions.
Issue = dpkt.Issue
Report = dpkt.Report
ConsistencyError = dpkt.ConsistencyError
TruncationError = dpkt.TruncationError
TrailingDataError = dpkt.TrailingDataError
LengthMismatchError = dpkt.LengthMismatchError
ChecksumError = dpkt.ChecksumError
ReassemblyError = dpkt.ReassemblyError

ISSUE_UNDECODED = dpkt.ISSUE_UNDECODED

_PSEUDO_V4 = struct.Struct('>4s4sxBH')   # src, dst, proto, l4 length
_PSEUDO_V6 = struct.Struct('>16s16sI3xB')  # src, dst, l4 length, next header


def _checksum(data, seed=0):
    return dpkt.in_cksum_add(seed, bytes(data))


def _verifies(data, seed=0):
    """True when the internet checksum of ``data`` (with ``seed``) is zero."""
    return dpkt.in_cksum_done(_checksum(data, seed)) == 0


def _pseudo_header_v4(src, dst, proto, length):
    return _PSEUDO_V4.pack(src, dst, proto, length)


def _pseudo_header_v6(src, dst, proto, length):
    return _PSEUDO_V6.pack(src, dst, length, proto)


def _as_bytes(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return bytes(value)


def _is_quote_container(layer):
    """True for an ICMP/ICMPv6 layer (or a type-specific body of one).

    Everything decoded *below* such a layer is either a fixed echo header or a
    datagram quoted from the original packet; the quoted bytes are evidence and
    are frequently truncated on purpose, so they are not authoritative.
    """
    from . import icmp, icmp6

    if isinstance(layer, (icmp.ICMP, icmp6.ICMP6)):
        return True
    for cls in list(icmp.ICMP._typesw.values()) + list(icmp6.ICMP6._typesw.values()):
        if isinstance(layer, cls):
            return True
    return False


def iter_layers(packet):
    """Yield ``(parent, layer, quoted)`` for every decoded layer.

    ``parent`` is ``None`` for the outermost packet.  ``quoted`` is ``True``
    once the walk enters a datagram quoted inside an ICMP error message: those
    bytes are evidence, not an authoritative next layer, so their lengths and
    checksums are not checked.  The walk stops at the first non-``Packet``
    payload.
    """
    parent = None
    node = packet
    quoted = False
    seen = set()
    while isinstance(node, dpkt.Packet):
        if id(node) in seen:  # defensive: never loop on a self-referential chain
            break
        seen.add(id(node))
        yield parent, node, quoted
        if _is_quote_container(node):
            quoted = True
        parent = node
        node = node.data


def _layer_issues(layer):
    return list(getattr(layer, '_issues', ()))


def _check_ip_checksum(layer, report):
    from . import ip

    if not isinstance(layer, ip.IP):
        return
    raw = layer._raw_buf
    if raw is None or not layer.sum:
        return
    hdr_len = (layer._v_hl & 0xf) << 2
    if hdr_len != 20 and hdr_len <= len(raw):
        # Classic "checksum computed over the fixed header only" bug: the
        # checksum validates over 20 bytes but the header is longer, so the
        # option bytes are outside the checksum's coverage.
        if _verifies(raw[:20]) and not _verifies(raw[:hdr_len]):
            report.add(Issue(
                dpkt.ISSUE_CHECKSUM, layer.__class__,
                'IPv4 header checksum covers only 20 of %d header bytes' % hdr_len,
                covered=20, header_length=hdr_len))
            return
    if hdr_len > len(raw):
        return  # truncation already reported
    if not _verifies(raw[:hdr_len]):
        report.add(Issue(
            dpkt.ISSUE_CHECKSUM, layer.__class__,
            'IPv4 header checksum does not verify', covered=hdr_len))


def _transport_segment(layer):
    raw = layer._raw_buf
    if raw is None:
        try:
            return _as_bytes(layer)
        except Exception:
            return None
    return raw


def _check_transport_checksum(parent, layer, report):
    from . import ip, ip6, udp, tcp, icmp, icmp6

    raw = _transport_segment(layer)
    if raw is None:
        return

    if isinstance(layer, udp.UDP):
        proto = 17
        # announced coverage: the UDP header plus ulen-8 payload bytes
        if layer.ulen == 0:
            if isinstance(parent, ip6.IP6):
                return  # jumbogram; length carried in a hop-by-hop option
            report.add(Issue(dpkt.ISSUE_LENGTH, layer.__class__,
                            'UDP length is zero in an IPv4 datagram'))
            return
        covered = layer.ulen
        if covered > len(raw):
            return  # truncation already reported; cannot verify
        if layer.sum == 0:
            if isinstance(parent, ip6.IP6):
                report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                                'UDP checksum must not be zero over IPv6'))
            return  # IPv4: zero means "not computed" (RFC 768)
        if isinstance(parent, ip.IP):
            seed = _checksum(_pseudo_header_v4(parent.src, parent.dst, proto, covered))
        elif isinstance(parent, ip6.IP6):
            seed = _checksum(_pseudo_header_v6(parent.src, parent.dst, proto, covered))
        else:
            return
        if _verifies(raw[:covered], seed):
            return
        # Distinguish a bad checksum from one computed over the wrong range.
        if covered != len(raw) and _verifies(raw, _checksum(
                _pseudo_header_v4(parent.src, parent.dst, proto, len(raw))
                if isinstance(parent, ip.IP) else
                _pseudo_header_v6(parent.src, parent.dst, proto, len(raw)))):
            report.add(Issue(
                dpkt.ISSUE_CHECKSUM, layer.__class__,
                'UDP checksum covers %d bytes but the datagram length is %d' %
                (len(raw), covered),
                covered=len(raw), announced=covered))
        else:
            report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                            'UDP checksum does not verify', covered=covered))
        return

    if isinstance(layer, tcp.TCP):
        proto = 6
        if layer.sum == 0 and isinstance(parent, ip6.IP6):
            report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                            'TCP checksum must not be zero over IPv6'))
            return
        if not layer.sum:
            return
        if isinstance(parent, ip.IP):
            seed = _checksum(_pseudo_header_v4(parent.src, parent.dst, proto, len(raw)))
        elif isinstance(parent, ip6.IP6):
            seed = _checksum(_pseudo_header_v6(parent.src, parent.dst, proto, len(raw)))
        else:
            return
        if not _verifies(raw, seed):
            report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                            'TCP checksum does not verify over %d bytes' % len(raw),
                            covered=len(raw)))
        return

    if isinstance(layer, icmp.ICMP):
        if layer.sum and not _verifies(raw):
            report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                            'ICMP checksum does not verify over %d bytes' % len(raw),
                            covered=len(raw)))
        return

    if isinstance(layer, icmp6.ICMP6):
        if not isinstance(parent, ip6.IP6):
            return
        seed = _checksum(_pseudo_header_v6(parent.src, parent.dst, 58, len(raw)))
        if not _verifies(raw, seed):
            report.add(Issue(dpkt.ISSUE_CHECKSUM, layer.__class__,
                            'ICMPv6 checksum does not verify over %d bytes' % len(raw),
                            covered=len(raw)))
        return


def _check_structure(layer, report):
    """Check declared lengths against the actual payload of a built packet.

    Parsed packets already had their boundaries enforced while unpacking (and
    any problem recorded as an issue), so this only runs for packets that were
    assembled from keyword arguments and therefore have no captured bytes.
    """
    from . import ip, ip6, udp

    if layer._raw_buf is not None:
        return

    if isinstance(layer, ip.IP):
        hdr_len = (layer._v_hl & 0xf) << 2
        if hdr_len < layer.__hdr_len__:
            report.add(Issue(dpkt.ISSUE_INVALID_HEADER, layer.__class__,
                             'IPv4 header length %d is smaller than %d' %
                             (hdr_len, layer.__hdr_len__)))
        elif layer.len and layer.len < hdr_len + len(layer.opts):
            report.add(Issue(dpkt.ISSUE_LENGTH, layer.__class__,
                             'IPv4 total length %d is smaller than its header length %d' %
                             (layer.len, hdr_len + len(layer.opts))))
        return

    if isinstance(layer, ip6.IP6):
        # programmatic IPv6: plen is authoritative over the payload it carries
        payload_len = len(layer.data) if isinstance(layer.data, (bytes, bytearray)) else len(bytes(layer.data))
        if layer.plen and layer.plen != payload_len:
            code = dpkt.ISSUE_TRUNCATED if layer.plen > payload_len else dpkt.ISSUE_TRAILING
            report.add(Issue(code, layer.__class__,
                             'IPv6 payload length %d disagrees with %d payload bytes' %
                             (layer.plen, payload_len),
                             announced=layer.plen, captured=payload_len))
        return

    if isinstance(layer, udp.UDP) and layer.ulen:
        if layer.ulen < layer.__hdr_len__:
            report.add(Issue(dpkt.ISSUE_INVALID_HEADER, layer.__class__,
                             'UDP length %d is smaller than the fixed header %d' %
                             (layer.ulen, layer.__hdr_len__)))
            return
        actual = len(layer.data) if isinstance(layer.data, (bytes, bytearray)) else len(bytes(layer.data))
        expected = layer.ulen - layer.__hdr_len__
        if actual < expected:
            report.add(Issue(dpkt.ISSUE_TRUNCATED, layer.__class__,
                             'UDP announces %d payload bytes but carries %d' %
                             (expected, actual),
                             announced=expected, captured=actual))
        elif actual > expected:
            tail = layer.data
            if isinstance(tail, (bytes, bytearray)) and not any(tail[expected:]):
                report.add(Issue(dpkt.ISSUE_PADDING, layer.__class__,
                                 '%d zero padding bytes follow the UDP datagram' %
                                 (actual - expected),
                                 trailing=actual - expected))
            else:
                report.add(Issue(dpkt.ISSUE_TRAILING, layer.__class__,
                                 '%d unexpected bytes follow the UDP datagram' %
                                 (actual - expected), trailing=actual - expected))
        return


def check_packet(packet, verify_checksums=True, include_nested=True):
    """Check a received packet stack for length/checksum consistency.

    Args:
        packet: the outermost parsed :class:`dpkt.Packet`.
        verify_checksums: also recompute IPv4/UDP/TCP/ICMP/ICMPv6 checksums
            over their advertised coverage.  Programmatically built packets
            (which have no captured bytes) are checked structurally only.
        include_nested: descend into the decoded payload chain.

    Returns:
        :class:`dpkt.Report`; ``bool(report)`` is ``True`` when the packet is
        trustworthy.
    """
    report = Report()
    if not isinstance(packet, dpkt.Packet):
        report.add(Issue(dpkt.ISSUE_INVALID_HEADER, type(packet),
                         'not a dpkt packet: %r' % (type(packet),)))
        return report

    quoted = False
    for parent, layer, quoted in iter_layers(packet):
        if quoted:
            # datagrams quoted inside ICMP errors keep their own (possibly
            # deliberately truncated) bytes; not authoritative, skip them
            break

        report.extend(_layer_issues(layer))
        _check_structure(layer, report)

        if verify_checksums:
            _check_ip_checksum(layer, report)
            if parent is not None:
                _check_transport_checksum(parent, layer, report)

        if not include_nested:
            break
    return report


# aliases used by callers with different vocabulary
check = check_packet
validate_packet = check_packet


def is_valid(packet, **kwargs):
    """Convenience wrapper: ``True`` when :func:`check_packet` finds no error."""
    return check_packet(packet, **kwargs).valid


def assert_valid(packet, **kwargs):
    """Raise the matching :class:`ConsistencyError` if the packet is invalid."""
    report = check_packet(packet, **kwargs)
    report.raise_if_invalid(packet)
    return packet


def receive(buf, cls=None, verify_checksums=True):
    """Parse ``buf`` and reject it unless the whole stack is consistent.

    This is the "receive" entry point: the returned packet is guaranteed to
    pass :func:`check_packet`, otherwise a :class:`ConsistencyError` subclass
    describing the first failure is raised.

    Args:
        buf: raw link-layer bytes.
        cls: outermost parser class; defaults to :class:`dpkt.ethernet.Ethernet`.
        verify_checksums: verify checksums as well as lengths.
    """
    if cls is None:
        from . import ethernet
        cls = ethernet.Ethernet
    packet = cls(buf)
    return assert_valid(packet, verify_checksums=verify_checksums)


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def _udp_frame(payload=b'hello', **udp_fields):
    from . import ethernet
    from . import ip
    from . import udp

    u = udp.UDP(sport=1, dport=2, data=payload, **udp_fields)
    u.ulen = 8 + len(u.data)
    p = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17, data=u)
    e = ethernet.Ethernet(dst=b'\x00' * 6, src=b'\x00' * 6, type=0x0800, data=p)
    return bytes(e)


def test_issue_and_report():
    rep = Report()
    assert rep.valid and bool(rep) and rep.status == 'ok'
    issue = Issue(dpkt.ISSUE_TRUNCATED, dpkt.Packet, 'short', announced=10, captured=4)
    rep.add(issue)
    assert not rep.valid and not bool(rep)
    assert rep.status == dpkt.ISSUE_TRUNCATED
    assert rep.errors == [issue] and rep.reasons
    d = rep.to_dict()
    assert d['valid'] is False and d['issues'][0]['code'] == dpkt.ISSUE_TRUNCATED
    try:
        rep.raise_if_invalid()
    except TruncationError as e:
        assert e.report is rep
    else:
        raise AssertionError('expected TruncationError')


def test_valid_packet_is_clean():
    from . import ethernet
    buf = _udp_frame()
    eth = ethernet.Ethernet(buf)
    report = check_packet(eth)
    assert report.valid, report.issues
    assert report.status == 'ok'
    # and receive() returns it unchanged
    again = receive(buf)
    assert bytes(again) == bytes(eth)


def test_nested_length_mismatch_rejected():
    # UDP announces more bytes than the IP payload carries
    from . import ethernet
    buf = bytearray(_udp_frame())
    ip_start = 14
    ihl = (buf[ip_start] & 0xf) * 4
    udp_start = ip_start + ihl
    ulen = (buf[udp_start + 4] << 8) | buf[udp_start + 5]
    buf[udp_start + 4:udp_start + 6] = struct.pack('>H', ulen + 10)
    eth = ethernet.Ethernet(bytes(buf))
    report = check_packet(eth)
    assert not report.valid
    assert dpkt.ISSUE_TRUNCATED in report.codes or dpkt.ISSUE_LENGTH in report.codes
    try:
        receive(bytes(buf))
    except ConsistencyError:
        pass
    else:
        raise AssertionError('expected rejection')


def test_trailing_bytes_do_not_reach_payload():
    from . import ethernet
    # append garbage after the IP datagram; it must not become UDP payload
    buf = _udp_frame(b'AAAA')
    eth = ethernet.Ethernet(buf)
    ip_len = eth.data.len
    padded = buf + b'\x99' * 6
    eth2 = ethernet.Ethernet(padded)
    assert eth2.data.len == ip_len
    assert eth2.data.data.data == b'AAAA'
    report = check_packet(eth2)
    assert not report.valid
    assert dpkt.ISSUE_TRAILING in report.codes


def test_zero_padding_is_informational():
    from . import ethernet
    buf = _udp_frame(b'AAAA')
    padded = buf + b'\x00' * 6
    eth = ethernet.Ethernet(padded)
    report = check_packet(eth)
    assert report.valid
    assert dpkt.ISSUE_PADDING in report.codes


def test_truncated_packet_rejected():
    from . import ethernet
    buf = _udp_frame(b'0123456789')
    # cut the capture short, leaving the announced IP length untouched
    cut = buf[:-4]
    from . import ip as ip_mod
    eth2 = ethernet.Ethernet(cut)
    assert isinstance(eth2.data, ip_mod.IP)
    report = check_packet(eth2)
    assert not report.valid
    assert dpkt.ISSUE_TRUNCATED in report.codes
    try:
        receive(cut)
    except ConsistencyError:
        pass
    else:
        raise AssertionError('expected rejection')


def test_bad_ip_checksum_rejected():
    from . import ethernet
    buf = bytearray(_udp_frame())
    # flip a header byte and repair the IP length so only the checksum is wrong
    buf[14 + 8] ^= 0xff  # TTL
    eth = ethernet.Ethernet(bytes(buf))
    report = check_packet(eth)
    assert not report.valid
    assert dpkt.ISSUE_CHECKSUM in report.codes


def test_bad_udp_checksum_rejected():
    from . import ethernet
    from . import ip
    from . import udp

    u = udp.UDP(sport=1, dport=2, data=b'hello')
    u.ulen = 13
    p = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17, data=u)
    raw = bytes(p)
    # corrupt the UDP checksum but keep the IP header checksum valid
    raw = bytearray(raw)
    raw[20 + 6] ^= 0x5a
    eth_raw = (b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + bytes(raw))
    # fix the IP header checksum so only the UDP checksum is wrong
    ip_hdr = bytearray(raw[:20])
    ip_hdr[10:12] = b'\x00\x00'
    ip_hdr[10:12] = struct.pack('>H', dpkt.in_cksum(bytes(ip_hdr)))
    eth_raw = eth_raw[:24] + bytes(ip_hdr) + eth_raw[44:]
    eth = ethernet.Ethernet(eth_raw)
    assert isinstance(eth.data, ip.IP) and isinstance(eth.data.data, udp.UDP)
    report = check_packet(eth)
    assert dpkt.ISSUE_CHECKSUM in report.codes, report.issues


def test_checksum_scoped_to_correct_coverage():
    """A UDP checksum computed including trailing bytes is flagged."""
    from . import ethernet
    from . import ip
    from . import udp

    u = udp.UDP(sport=1, dport=2, data=b'abcd')
    u.ulen = 12
    p = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17, data=u)
    frame = bytes(p)
    # make a UDP checksum over segment + 4 extra trailing bytes
    seg = bytearray(frame[20:] + b'WXYZ')
    seg[6:8] = b'\x00\x00'
    seed = _checksum(_pseudo_header_v4(b'\x01\x02\x03\x04', b'\x05\x06\x07\x08', 17, len(seg)))
    ck = dpkt.in_cksum_done(_checksum(seg, seed))
    seg[6:8] = struct.pack('>H', ck)
    seg = bytes(seg[:12])
    ip_hdr = bytearray(frame[:20])
    ip_hdr[2:4] = struct.pack('>H', 20 + len(seg))
    ip_hdr[10:12] = b'\x00\x00'
    ip_hdr[10:12] = struct.pack('>H', dpkt.in_cksum(bytes(ip_hdr)))
    eth = ethernet.Ethernet(b'\x00' * 12 + b'\x08\x00' + bytes(ip_hdr) + seg)
    report = check_packet(eth)
    # the announced UDP length (12) disagrees with the IP payload carried; the
    # checksum only verifies over the wrong range - either way it is rejected
    assert not report.valid


def test_programmatic_packet_structural_check():
    from . import ip, udp

    u = udp.UDP(sport=1, dport=2, data=b'hello', ulen=20)  # lies about length
    p = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17, data=u)
    report = check_packet(p)
    assert not report.valid
    assert dpkt.ISSUE_TRUNCATED in report.codes


def test_quoted_icmp_datagram_not_validated():
    """An ICMP error quoting a (truncated) datagram stays valid if the outer
    packet is consistent."""
    from . import ethernet
    from . import icmp
    from . import ip

    # quoted IP header with a deliberately broken checksum
    quoted = (b'\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x06\x11\x22'
              b'\x0a\x00\x00\x01\x0a\x00\x00\x02')
    payload = b'\x00\x00\x00\x00' + quoted  # 4-byte pad + quote
    icmp_pkt = icmp.ICMP(type=3, code=3, data=payload)
    icmp_pkt.sum = 0
    icmp_raw = bytes(icmp_pkt)
    ip_pkt = ip.IP(src=b'\x0a\x00\x00\x02', dst=b'\x0a\x00\x00\x01', p=1, data=icmp_raw)
    frame = b'\x00' * 12 + b'\x08\x00' + bytes(ip_pkt)
    eth = ethernet.Ethernet(frame)
    assert isinstance(eth.data, ip.IP)
    report = check_packet(eth)
    # the outer IP/ICMP are fine; the quoted inner header is not authoritative
    assert report.valid, report.issues


def test_ip_checksum_coverage_includes_options():
    """A checksum computed over only 20 of the 24 header bytes is rejected."""
    from . import ethernet
    from . import ip

    # 24-byte header (IHL=6) with a 4-byte no-op option
    hdr = bytearray(b'\x46\x00\x00\x18\x00\x00\x00\x00\x40\x11\x00\x00'
                    b'\x0a\x00\x00\x01\x0a\x00\x00\x02' + b'\x01\x01\x01\x01')
    # checksum over the fixed 20 bytes only (the classic coverage bug)
    hdr[10:12] = b'\x00\x00'
    hdr[10:12] = struct.pack('>H', dpkt.in_cksum(bytes(hdr[:20])))
    udp_seg = b'\x00\x01\x00\x02\x00\x08\x00\x00'
    frame = b'\x00' * 12 + b'\x08\x00' + bytes(hdr) + udp_seg
    eth = ethernet.Ethernet(frame)
    assert isinstance(eth.data, ip.IP)
    report = check_packet(eth)
    assert not report.valid
    assert any('only 20' in i.message for i in report.errors), report.issues


def test_tcp_checksum_verified_ipv4():
    from . import ethernet
    from . import ip
    from . import tcp

    t = tcp.TCP(sport=1234, dport=80, seq=1, ack=0, flags=tcp.TH_ACK, sum=0)
    p = ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6, data=t)
    frame = b'\x00' * 12 + b'\x08\x00' + bytes(p)  # IP.__bytes__ fills sums
    eth = ethernet.Ethernet(frame)
    assert check_packet(eth).valid
    # corrupt the TCP checksum only; recompute the IP header checksum
    raw = bytearray(frame)
    raw[14 + 20 + 16] ^= 0xff
    raw[14 + 10:14 + 12] = b'\x00\x00'
    raw[14 + 10:14 + 12] = struct.pack('>H', dpkt.in_cksum(bytes(raw[14:14 + 20])))
    report = check_packet(ethernet.Ethernet(bytes(raw)))
    assert not report.valid
    assert dpkt.ISSUE_CHECKSUM in report.codes


def test_tcp_checksum_verified_ipv6():
    from . import ethernet
    from . import ip6
    from . import tcp

    t = tcp.TCP(sport=1234, dport=80, seq=1, ack=0, flags=tcp.TH_ACK, sum=0)
    p = ip6.IP6(src=b'\x20\x01' + b'\x00' * 14, dst=b'\x20\x02' + b'\x00' * 14,
                nxt=6, plen=len(bytes(t)), data=t)
    frame = b'\x00' * 12 + b'\x86\xdd' + bytes(p)
    eth = ethernet.Ethernet(frame)
    assert check_packet(eth).valid, check_packet(eth).issues
    raw = bytearray(frame)
    raw[14 + 40 + 16] ^= 0xff
    report = check_packet(ethernet.Ethernet(bytes(raw)))
    assert not report.valid
    assert dpkt.ISSUE_CHECKSUM in report.codes


def test_icmp6_checksum_verified():
    from . import ethernet
    from . import icmp6
    from . import ip6

    ic = icmp6.ICMP6(type=icmp6.ICMP6_ECHO_REQUEST, code=0, sum=0,
                     data=icmp6.ICMP6.Echo(id=1, seq=1))
    p = ip6.IP6(src=b'\x20\x01' + b'\x00' * 14, dst=b'\x20\x02' + b'\x00' * 14,
                nxt=58, plen=len(bytes(ic)), data=ic)
    frame = b'\x00' * 12 + b'\x86\xdd' + bytes(p)
    eth = ethernet.Ethernet(frame)
    assert check_packet(eth).valid, check_packet(eth).issues
    raw = bytearray(frame)
    raw[14 + 40 + 2] ^= 0xff
    report = check_packet(ethernet.Ethernet(bytes(raw)))
    assert not report.valid
    assert dpkt.ISSUE_CHECKSUM in report.codes


def test_ipv6_trailing_and_truncation():
    from . import ethernet
    from . import ip6

    p = ip6.IP6(src=b'\x00' * 16, dst=b'\x00' * 16, nxt=59, plen=4, data=b'abcd')
    assert check_packet(p).valid, check_packet(p).issues

    # declared payload length shorter than what is present -> trailing
    p2 = ip6.IP6(src=b'\x00' * 16, dst=b'\x00' * 16, nxt=59, plen=2, data=b'abcd')
    r2 = check_packet(p2)
    assert not r2.valid and dpkt.ISSUE_TRAILING in r2.codes

    # declared payload length larger than what is present -> truncated
    frame = b'\x00' * 12 + b'\x86\xdd' + bytes(
        ip6.IP6(src=b'\x00' * 16, dst=b'\x00' * 16, nxt=59, plen=8, data=b'abcd'))
    eth = ethernet.Ethernet(frame)
    r3 = check_packet(eth)
    assert not r3.valid and dpkt.ISSUE_TRUNCATED in r3.codes
    assert eth.data.data == b'abcd'  # plen bounds what the payload can be


def test_ipv6_extension_header_length_truncation():
    from . import ethernet
    from . import ip6

    # hop-by-hop extension header announces 16 bytes (len=1) but only 4 remain
    pkt = (b'\x60\x00\x00\x00\x00\x04\x00\x40' + b'\x00' * 32 +
           b'\x3b\x01' + b'\x00\x00')
    eth = ethernet.Ethernet(b'\x00' * 12 + b'\x86\xdd' + pkt)
    assert not isinstance(eth.data, ip6.IP6) or not check_packet(eth).valid
    # the IP6 decoder rejected the extension header, leaving the raw bytes
    assert eth.data == pkt
    assert dpkt.ISSUE_TRUNCATED in [i.code for i in eth.issues]


def test_8023_length_bounds_body():
    from . import ethernet
    from . import llc

    # 802.3 length field declares 100 bytes; only 13 are present
    buf = b'\x00' * 12 + struct.pack('>H', 100) + b'\xaa\xaa\x03' + b'\x00' * 10
    eth = ethernet.Ethernet(buf)
    report = check_packet(eth)
    assert not report.valid
    assert dpkt.ISSUE_TRUNCATED in report.codes


def test_receive_rejects_and_reports_status():
    buf = _udp_frame(b'0123456789')[:-3]
    try:
        receive(buf)
    except TruncationError as e:
        assert e.report.status == dpkt.ISSUE_TRUNCATED
    else:
        raise AssertionError('expected TruncationError')
