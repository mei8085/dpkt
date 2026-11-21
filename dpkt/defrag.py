# -*- coding: utf-8 -*-
"""Consistency-checked IPv4 fragment reassembly.

Receiving a datagram split across IP fragments is the last place where the
trust decision has to happen: the individual fragments can each look
plausible, while the *reassembled* datagram is illegal (overlapping bytes,
a hole, a total length that no fragment ever announced, or a transport header
that contradicts the reassembled length).

This module implements a stateful reassembler with those checks built in:

* Non-overlapping fragments are concatenated in offset order.
* A fragment that is an exact duplicate (same offset, same length, same bytes)
  is tolerated and ignored.
* Any other overlap is ambiguous and rejects the whole set,
  :class:`ReassemblyError` is raised and the set is discarded.
* Fragments past the total length announced by the last fragment, or past the
  configured maximum datagram size, reject the set.
* On completion the reassembled datagram is re-parsed through the normal IP
  dispatch table and verified - by default with
  :func:`dpkt.validation.check_packet` - so that a payload whose announced
  length or checksum does not survive reassembly is rejected, not returned.

Resource use is bounded across the whole lifecycle: the number of concurrent
sets, fragments per set, holes per set and the reassembled length are all
capped so hostile fragment streams cannot consume unbounded memory.

After a set is rejected the same reassembler keeps working; subsequently fed
valid datagrams are reassembled and returned normally.
"""
from __future__ import absolute_import
from __future__ import print_function

import bisect
import struct
from collections import OrderedDict

from . import dpkt
from . import ip


class FragmentationError(dpkt.ReassemblyError):
    """A fragment set was ambiguous, malformed, or exceeded safety limits.

    The offending set has already been discarded when this is raised; the
    reassembler that raised it remains usable.
    """


class _FragmentSet(object):
    """State of one in-flight datagram."""

    __slots__ = ('fragments', 'total', 'first', 'seen')

    def __init__(self):
        self.fragments = []  # sorted list of (start, end, payload)
        self.total = None    # total payload length, known once the last frag arrives
        self.first = None    # the offset-0 fragment, donor of the header
        self.seen = set()    # (start, end) already stored, for duplicate detection

    def holes(self):
        holes = 0
        covered = 0
        for start, end, _ in self.fragments:
            if start > covered:
                holes += 1
            covered = end
        if self.total is not None and covered < self.total:
            holes += 1
        return holes

    def complete(self):
        if self.total is None or not self.fragments or self.fragments[0][0] != 0:
            return False
        covered = 0
        for start, end, _ in self.fragments:
            if start > covered:
                return False
            covered = end
        return covered >= self.total

    def overlaps(self, start, end):
        """True when [start, end) overlaps any stored fragment."""
        for s, e, _ in self.fragments:
            if start < e and s < end:
                return True
        return False

    def exact_duplicate(self, start, end, payload):
        for s, e, d in self.fragments:
            if s == start and e == end:
                return d == payload
        return False

    def payload(self):
        return b''.join(d for (_, _, d) in self.fragments)[:self.total]


class Defragmenter(object):
    """Stateful, resource-bounded and consistency-checked IPv4 reassembler.

    Feed parsed :class:`dpkt.ip.IP` packets with :meth:`feed`.  Unfragmented
    packets pass through unchanged; incomplete sets return ``None``; a set
    completes with a reassembled :class:`dpkt.ip.IP` packet.

    Attributes:
        max_datagrams: concurrent in-flight sets (the oldest is evicted).
        max_fragments: fragments buffered per set.
        max_holes: coverage gaps tolerated per set.
        max_datagram_size: maximum reassembled payload length in bytes.
        verify: when true the completed datagram is checked with
            :func:`dpkt.validation.check_packet`; an invalid reassembly raises
            :class:`FragmentationError` instead of being returned.
    """

    def __init__(self, max_datagrams=256, max_fragments=64, max_holes=32,
                 max_datagram_size=ip.IP_LEN_MAX, verify=True):
        self.max_datagrams = max_datagrams
        self.max_fragments = max_fragments
        self.max_holes = max_holes
        self.max_datagram_size = max_datagram_size
        self.verify = verify
        self._sets = OrderedDict()  # key -> _FragmentSet, LRU ordered

    def __len__(self):
        return len(self._sets)

    def _reject(self, key, reason, packet=None):
        self._sets.pop(key, None)
        report = None
        if packet is not None:
            report = dpkt.Report(getattr(packet, 'issues', None))
        raise FragmentationError(reason, report=report)

    def reset(self):
        """Discard every in-flight fragment set (e.g. between captures)."""
        self._sets.clear()

    def feed(self, pkt):
        """Feed one parsed IPv4 packet.

        Returns ``pkt`` if it is not fragmented, ``None`` while the set is
        incomplete, or a reassembled :class:`dpkt.ip.IP`.  Raises
        :class:`FragmentationError` when the set must be rejected.
        """
        if pkt.offset == 0 and not pkt.mf:
            return pkt

        key = (pkt.src, pkt.dst, pkt.id, pkt.p)
        payload = bytes(pkt.data)
        start = pkt.offset * 8
        end = start + len(payload)

        if end > self.max_datagram_size:
            self._reject(key, 'fragment exceeds maximum datagram size', pkt)

        fs = self._sets.get(key)
        if fs is None:
            if len(self._sets) >= self.max_datagrams:
                self._sets.popitem(last=False)  # evict the oldest set
            fs = _FragmentSet()
            self._sets[key] = fs
        else:
            self._sets.move_to_end(key)

        if not pkt.mf:
            if fs.total is not None and fs.total != end:
                self._reject(key, 'conflicting total datagram lengths', pkt)
            fs.total = end
        if fs.total is not None and end > fs.total:
            self._reject(key, 'fragment exceeds total datagram length', pkt)

        if fs.overlaps(start, end):
            if not fs.exact_duplicate(start, end, payload):
                self._reject(key, 'overlapping fragments with ambiguous content', pkt)
            return None  # exact retransmission; keep the stored copy

        if len(fs.fragments) >= self.max_fragments:
            self._reject(key, 'too many fragments in one datagram', pkt)

        bisect.insort(fs.fragments, (start, end, payload))
        fs.seen.add((start, end))
        if start == 0:
            fs.first = pkt

        if fs.holes() > self.max_holes:
            self._reject(key, 'too many holes in one datagram', pkt)

        if fs.complete():
            return self._build(key, fs)
        return None

    def _build(self, key, fs):
        del self._sets[key]
        payload = fs.payload()
        first = fs.first
        out = ip.IP(tos=first.tos, id=first.id, ttl=first.ttl, p=first.p,
                    src=first.src, dst=first.dst, data=payload)
        out.opts = first.opts
        out.rf = first.rf
        out.df = first.df
        # Serialize (recomputing length and checksum) and re-parse so the
        # payload is decoded through the standard IP protocol dispatch.
        built = ip.IP(bytes(out))

        if self.verify:
            from . import validation
            report = validation.check_packet(built, verify_checksums=True)
            if report.errors:
                raise FragmentationError(
                    'reassembled datagram is inconsistent: %s' % report.reason,
                    report=report)
        return built


def defragment(pkts, **kwargs):
    """Reassemble an iterable of IPv4 packets with a fresh Defragmenter.

    Returns the list of completed datagrams (reassembled fragments and
    unfragmented packets) in completion order.

    A rejected set raises :class:`FragmentationError`.  To keep going after a
    bad set, drive a :class:`Defragmenter` directly and handle the exception::

        d = Defragmenter()
        out, errors = [], []
        for pkt in pkts:
            try:
                r = d.feed(pkt)
            except FragmentationError as e:
                errors.append(e)
                continue
            if r is not None:
                out.append(r)
    """
    d = Defragmenter(**kwargs)
    out = []
    for pkt in pkts:
        r = d.feed(pkt)
        if r is not None:
            out.append(r)
    return out


def _make_fragment(id_, offset_bytes, payload, mf,
                   src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17):
    pkt = ip.IP(id=id_, src=src, dst=dst, p=p, data=payload)
    pkt.offset = offset_bytes // 8
    pkt.mf = 1 if mf else 0
    return pkt


def _udp_payload(size, bad_sum=False, src=b'\x01\x02\x03\x04',
                  dst=b'\x05\x06\x07\x08'):
    from . import udp
    u = udp.UDP(sport=111, dport=222, data=b'X' * (size - 8))
    u.ulen = size
    seg = bytearray(udp.UDP.pack_hdr(u) + u.data)
    if not bad_sum:
        # fill in a correct checksum so the verifier has something to check
        pseudo = dpkt.in_cksum_add(
            0, struct.pack('>4s4sxBH', src, dst, 17, len(seg)))
        seg[6:8] = b'\x00\x00'
        seg[6:8] = struct.pack('>H', dpkt.in_cksum_done(
            dpkt.in_cksum_add(pseudo, bytes(seg))))
    else:
        seg[6:8] = b'\xde\xad'
    return bytes(seg)


def test_unfragmented_passthrough():
    d = Defragmenter()
    pkt = ip.IP(id=1, src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17, data=b'hello')
    assert d.feed(pkt) is pkt
    assert len(d) == 0


def test_reassemble_out_of_order():
    payload = _udp_payload(48)
    frags = [_make_fragment(0x1234, 0, payload[:16], True),
             _make_fragment(0x1234, 16, payload[16:32], True),
             _make_fragment(0x1234, 32, payload[32:], False)]
    d = Defragmenter()
    assert d.feed(frags[2]) is None
    assert d.feed(frags[0]) is None
    assert len(d) == 1
    pkt = d.feed(frags[1])
    assert pkt is not None
    assert len(d) == 0
    assert pkt.id == 0x1234
    assert pkt.offset == 0
    assert pkt.mf == 0
    assert pkt.udp.sport == 111
    assert pkt.udp.data == b'X' * 40


def test_duplicate_fragment_tolerated():
    payload = _udp_payload(32)
    frags = [_make_fragment(7, 0, payload[:16], True),
             _make_fragment(7, 16, payload[16:], False)]
    d = Defragmenter()
    assert d.feed(frags[0]) is None
    assert d.feed(frags[0]) is None
    pkt = d.feed(frags[1])
    assert pkt is not None
    assert pkt.udp.data == b'X' * 24


def test_partial_overlap_rejected_and_parser_reusable():
    payload = _udp_payload(32)
    d = Defragmenter()
    assert d.feed(_make_fragment(9, 0, payload[:16], True)) is None
    try:
        d.feed(_make_fragment(9, 8, b'Y' * 16, True))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0
    assert d.feed(_make_fragment(9, 0, payload[:16], True)) is None
    pkt = d.feed(_make_fragment(9, 16, payload[16:], False))
    assert pkt is not None
    assert pkt.udp.data == b'X' * 24


def test_reassembled_datagram_with_bad_udp_length_rejected():
    """A reassembled payload whose UDP length disagrees must not be returned."""
    good = _udp_payload(32)
    # make the first fragment's UDP length field announce more than the total
    bad = bytearray(good)
    bad[4:6] = b'\x00\xff'  # ulen = 255, bigger than the 32-byte datagram
    bad = bytes(bad)
    d = Defragmenter()
    assert d.feed(_make_fragment(11, 0, bad[:16], True)) is None
    try:
        d.feed(_make_fragment(11, 16, bad[16:], False))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0
    # reassembler still usable
    assert d.feed(_make_fragment(12, 0, good[:16], True)) is None
    pkt = d.feed(_make_fragment(12, 16, good[16:], False))
    assert pkt is not None


def test_reassembled_datagram_with_bad_checksum_rejected():
    payload = _udp_payload(32, bad_sum=True)
    d = Defragmenter()
    assert d.feed(_make_fragment(13, 0, payload[:16], True)) is None
    # the checksum only covers the whole UDP segment, which exists only once
    # the datagram has been reassembled
    try:
        d.feed(_make_fragment(13, 16, payload[16:], False))
    except FragmentationError:
        pass
    else:
        raise AssertionError('expected FragmentationError for a bad checksum')
    assert len(d) == 0


def test_fragment_beyond_total_length_rejected():
    d = Defragmenter()
    assert d.feed(_make_fragment(5, 0, b'A' * 16, True)) is None
    assert d.feed(_make_fragment(5, 24, b'B' * 8, False)) is None
    try:
        d.feed(_make_fragment(5, 32, b'C' * 8, True))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_conflicting_total_lengths_rejected():
    d = Defragmenter()
    assert d.feed(_make_fragment(6, 0, b'A' * 16, True)) is None
    assert d.feed(_make_fragment(6, 24, b'B' * 8, False)) is None
    try:
        d.feed(_make_fragment(6, 32, b'C' * 8, False))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_fragment_count_limit():
    d = Defragmenter(max_fragments=2)
    assert d.feed(_make_fragment(1, 0, b'A' * 8, True)) is None
    assert d.feed(_make_fragment(1, 8, b'B' * 8, True)) is None
    try:
        d.feed(_make_fragment(1, 16, b'C' * 8, False))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_hole_limit():
    d = Defragmenter(max_holes=1)
    assert d.feed(_make_fragment(2, 0, b'A' * 8, True)) is None
    assert d.feed(_make_fragment(2, 16, b'B' * 8, True)) is None
    try:
        d.feed(_make_fragment(2, 32, b'C' * 8, False))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_datagram_size_limit():
    d = Defragmenter(max_datagram_size=32)
    try:
        d.feed(_make_fragment(4, 0, b'A' * 64, True))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_datagram_count_limit_evicts_oldest():
    d = Defragmenter(max_datagrams=2)
    p2 = _udp_payload(16)
    p3 = _udp_payload(16)
    assert d.feed(_make_fragment(1, 0, _udp_payload(16)[:8], True)) is None
    assert d.feed(_make_fragment(2, 0, p2[:8], True)) is None
    assert d.feed(_make_fragment(3, 0, p3[:8], True)) is None
    assert len(d) == 2
    assert d.feed(_make_fragment(2, 8, p2[8:], False)) is not None
    assert d.feed(_make_fragment(3, 8, p3[8:], False)) is not None
    assert len(d) == 0


def test_defragment_convenience():
    payload = _udp_payload(32)
    pkts = [_make_fragment(8, 16, payload[16:], False),
            ip.IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=0, data=b'raw'),
            _make_fragment(8, 0, payload[:16], True)]
    out = defragment(pkts)
    assert len(out) == 2
    assert out[0].data == b'raw'
    assert out[1].udp.data == b'X' * 24


def test_wire_level_reassembly():
    """The reassembled datagram re-parses from its serialized bytes."""
    from . import udp

    payload = _udp_payload(64, src=b'\x0a\x00\x00\x01',
                           dst=b'\x0a\x00\x00\x02')
    frames = []
    for off in (0, 24, 48):
        mf = off + 24 < 64
        chunk = payload[off:off + 24]
        pkt = ip.IP(id=77, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                    p=17, data=chunk)
        pkt.offset = off // 8
        pkt.mf = 1 if mf else 0
        frames.append(ip.IP(bytes(pkt)))
    d = Defragmenter()
    assert d.feed(frames[2]) is None
    assert d.feed(frames[0]) is None
    out = d.feed(frames[1])
    assert out is not None
    assert out.p == 17
    assert isinstance(out.data, udp.UDP)
    assert out.udp.ulen == 64
    assert len(out.udp.data) == 56


def test_reset_discards_inflight_sets():
    d = Defragmenter()
    assert d.feed(_make_fragment(21, 0, b'A' * 8, True)) is None
    assert len(d) == 1
    d.reset()
    assert len(d) == 0
