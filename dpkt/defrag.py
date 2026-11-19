# -*- coding: utf-8 -*-
"""Safe IPv4 fragment reassembly.

This module implements a defensive IPv4 defragmenter with deterministic
behavior for overlapping data:

* Non-overlapping fragments are concatenated in offset order.
* Fully duplicate fragments (same offset, same length, same payload) are
  tolerated and simply ignored.
* Any other overlap (partial overlap, or a retransmitted fragment whose
  payload differs) makes the set ambiguous and the whole set is rejected.
* Fragments that extend beyond the total datagram length announced by the
  final fragment (or beyond the configured maximum datagram size) cause the
  set to be rejected.

Resource usage is bounded for the whole reassembly lifecycle: the number of
concurrent fragment sets, the number of fragments per set, the number of
holes (gaps) in a set, and the total reassembled length are all limited, so
hostile or corrupt fragment streams cannot consume unbounded memory.

When a set is rejected it is discarded immediately and the same
Defragmenter instance keeps working: subsequently fed valid datagrams are
reassembled and returned through the usual interface (a parsed
:class:`dpkt.ip.IP` packet with its metadata and payload).
"""
from __future__ import absolute_import
from __future__ import print_function

import bisect
from collections import OrderedDict

from . import dpkt
from . import ip


class FragmentationError(dpkt.Error):
    """A fragment set was ambiguous, malformed, or exceeded safety limits.

    The offending set has already been discarded when this is raised; the
    Defragmenter that raised it remains usable for subsequent datagrams.
    """


class _FragmentSet(object):
    """State of one in-flight reassembly (one datagram)."""
    __slots__ = ('fragments', 'total', 'first')

    def __init__(self):
        self.fragments = []  # sorted list of (start, end, payload), non-overlapping
        self.total = None    # total payload length, known once the final fragment arrives
        self.first = None    # the offset-0 fragment, donor of the reassembled header

    def holes(self):
        """Number of gaps in the byte coverage of this set."""
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
        """True when the total length is known and fully covered."""
        if self.total is None or not self.fragments or self.fragments[0][0] != 0:
            return False
        covered = 0
        for start, end, _ in self.fragments:
            if start > covered:
                return False
            covered = end
        return covered >= self.total


class Defragmenter(object):
    """Stateful, resource-bounded IPv4 fragment reassembler.

    Feed parsed :class:`dpkt.ip.IP` packets with :meth:`feed`. Unfragmented
    packets are passed through unchanged. Incomplete sets yield ``None``;
    a completed set yields a single reassembled :class:`dpkt.ip.IP` packet
    whose payload is parsed through the normal IP dispatch table.

    Ambiguous or limit-exceeding sets are discarded and reported by raising
    :class:`FragmentationError`; the Defragmenter itself stays valid and can
    keep processing further packets, including a fresh set with the same key.

    Attributes:
        max_datagrams: maximum number of concurrent in-flight fragment sets;
            the oldest set is evicted when the limit is reached.
        max_fragments: maximum number of fragments buffered per set.
        max_holes: maximum number of coverage gaps tolerated per set.
        max_datagram_size: maximum reassembled payload length in bytes.
    """

    def __init__(self, max_datagrams=256, max_fragments=64, max_holes=32,
                 max_datagram_size=ip.IP_LEN_MAX):
        self.max_datagrams = max_datagrams
        self.max_fragments = max_fragments
        self.max_holes = max_holes
        self.max_datagram_size = max_datagram_size
        self._sets = OrderedDict()  # (src, dst, id, p) -> _FragmentSet, LRU ordered

    def __len__(self):
        return len(self._sets)

    def _reject(self, key, reason):
        """Discard the set identified by key and raise FragmentationError."""
        self._sets.pop(key, None)
        raise FragmentationError(reason)

    def feed(self, pkt):
        """Feed one parsed IPv4 packet.

        Returns the packet itself if it is not fragmented, ``None`` while a
        fragment set is still incomplete, or a reassembled ``dpkt.ip.IP``
        packet once a set completes. Raises FragmentationError when the set
        this fragment belongs to must be rejected.
        """
        if pkt.offset == 0 and not pkt.mf:
            return pkt  # not fragmented; pass through untouched

        key = (pkt.src, pkt.dst, pkt.id, pkt.p)
        payload = bytes(pkt.data)
        start = pkt.offset * 8
        end = start + len(payload)

        if end > self.max_datagram_size:
            self._reject(key, 'fragment exceeds maximum datagram size')

        fs = self._sets.get(key)
        if fs is None:
            if len(self._sets) >= self.max_datagrams:
                self._sets.popitem(last=False)  # evict the oldest set
            fs = _FragmentSet()
            self._sets[key] = fs
        else:
            self._sets.move_to_end(key)

        if not pkt.mf:
            # final fragment: it fixes the total payload length
            if fs.total is not None and fs.total != end:
                self._reject(key, 'conflicting total datagram lengths')
            fs.total = end
        if fs.total is not None and end > fs.total:
            self._reject(key, 'fragment exceeds total datagram length')

        for (s, e, d) in fs.fragments:
            if start < e and s < end:
                if start == s and end == e and payload == d:
                    return None  # fully duplicate fragment; ignore it
                self._reject(key, 'overlapping fragments with ambiguous content')

        if len(fs.fragments) >= self.max_fragments:
            self._reject(key, 'too many fragments in one datagram')

        bisect.insort(fs.fragments, (start, end, payload))
        if start == 0:
            fs.first = pkt

        if fs.holes() > self.max_holes:
            self._reject(key, 'too many holes in one datagram')

        if fs.complete():
            return self._build(key, fs)
        return None

    def _build(self, key, fs):
        """Assemble a completed set into a single parsed IP packet."""
        del self._sets[key]
        payload = b''.join(d for (_, _, d) in fs.fragments)[:fs.total]
        first = fs.first
        out = ip.IP(tos=first.tos, id=first.id, ttl=first.ttl, p=first.p,
                    src=first.src, dst=first.dst, data=payload)
        out.opts = first.opts
        out.rf = first.rf
        out.df = first.df
        # Serialize (recomputing length and header checksum) and re-parse so
        # the payload is decoded through the standard IP protocol dispatch.
        return ip.IP(bytes(out))


def defragment(pkts, **kwargs):
    """Reassemble an iterable of IPv4 packets with a fresh Defragmenter.

    Returns the list of completed datagrams (reassembled fragments and
    unfragmented packets) in the order they completed. FragmentationError
    raised for a rejected set propagates to the caller.
    """
    defragmenter = Defragmenter(**kwargs)
    out = []
    for pkt in pkts:
        r = defragmenter.feed(pkt)
        if r is not None:
            out.append(r)
    return out


def _make_fragment(id_, offset_bytes, payload, mf,
                   src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=17):
    pkt = ip.IP(id=id_, src=src, dst=dst, p=p, data=payload)
    pkt.offset = offset_bytes // 8
    pkt.mf = 1 if mf else 0
    return pkt


def _udp_payload(size):
    from . import udp
    u = udp.UDP(sport=111, dport=222, data=b'X' * (size - 8))
    u.ulen = 8 + len(u.data)
    return bytes(u)


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
    # metadata preserved and payload parsed through the original interface
    assert pkt.id == 0x1234
    assert pkt.src == b'\x01\x02\x03\x04'
    assert pkt.dst == b'\x05\x06\x07\x08'
    assert pkt.p == 17
    assert pkt.offset == 0
    assert pkt.mf == 0
    assert pkt.udp.sport == 111
    assert pkt.udp.dport == 222
    assert pkt.udp.data == b'X' * 40


def test_duplicate_fragment_tolerated():
    payload = _udp_payload(32)
    frags = [_make_fragment(7, 0, payload[:16], True),
             _make_fragment(7, 16, payload[16:], False)]
    d = Defragmenter()
    assert d.feed(frags[0]) is None
    assert d.feed(frags[0]) is None  # exact retransmission ignored
    pkt = d.feed(frags[1])
    assert pkt is not None
    assert pkt.udp.data == b'X' * 24
    # duplicates fed after completion start a fresh set harmlessly
    assert d.feed(frags[0]) is None


def test_partial_overlap_rejected_and_parser_reusable():
    payload = _udp_payload(32)
    d = Defragmenter()
    assert d.feed(_make_fragment(9, 0, payload[:16], True)) is None
    try:
        # overlaps bytes 8..16 of the first fragment with different content
        d.feed(_make_fragment(9, 8, b'Y' * 16, True))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0  # the ambiguous set was discarded
    # the same defragmenter still reassembles the next valid datagram,
    # even one reusing the same (src, dst, id, p) key
    assert d.feed(_make_fragment(9, 0, payload[:16], True)) is None
    pkt = d.feed(_make_fragment(9, 16, payload[16:], False))
    assert pkt is not None
    assert pkt.udp.data == b'X' * 24


def test_same_span_different_content_rejected():
    d = Defragmenter()
    assert d.feed(_make_fragment(3, 0, b'A' * 16, True)) is None
    try:
        d.feed(_make_fragment(3, 0, b'B' * 16, True))
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_fragment_beyond_total_length_rejected():
    d = Defragmenter()
    assert d.feed(_make_fragment(5, 0, b'A' * 16, True)) is None
    assert d.feed(_make_fragment(5, 24, b'B' * 8, False)) is None  # total = 32, hole at 16..24
    try:
        d.feed(_make_fragment(5, 32, b'C' * 8, True))  # extends past total
        assert False, 'expected FragmentationError'
    except FragmentationError:
        pass
    assert len(d) == 0


def test_conflicting_total_lengths_rejected():
    d = Defragmenter()
    assert d.feed(_make_fragment(6, 0, b'A' * 16, True)) is None
    assert d.feed(_make_fragment(6, 24, b'B' * 8, False)) is None  # total = 32, hole at 16..24
    try:
        d.feed(_make_fragment(6, 32, b'C' * 8, False))  # claims total = 40
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
    assert d.feed(_make_fragment(2, 16, b'B' * 8, True)) is None  # one hole
    try:
        d.feed(_make_fragment(2, 32, b'C' * 8, False))  # two holes
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
    assert d.feed(_make_fragment(1, 0, b'A' * 8, True)) is None
    assert d.feed(_make_fragment(2, 0, b'B' * 8, True)) is None
    assert d.feed(_make_fragment(3, 0, b'C' * 8, True)) is None
    assert len(d) == 2
    # the id=1 set was evicted; id=2 and id=3 remain and can complete
    assert d.feed(_make_fragment(2, 8, b'B' * 8, False)) is not None
    assert d.feed(_make_fragment(3, 8, b'C' * 8, False)) is not None
    assert len(d) == 0


def test_defragment_convenience():
    payload = _udp_payload(32)
    pkts = [_make_fragment(8, 16, payload[16:], False),
            ip.IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=0, data=b'raw'),
            _make_fragment(8, 0, payload[:16], True)]
    out = defragment(pkts)
    assert len(out) == 2
    assert out[0].data == b'raw'  # unfragmented packet passed through
    assert out[1].udp.data == b'X' * 24
