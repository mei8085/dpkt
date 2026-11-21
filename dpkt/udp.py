# $Id: udp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""User Datagram Protocol."""
from __future__ import absolute_import

from . import dpkt

UDP_HDR_LEN = 8
UDP_PORT_MAX = 65535


class UDP(dpkt.Packet):
    """User Datagram Protocol.

    User Datagram Protocol (UDP) is one of the core members of the Internet protocol suite.
    With UDP, computer applications can send messages, in this case referred to as datagrams,
    to other hosts on an Internet Protocol (IP) network. Prior communications are not required
    in order to set up communication channels or data paths.

    Attributes:
        __hdr__: Header fields of UDP.
            sport: (int): Source port. (2 bytes)
            dport: (int): Destination port. (2 bytes)
            ulen: (int): Length. (2 bytes)
            sum: (int): Checksum. (2 bytes)
    """

    __hdr__ = (
        ('sport', 'H', 0xdead),
        ('dport', 'H', 0),
        ('ulen', 'H', 8),
        ('sum', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        # ulen covers the UDP header and payload.  It is authoritative: bytes
        # beyond it are not part of this datagram and must not leak into
        # self.data (otherwise a truncated/oversized length would shift the
        # boundary of the next packet).  A zero ulen only happens for IPv6
        # jumbograms, where the length is carried elsewhere.
        if self.ulen == 0:
            return
        if self.ulen < self.__hdr_len__:
            raise dpkt.InvalidPacket(
                'UDP length %d is smaller than the fixed header %d' %
                (self.ulen, self.__hdr_len__))
        payload_len = self.ulen - self.__hdr_len__
        payload = self.data
        if len(payload) < payload_len:
            # captured fewer bytes than announced: keep what we have, but make
            # the truncation visible instead of pretending the datagram is whole
            self._note_truncated(payload_len, len(payload), what='UDP payload')
            self.data = payload
        else:
            if len(payload) > payload_len:
                # extra bytes are outside the announced datagram; zero padding is
                # tolerated as informational, anything else is an error
                self._note_trailing(len(payload) - payload_len, what='UDP datagram')
            self.data = payload[:payload_len]


def test_udp_ulen_bounds_payload():
    """The UDP length field is authoritative for the datagram's boundary."""
    # ulen == 12, header + 4 payload bytes, 5 bytes of trailing garbage
    buf = b'\x00\x01\x00\x02\x00\x0c\x00\x00' + b'ABCD' + b'ZZZZZ'
    u = UDP(buf)
    assert u.ulen == 12
    assert u.data == b'ABCD'
    assert dpkt.ISSUE_TRAILING in [i.code for i in u.issues]


def test_udp_ulen_truncated_is_recorded():
    # ulen announces 12 bytes but only 10 were captured
    buf = b'\x00\x01\x00\x02\x00\x0c\x00\x00' + b'AB'
    u = UDP(buf)
    assert u.data == b'AB'
    issues = [i for i in u.issues if i.code == dpkt.ISSUE_TRUNCATED]
    assert issues and issues[0].details['announced'] == 4


def test_udp_ulen_smaller_than_header_rejected():
    import pytest
    buf = b'\x00\x01\x00\x02\x00\x04\x00\x00'
    with pytest.raises(dpkt.InvalidPacket):
        UDP(buf)


def test_udp_zero_ulen_not_bounded():
    # a zero length is only legal for IPv6 jumbograms; the buffer is kept whole
    buf = b'\x00\x01\x00\x02\x00\x00\x00\x00' + b'payload'
    u = UDP(buf)
    assert u.data == b'payload'
    assert u.issues == []
