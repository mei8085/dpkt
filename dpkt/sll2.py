# -*- coding: utf-8 -*-
"""Linux libpcap "cooked v2" capture encapsulation."""
from __future__ import absolute_import

from . import arp
from . import dpkt
from . import ethernet


class SLL2(dpkt.Packet):
    """Linux libpcap "cooked v2" capture encapsulation.

    See https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html

    Attributes:
        __hdr__: Header fields of SLLv2.
    """

    __hdr__ = (
        ('ethtype', 'H', ethernet.ETH_TYPE_IP),
        ('mbz', 'H', 0),  # reserved
        ('intindex', 'i', 0),  # the 1-based index of the interface on which the packet was observed
        ('hrd', 'H', arp.ARP_HRD_ETH),
        ('type', 'B', 0),  # 0: to us, 1: bcast, 2: mcast, 3: other, 4: from us
        ('hlen', 'B', 6),  # hardware address length
        ('hdr', '8s', b''),  # first 8 bytes of link-layer header
    )
    _typesw = ethernet.Ethernet._typesw

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self._unpack_inner(
            lambda: self._typesw[self.ethtype], self.data, self.ethtype)


def test_sll2():
    sll2data = (b'\x08\x00\x00\x00\x00\x00\x00\x03\x00\x01\x00\x06\x00\x0b\xdb\x52\x0e\x08\xf6\x7f'
                b'\x45\x00\x00\x34\xcc\x6c\x40\x00\x40\x06\x74\x08\x82\xd9\xfa\x8e\x82\xd9\xfa\x0d')
    sll2test = SLL2(sll2data)
    assert sll2test.type == 0
    assert sll2test.mbz == 0
    assert sll2test.intindex == 3
    assert sll2test.hrd == 1
    assert sll2test.hlen == 6
    assert sll2test.hdr == b'\x00\x0b\xdb\x52\x0e\x08\xf6\x7f'
    assert sll2test.ethtype == 0x0800

    # give invalid ethtype of 0x1234 to make sure error is handled
    sll2data2 = (b'\x12\x34\x00\x00\x00\x00\x00\x03\x00\x01\x00\x06\x00\x0b\xdb\x52\x0e\x08\xf6\x7f'
                b'\x45\x00\x00\x34\xcc\x6c\x40\x00\x40\x06\x74\x08\x82\xd9\xfa\x8e\x82\xd9\xfa\x0d')
    sll2test2 = SLL2(sll2data2)


def test_sll2_unknown_vs_malformed():
    from dpkt import dpkt

    # SLL2 header is 20 bytes: ethtype(2) mbz(2) intindex(4) hrd(2)
    #                          type(1) hlen(1) hdr(8)
    sll2_hdr = (b'\x12\x34'   # ethtype (unregistered below)
                b'\x00\x00'   # mbz
                b'\x03\x00\x00\x00'  # intindex
                b'\x01\x00'   # hrd
                b'\x00\x06'   # type, hlen
                b'\xdb\x52\x0e\x08\x00\x00\x00\x00')  # hdr (8)
    pkt = SLL2(sll2_hdr + b'payload')
    assert isinstance(pkt.unpack_error, dpkt.UnknownProtocolError)
    assert pkt.unpack_error.type_id == 0x1234
    assert pkt.data == b'payload'

    # ethtype 0x0800 (IP) selected, IP header truncated
    bad_ip = b'\x45\x00\x00'
    hdr_ip = b'\x08\x00' + sll2_hdr[2:]
    pkt2 = SLL2(hdr_ip + bad_ip)
    err = pkt2.unpack_error
    assert isinstance(err, dpkt.InnerPacketUnpackError)
    assert not isinstance(err, dpkt.UnknownProtocolError)
    assert err.protocol_name == 'IP'
    assert isinstance(err.inner_error, dpkt.UnpackError)
    assert pkt2.data == bad_ip
