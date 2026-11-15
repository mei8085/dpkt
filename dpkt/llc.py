# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from . import stp


class LLC(dpkt.Packet):
    """802.2 Logical Link Control (LLC) data communication protocol.

    Attributes:
        __hdr__ = (
            ('dsap', 'B', 0xaa),   # Destination Service Access Point
            ('ssap', 'B', 0xaa),   # Source Service Access Point
            ('ctl', 'B', 3)        # Control Byte
        )
    """

    __hdr__ = (
        ('dsap', 'B', 0xaa),   # Destination Service Access Point
        ('ssap', 'B', 0xaa),   # Source Service Access Point
        ('ctl', 'B', 3)        # Control Byte
    )

    @property
    def is_snap(self):
        return self.dsap == self.ssap == 0xaa

    def unpack(self, buf):
        from .ethernet import Ethernet, ETH_TYPE_IP, ETH_TYPE_IPX

        dpkt.Packet.unpack(self, buf)
        if self.is_snap:
            self.oui, self.type = struct.unpack('>IH', b'\x00' + self.data[:5])
            payload = self.data[5:]
            self.data = payload
            self._unpack_inner(
                lambda: Ethernet.get_type(self.type), payload, self.type)
        else:
            # non-SNAP
            if self.dsap == 0x06:  # SAP_IP
                self.data = self.ip = Ethernet.get_type(ETH_TYPE_IP)(self.data)
            elif self.dsap == 0x10 or self.dsap == 0xe0:  # SAP_NETWARE{1,2}
                self.data = self.ipx = Ethernet.get_type(ETH_TYPE_IPX)(self.data)
            elif self.dsap == 0x42:  # SAP_STP
                self.data = self.stp = stp.STP(self.data)

    def pack_hdr(self):
        buf = dpkt.Packet.pack_hdr(self)
        if self.is_snap:  # add SNAP sublayer
            oui = getattr(self, 'oui', 0)
            _type = getattr(self, 'type', 0)
            if not _type and isinstance(self.data, dpkt.Packet):
                from .ethernet import Ethernet
                try:
                    _type = Ethernet.get_type_rev(self.data.__class__)
                except KeyError:
                    pass
            buf += struct.pack('>IH', oui, _type)[1:]
        return buf

    def __len__(self):  # add 5 bytes of SNAP header if needed
        return self.__hdr_len__ + 5 * int(self.is_snap) + len(self.data)


def test_llc():
    from . import ip
    from . import ethernet
    s = (b'\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d'
         b'\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b'
         b'\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00')
    llc_pkt = LLC(s)
    ip_pkt = llc_pkt.data
    assert isinstance(ip_pkt, ip.IP)
    assert llc_pkt.type == ethernet.ETH_TYPE_IP
    assert ip_pkt.dst == b'\x3f\xf5\xd1\x69'
    assert str(llc_pkt) == str(s)
    assert len(llc_pkt) == len(s)

    # construction with SNAP header
    llc_pkt = LLC(ssap=0xaa, dsap=0xaa, data=ip.IP(s[8:]))
    assert str(llc_pkt) == str(s)

    # no SNAP
    llc_pkt = LLC(ssap=6, dsap=6, data=ip.IP(s[8:]))
    assert isinstance(llc_pkt.data, ip.IP)
    assert str(llc_pkt) == str(b'\x06\x06\x03' + s[8:])


def test_unpack_sap_ip():
    from binascii import unhexlify

    from . import ip

    buf_llc = unhexlify(
        '06'  # dsap (SAP_IP)
        'aa'  # ssap
        '03'  # ctl
    )
    buf_ip = unhexlify(
        '45'    # _v_hl
        '00'    # tos
        '0014'  # len
        '0000'  # id
        '0000'  # off
        '80'    # ttl
        '06'    # p
        'd47e'  # sum
        '11111111'  # src
        '22222222'  # dst
    )

    buf = buf_llc + buf_ip
    llc = LLC(buf)
    assert isinstance(llc.data, ip.IP)


def test_unpack_exception_handling():
    from binascii import unhexlify

    buf_llc = unhexlify(
        'aa'  # dsap (SAP_IP)
        'aa'  # ssap
        '03'  # ctl

        '111111'  # oui
        '2222'    # type (not valid ethertype)
    )

    llc = LLC(buf_llc)
    assert not isinstance(llc.data, dpkt.Packet)


def test_pack_hdr_invalid_class():
    from binascii import unhexlify

    class InvalidClass(dpkt.Packet):
        __hdr__ = (('test', 'B', 0x22),)

    llc = LLC(dsap=0xaa, ssap=0xaa, ctl=3, oui=0x111111, data=InvalidClass())
    correct = unhexlify(
        'aa'       # dsap
        'aa'       # ssap
        '03'       # ctl

        '111111'   # oui
        '0000'     # type

        '22'       # data in test class header
    )
    assert bytes(llc) == correct


def test_llc_snap_unknown_type_records_error():
    from binascii import unhexlify

    llc = LLC(unhexlify('aaaa03' '111111' '2222'))
    err = llc.unpack_error
    assert isinstance(err, dpkt.UnknownProtocolError)
    assert err.type_id == 0x2222


def test_llc_snap_malformed_known_type_keeps_reason():
    from binascii import unhexlify

    # SNAP ethertype 0x0800 (IP) selected, but the IP payload is truncated
    buf = unhexlify('aaaa03' '000000' '0800') + b'\x45\x00\x00'
    llc = LLC(buf)
    err = llc.unpack_error
    assert isinstance(err, dpkt.InnerPacketUnpackError)
    assert not isinstance(err, dpkt.UnknownProtocolError)
    assert err.protocol_name == 'IP'
    assert isinstance(err.inner_error, dpkt.UnpackError)
    assert llc.data == b'\x45\x00\x00'
