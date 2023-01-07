from config import *


class udp_pkt:
    """
        The format of p2p packet format is listed below.

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Magic             |     Index      |   Type Code  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Header Length         |        Packet Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Sequence Number                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          ACK Number                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               :
           :                            Payload                            :
           :                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


        Attributes
        ----------
        magic : int
            To check if you correctly deal with endian issue, or to check if the packet is spoofed.
        index : int
            The index of the chunkhash of the sending/receiving chunk
        type : int
            Indicate what type is this packet
        hlen : int
            Header length.
        plen : int
            Packet length.
        seq : int
            The sequence number for packet, i.e., it counts packets rather than bytes. This field is only
            valid for DATA packet. For other packet, it should always be 0.
        ack : int
            Only valid for ACK packet. For other packets, it should always be 0.
        payload : bytes
            Data to be transferred.
    """

    def __init__(self):
        self.magic = MAGIC
        self.index = NO_USE
        self.type = -1
        self.hlen = struct.calcsize(PKT_FORMAT)
        self.plen = 0
        self.seq = 0
        self.ack = 0
        self.payload = bytes()

    def make_header(self):
        return struct.pack(PKT_FORMAT,
                           self.magic,
                           self.index,
                           self.type,
                           self.hlen,
                           self.plen,
                           self.seq,
                           self.ack)

    def make_packet(self):
        return self.make_header() + self.payload

    def parse_packet(self, packet: bytes):
        header, self.payload = packet[:16], packet[16:]
        self.magic, self.index, self.type, self.hlen, self.plen, self.seq, self.ack = struct.unpack(PKT_FORMAT,
                                                                                                    header)

    @staticmethod
    def whohas(chunkhash):
        """
            Generate WHOHAS packet

            Parameters
            ----------
            chunkhash : bytes
                The chunkhash of the chunk peer wants.
        """
        return struct.pack(PKT_FORMAT,
                           MAGIC,
                           NO_USE,
                           WHOHAS,
                           HEADER_LEN,
                           HEADER_LEN + len(chunkhash),
                           NO_USE,
                           NO_USE) + chunkhash

    @staticmethod
    def ihave(chunkhash):
        """
            Generate IHAVE packet

            Parameters
            ----------
            chunkhash : bytes
                The requested chunk that peer has.
        """
        return struct.pack(PKT_FORMAT,
                           MAGIC,
                           NO_USE,
                           IHAVE,
                           HEADER_LEN,
                           HEADER_LEN + len(chunkhash),
                           NO_USE,
                           NO_USE) + chunkhash

    @staticmethod
    def get(idx: int, chunkhash):
        """
            Generate GET packet

            Parameters
            ----------
            idx : int
                Index of the chunk that the pkt is sending
            chunkhash : bytes
                The chunk peer wants to download.
        """
        return struct.pack(PKT_FORMAT,
                           MAGIC,
                           idx,
                           GET,
                           HEADER_LEN,
                           HEADER_LEN + len(chunkhash),
                           NO_USE,
                           NO_USE) + chunkhash

    @staticmethod
    def data(idx: int, seq: int, chunkdata: bytes):
        """
            Generate DATA packet

            Parameters
            ----------
            chunkdata : bytes
                The chunkdata peer needs to send
            seq : int
                Sequence number of packet to be sent
            idx : int
                Index of the chunk that the pkt is sending
        """
        return struct.pack(PKT_FORMAT,
                           MAGIC,
                           idx,
                           DATA,
                           HEADER_LEN,
                           HEADER_LEN + len(chunkdata),
                           seq,
                           NO_USE) + chunkdata

    @staticmethod
    def ack(idx: int, ack: int):
        """
            Generate ACK packet

            Parameters
            ----------
            ack : int
                The packet peer has received
            idx : int
                Index of the chunk that the pkt is sending
        """
        return struct.pack(PKT_FORMAT,
                           MAGIC,
                           idx,
                           ACK,
                           HEADER_LEN,
                           HEADER_LEN,
                           NO_USE,
                           ack)
