import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024  # 512K
# 报文数据部分的最大载荷
MAX_PAYLOAD = 1024

# 以网络端作为大小端打包数据
PKT_FORMAT = '!HBBHHII'
MAGIC = 52305
TEAM = 35
# 表示当前字段这个包用不到
NO_USE = 0
HEADER_LEN = struct.calcsize(PKT_FORMAT)

# peer的个人信息
config = None
# peer输出的文件名
output_file = None
# peer用来记录所有接收到的hash:data数据记录形成的字典
received_chunk = dict()
# peer正在下载的chunkhash
downloading_chunkhash = ""
# peer 正在发送的chunkhash
sending_chunkhash = ""


# 这里直接使用网络端传输有bug，没搞懂
# HEADER_FORM = "!HBBHHII"

def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    global PKT_FORMAT, MAGIC, TEAM, HEADER_LEN, NO_USE
    global output_file
    global received_chunk
    global downloading_chunkhash

    output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        # TODO:这里需要考虑download文件里不只有一个chunkhash的情况
        index, datahash_str = cf.readline().strip().split(" ")
        received_chunk[datahash_str] = bytes()
        downloading_chunkhash = datahash_str

        # hex_str to bytes
        datahash = bytes.fromhex(datahash_str)
        download_hash = download_hash + datahash
        print(cf.readline())

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    #                +
    # |      ?byte  payload              |

    whohas_header = struct.pack(PKT_FORMAT,
                                MAGIC,
                                TEAM,
                                0,
                                HEADER_LEN,
                                HEADER_LEN + len(download_hash),
                                NO_USE,
                                NO_USE)
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))
            print(f"发送 WHOHAS 报文给peer: {p}")


# 处理到来的udp报文
def process_inbound_udp(sock):
    # Receive pkt
    global config
    global output_file
    global sending_chunkhash

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    # udp packet 的 header部分
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(PKT_FORMAT, pkt[:HEADER_LEN])
    # udp packet 的 data部分
    data = pkt[HEADER_LEN:]
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has

        print("接收到 WHOHAS 报文")

        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        sending_chunkhash = chunkhash_str

        print(f"received whohas: {chunkhash_str}, current peer has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:
            # send back IHAVE pkt
            ihave_header = struct.pack(PKT_FORMAT,
                                       MAGIC,
                                       TEAM,
                                       1,
                                       HEADER_LEN,
                                       HEADER_LEN + len(whohas_chunk_hash),
                                       NO_USE,
                                       NO_USE)
            ihave_pkt = ihave_header + whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)
            print("发送 IHAVE 报文")

    elif Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]

        print("接收 IHAVE 报文")

        # send back GET pkt
        get_header = struct.pack(PKT_FORMAT,
                                 MAGIC,
                                 TEAM,
                                 2,
                                 HEADER_LEN,
                                 HEADER_LEN + len(get_chunk_hash),
                                 NO_USE,
                                 NO_USE)
        get_pkt = get_header + get_chunk_hash
        sock.sendto(get_pkt, from_addr)

        print("发送 GET 报文")

    elif Type == 2:
        # received a GET pkt
        chunk_data = config.haschunks[sending_chunkhash][:MAX_PAYLOAD]
        print("收到 GET 报文")

        # send back DATA
        data_header = struct.pack(PKT_FORMAT,
                                  MAGIC,
                                  TEAM,
                                  3,
                                  HEADER_LEN,
                                  HEADER_LEN + len(chunk_data),
                                  1,
                                  NO_USE)
        sock.sendto(data_header + chunk_data, from_addr)
        print("发送 DATA 报文")

    elif Type == 3:
        # received a DATA pkt
        received_chunk[downloading_chunkhash] += data
        print("收到 DATA 报文")

        # send back ACK
        ack_pkt = struct.pack(PKT_FORMAT,
                              MAGIC,
                              TEAM,
                              4,
                              HEADER_LEN,
                              HEADER_LEN,
                              NO_USE,
                              Seq)
        sock.sendto(ack_pkt, from_addr)
        print("发送 ACK 报文")

        # see if finished
        if len(received_chunk[downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(output_file, 'wb') as wf:
                pickle.dump(received_chunk, wf)

            # add to this peer's haschunk:
            # 将新下载的chunk加入到peer的字典里
            config.haschunks[downloading_chunkhash] = received_chunk[downloading_chunkhash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            # 校验接收到的chunkhash是否相同，若相同，说明成功传输
            sha1 = hashlib.sha1()
            sha1.update(received_chunk[downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = downloading_chunkhash == received_chunkhash_str
            if success:
                print(f"Successful received: {success}")
            else:
                print(f"Fail to received the chunk")
    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        print("收到 ACK 报文")

        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {sending_chunkhash}")
            pass
        else:
            # 确定下一个要传输的数据段的数据
            left = ack_num * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[sending_chunkhash][left: right]
            # send next data
            # ACK字段只对ACK_pkt生效
            data_header = struct.pack(PKT_FORMAT,
                                      MAGIC,
                                      TEAM,
                                      3,
                                      HEADER_LEN,
                                      HEADER_LEN + len(next_data),
                                      ack_num + 1,
                                      NO_USE)
            sock.sendto(data_header + next_data, from_addr)
            print("成功接收，继续发送 DATA 报文")


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    # 这里应该进行对环境的初始化操作,通过握手直到其他peer有哪些chunk

    try:
        while True:
            # readable, writable, exceptional = select.select(inputs, outputs, inputs)
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    bt_utils.BtConfig.bt_dump_config(config)
    peer_run(config)
