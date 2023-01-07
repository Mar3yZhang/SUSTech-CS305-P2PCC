import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
from time import time
from packet import udp_pkt
from config import *

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
# peer 发送pkt时放入其中turple（chunkhash+seq, time），判断是否需要超时重传
pkt_queue = list()
# 记录已经收到的pkt，chunkhash+seq : 1-收到，0-未收到
ack_pkt_map = dict()

# Time Out Recording , 只在DATA和ACK的传输过程中起作用

Estimated_RTT: float = 0
Dev_RTT: float = 0
Timeout_Interval: float = 0.1  # default: 0.1s

# 用于计时,当前START以毫秒为单位
# 只在发送DATA的时候开始计时,接收ACK报文的时候结束计时，才为完整的RTT
START: float = 0


# 滑动窗口协议相关

def update_timeout_interval(SampleRTT: float):
    global ALPHA, BETA, Estimated_RTT, Dev_RTT, Timeout_Interval
    Estimated_RTT = (1 - ALPHA) * Estimated_RTT + ALPHA * SampleRTT
    Dev_RTT = (1 - BETA) * Dev_RTT + BETA * abs(SampleRTT - Estimated_RTT)
    Timeout_Interval = Estimated_RTT + 4 * Dev_RTT


def get_sample_rtt() -> float:
    global START
    if START == 0:
        raise ValueError
    else:
        return (time() - START) * 1000


def check_overtime(sock):
    is_ack = 1
    no_ack = 0
    while len(pkt_queue) != 0:
        """
        1. 弹出前面所有已经收到的
        2. 判断第一个没有收到的是否超时
        """
        while len(pkt_queue) != 0:
            if ack_pkt_map[pkt_queue[0][0]] == is_ack:
                pkt_queue.pop(0)
            else:
                break
        if len(pkt_queue) != 0 and time() - pkt_queue[0][1] > Timeout_Interval:
            pkt = pkt_queue.pop(0)
            # chunkhash 长度
            from_addr_list = list(pkt[0].split('.')[2])
            from_addr = tuple(from_addr_list)
            # from_addr = bytes(pkt[0].split('.')[2].encode())
            left = int(pkt[0].split('.')[1])
            ack_num = int(left / MAX_PAYLOAD)
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
            data_pkt = data_header + next_data
            sock.sendto(data_pkt, from_addr)
            """
                pkt_queue format:
                0: str(sending_chunkhash)
                1: str(seq_num)
                2: from_addr tuple(ip,port)
                3: start_time
            """
            pkt_queue.append((str(sending_chunkhash), str(left), from_addr, time()))
            print(f'超时重传 {pkt[0]}')


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

    # 封装Whohas报文
    whohas_pkt = udp_pkt.whohas(download_hash)

    # 泛洪Whohas报文给周围的peer
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))
            print(f"发送 WHOHAS 报文给peer: {p}")


# 处理到来的udp报文
"""
Packet Type: Type Code
     WHOHAS: 0
      IHAVE: 1
        GET: 2
       DATA: 3
        ACK: 4
"""


def process_inbound_udp(sock):
    # Receive pkt
    global START
    global config
    global output_file
    global sending_chunkhash

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    # udp packet 的 header部分
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(PKT_FORMAT, pkt[:HEADER_LEN])
    # udp packet 的 data部分
    data = pkt[HEADER_LEN:]

    if Type == WHOHAS:
        # received an WHOHAS pkt
        # see what chunk the sender has

        print("接收到 WHOHAS 报文")
        # chunkhash的长度是20 bytes
        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        sending_chunkhash = chunkhash_str

        print(f"received whohas: {chunkhash_str}, current peer has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:

            # 封装IHAVE报文
            ihave_pkt = udp_pkt.ihave(whohas_chunk_hash)

            # 发送IHAVE报文
            sock.sendto(ihave_pkt, from_addr)

            print("发送 IHAVE 报文")

    elif Type == IHAVE:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]

        print("接收 IHAVE 报文")

        # 封装GET报文
        get_pkt = udp_pkt.get(get_chunk_hash)

        # 发送GET报文
        sock.sendto(get_pkt, from_addr)

        print("发送 GET 报文")

    elif Type == GET:
        # received a GET pkt
        chunk_data = config.haschunks[sending_chunkhash][:MAX_PAYLOAD]
        print("收到 GET 报文")

        # send back DATA
        # 建立map，对应所有需要发送的pkt
        section_num = 0
        while section_num * MAX_PAYLOAD <= CHUNK_DATA_SIZE:
            ack_pkt_map[str(sending_chunkhash) + '.' + str(section_num * MAX_PAYLOAD) + '.' + str(from_addr)] = 0
            section_num += 1

        START = time()

        # 封装Data报文
        data_pkt = udp_pkt.data(chunk_data, 1)

        # 发送Data报文
        sock.sendto(data_pkt, from_addr)

        pkt_queue.append((str(sending_chunkhash), str(0), from_addr, time()))
        print("发送 DATA 报文")

    elif Type == DATA:
        # received a DATA pkt
        received_chunk[downloading_chunkhash] += data
        print("收到 DATA 报文")

        # 封装Ack报文
        ack_pkt = udp_pkt.ack(Seq)

        # 发送Ack报文
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
    elif Type == ACK:
        # 收到ACK报文
        ack_num = Ack

        update_timeout_interval(get_sample_rtt())
        print("收到 ACK 报文")

        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished, 已被成功接收的文件大于chunk，相当于单个发送
            print(f"finished sending {sending_chunkhash}")
            pass
        else:
            # 确定下一个要传输的数据段的数据
            left = ack_num * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[sending_chunkhash][left: right]
            # send next data

            # 封装Data报文
            data_pkt = udp_pkt.data(next_data, ack_num + 1)

            # 发送Data报文
            sock.sendto(data_pkt, from_addr)

            ack_pkt_map[str(sending_chunkhash) + '.' + str(left) + '.' + str(from_addr)] += 1
            pkt_queue.append((str(sending_chunkhash), str(left), from_addr, time()))
            print("成功接收，继续发送 DATA 报文")

    else:
        raise ConnectionError("错误的udp_pkt类型")


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            check_overtime(sock)
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
