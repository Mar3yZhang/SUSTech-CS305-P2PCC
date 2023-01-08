import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import json
from time import time
from packet import udp_pkt
from config import *

# peer的个人信息
config = None
# peer输出的文件名
output_file = None

"""接收方全局变量
receiving_chunks: 正在接收的chunk数据的字典
        index: chunkhash在master.chunkhash里的序号
    1) chunkhash:str : 由chunk经sha1算法生成的哈希值
    2) chunk:bytes() : chunk的二进制字节
downloading_index_to_chunkhash: 当前peer正在下载的chunk的chunkhash的字典
        key:value -> index:chunkhash
    1) index:int : chunkhash在master.chunkhash里的序号
    2) chunkhash:str : 由chunk经sha1算法生成的哈希值
peer_chunkhash_map: 当前peer所有邻居的ihave情况
        key:value -> address:chunkhash_list
    1) index:int : 需要的chunkhash的index
    2) peer_list: list[from_address] : 所有有这个chunkhash的邻居的地址list
    
超时重传部分
unack_pkt = dict()
    (Index, ack_num, from_addr) : (time, pkt)
ack_pkt_map = dict() 记录已收到的pkt
    str(chunkhash)+str(ack_num) : 1-收到，0-未收到

维护接收正确性
    DATA：收到seq=base_ack+1才接收，发送ack=base_ack+1, base_ack += 1;若seq=1，加入dict中，
chunk_base_ack = dict() 
    Index : base_ack
    
"""
receiving_chunks = dict()
downloading_index_to_chunkhash = dict()
peer_chunkhash_map = dict()

unack_pkt = dict()
ack_pkt_map = dict()

chunkIndex_base_ack = dict()

"""发送方全局变量
chunkhash_to_idx: 当前peer需要下载的chunkhash和index的映射
        key:value -> chunkhash:index
    1) chunkhash:str : 由chunk经sha1算法生成的哈希值
    2) index:int : chunkhash在master.chunkhash里的序号
sending_index_to_chunkhash : 当前peer正在发送的chunk的chunkhash的字典
        key:value -> index:chunkhash
    1) index:int : chunkhash在master.chunkhash里的序号
    2) chunkhash:str : 由chunk经sha1算法生成的哈希值
"""
chunkhash_to_idx = dict()
sending_index_to_chunkhash = dict()

# Time Out Recording , 只在DATA和ACK的传输过程中起作用
Estimated_RTT: float = 0
Dev_RTT: float = 0
Timeout_Interval: float = 0.1  # default: 0.1s

# 用于计时,当前START以毫秒为单位
# 只在发送DATA的时候开始计时,接收ACK报文的时候结束计时，才为完整的RTT
START: float = 0

# 用来记录当前的peer收到了几个IHAVE
ihave_counter = None



# 滑动窗口协议相关

# 通过JSON序列化
def pack_payload(payload) -> bytes:
    return bytes(json.dumps(payload).encode('utf-8'))


# 通过JSON反序列化
def unpack_payload(payload: bytes):
    return json.loads(payload)


def update_timeout_interval(SampleRTT: float):
    global Estimated_RTT, Dev_RTT, Timeout_Interval
    Estimated_RTT = (1 - ALPHA) * Estimated_RTT + ALPHA * SampleRTT
    Dev_RTT = (1 - BETA) * Dev_RTT + BETA * abs(SampleRTT - Estimated_RTT)
    Timeout_Interval = Estimated_RTT + 4 * Dev_RTT


def get_sample_rtt() -> float:
    global START
    if START == 0:
        raise ValueError
    else:
        return (time() - START) * 1000


def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    global output_file
    global ihave_counter
    global receiving_chunks
    global downloading_index_to_chunkhash

    ihave_counter = len(config.peers) - 1

    output_file = outputfile
    # Step 1: 从chunkfile里读取需要下载的chunk的chunkhash
    # download_chunkhash_str_list: 所有待下载的chunk的chunkhash组成的list
    download_chunkhash_str_list = list()

    with open(chunkfile, 'r') as cf:
        # TODO:这里需要考虑download文件里不只有一个chunkhash的情况
        # 逐行读取文件
        for line in cf.readlines():
            index_str, chunkhash_str = line.strip().split(" ")
            index = int(index_str)
            # 初始化待接收的chunk字节流
            receiving_chunks[chunkhash_str] = bytes()
            downloading_index_to_chunkhash[index] = chunkhash_str
            chunkhash_to_idx[chunkhash_str] = index
            download_chunkhash_str_list.append(chunkhash_str)

    # 封装Whohas报文
    # TODO: 尝试把 str list转成字节流传输，在接收侧解封装
    whohas_pkt = udp_pkt.whohas(pack_payload(download_chunkhash_str_list))
    print(f' download_chunkhash_str_list : {download_chunkhash_str_list}')
    print(f'I have {sending_index_to_chunkhash.items()}')

    # 泛洪Whohas报文给周围的peer
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))
            print(f"发送 WHOHAS 报文给peer: {p}")


"""
检查超时重传：

"""
def check_overtime(sock):
    # TODO：check un_ack 是否有超时
    for key, value in unack_pkt.items():
        Index, ack_num, from_addr = key
        _time, next_data = value
        if time() - _time > Timeout_Interval:
            # data_pkt = udp_pkt.data(next_data, ack_num)
            sock.sendto(next_data, from_addr)
            unack_pkt[(Index, ack_num, from_addr)] = (time(), next_data)

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
    global ihave_counter
    global sending_index_to_chunkhash

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    # udp packet 的 header部分
    Magic, Index, Type, hlen, plen, Seq, Ack = struct.unpack(PKT_FORMAT, pkt[:HEADER_LEN])
    # udp packet 的 data部分
    data = pkt[HEADER_LEN:]

    # 发送方 收到 WHOHAS，GET，ACK
    if Type == WHOHAS:
        # 接收到WHOHAS报文
        print(f"接收到 WHOHAS 报文 from {from_addr}")
        # Data部分是一个str list，需要解封装
        # whohas_chunk_hash = data[:20]
        whohas_chunkhash_str_list = unpack_payload(data)
        ihave_chunkhash_str_list = []
        # bytes to hex_str
        for chunkhash_str in whohas_chunkhash_str_list:
            # sending_index_to_chunkhash[chunkhash_to_idx[chunkhash_str]] = chunkhash_str
            print(f"received whohas: {chunkhash_str}, current peer has: {list(config.haschunks.keys())}")
            if chunkhash_str in config.haschunks:
                ihave_chunkhash_str_list.append(chunkhash_str)
        # 封装IHAVE报文
        # whohas_chunkhash_bytes = bytes.fromhex(chunkhash_str)
        ihave_pkt = udp_pkt.ihave(pack_payload(ihave_chunkhash_str_list))
        # 发送IHAVE报文
        sock.sendto(ihave_pkt, from_addr)
        # print(f"发送 IHAVE 报文 to {from_addr}")

    elif Type == GET:
        # received a GET pkt
        chunkhash_str = unpack_payload(data)
        sending_index_to_chunkhash[Index] = chunkhash_str
        chunk_data = config.haschunks[chunkhash_str][:MAX_PAYLOAD]
        print("收到 GET 报文 get_Index {Index}")
        # send back DATA
        # 建立map，对应所有需要发送的pkt
        START = time()
        # 封装Data报文
        data_pkt = udp_pkt.data(Index, 1, chunk_data)
        # 发送Data报文
        sock.sendto(data_pkt, from_addr)
        unack_pkt[(Index, 1, from_addr)] = (time(), data_pkt)

    elif Type == ACK:
        # 收到ACK报文
        ack_num = Ack
        for key, value in unack_pkt.items():
            print(f'key : {key}')
        # update_timeout_interval(get_sample_rtt())
        print(f"收到 ACK 报文 ACK {Ack}")

        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished, 已被成功接收的文件大于chunk，相当于单个发送
            print(f"finished sending {sending_index_to_chunkhash[Index]}")
            key_list = list()
            for key, value in unack_pkt.items():
                index2, seq, from_addr = key
                _time, _ = value
                if index2 == Index:
                    key_list.append(key)
            for key in key_list:
                unack_pkt.pop(key)
            pass
        else:
            # 确定下一个要传输的数据段的数据
            left = ack_num * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[sending_index_to_chunkhash[Index]][left: right]
            # send next data
            # 封装Data报文
            data_pkt = udp_pkt.data(Index, ack_num + 1, next_data)
            unack_pkt[(Index, ack_num + 1, from_addr)] = (time(), data_pkt)
            # assert unack_pkt.get((Index, ack_num, from_addr)) is not None
            # TODO: 修复不符合逻辑的判断 - 解释：因为有重复ACK，所以这里符合逻辑
            if unack_pkt.get((Index, ack_num, from_addr)) is not None:
                unack_pkt.pop((Index, ack_num, from_addr))
            # print(f"成功接收，继续发送 DATA 报文 seq {ack_num + 1}")
            # 发送Data报文
            sock.sendto(data_pkt, from_addr)

    # 接收方 收到 IHAVE， DATA
    elif Type == IHAVE:
        # received an IHAVE pkt
        # TODO: 这里需要考虑从所有的IHAVE中选择一个发送GET报文，否则会有多个peer发送相同的chunk给当前peer
        # TODO: 需要记录所有的peer的含有的chunkhash
        get_chunkhash_str_list = unpack_payload(data)
        ihave_counter -= 1
        print(f'收到 IHAVE from_addr {from_addr}')
        print(f"ihave_counter: {ihave_counter}")

        for chunkhash_str in get_chunkhash_str_list:
            idx = chunkhash_to_idx[chunkhash_str]
            if peer_chunkhash_map.get(idx) is None:
                peer_chunkhash_map[idx] = list()
            peer_chunkhash_map[idx].append(from_addr)

        for i, j in peer_chunkhash_map.items():
            print(f"key: {i} , value: {j}")

        if ihave_counter == 0:
            for index, chunkhash_str in downloading_index_to_chunkhash.items():
                from_addr = peer_chunkhash_map[index].pop()
                get_pkt = udp_pkt.get(index, pack_payload(chunkhash_str))
                # 发送GET报文
                sock.sendto(get_pkt, from_addr)
                print(f'sending GET index {index} to {from_addr}')
                # 累积确认ack，初始化为0
                chunkIndex_base_ack[index] = 0

    elif Type == DATA:
        # 收到DATA报文，这里需要判断这个报文来自的chunk对饮的chunkhash
        print(f"收到 DATA 报文 from {from_addr}, seq {Seq}", end="")
        # TODO 采用累积确认ack的方式
        if Seq != chunkIndex_base_ack[Index] + 1:
            print(f' dup, discard')
            print(f'received : {len(receiving_chunks[downloading_index_to_chunkhash[Index]])} index {Index}')
            return
        else:
            print(f' accept')
            chunkIndex_base_ack[Index] = Seq
        receiving_chunks[downloading_index_to_chunkhash[Index]] += data
        # 封装Ack报文
        ack_pkt = udp_pkt.ack(Index, Seq)
        sock.sendto(ack_pkt, from_addr)
        # see if finished
        assert len(receiving_chunks[downloading_index_to_chunkhash[Index]]) % 1024 == 0
        assert len(receiving_chunks[downloading_index_to_chunkhash[Index]]) <= CHUNK_DATA_SIZE
        print(f'received : {len(receiving_chunks[downloading_index_to_chunkhash[Index]])} index {Index}')
        print(f'CHUNK_DATA_SIZE {CHUNK_DATA_SIZE}')
        if len(receiving_chunks[downloading_index_to_chunkhash[Index]]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(output_file, 'wb') as wf:
                pickle.dump(receiving_chunks, wf)
            # add to this peer's haschunk:
            # 将新下载的chunk加入到peer的字典里
            config.haschunks[downloading_index_to_chunkhash[Index]] = receiving_chunks[
                downloading_index_to_chunkhash[Index]]
            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {output_file}")
            # The following things are just for illustration, you do not need to print out in your design.
            # 校验接收到的chunkhash是否相同，若相同，说明成功传输
            sha1 = hashlib.sha1()
            sha1.update(receiving_chunks[downloading_index_to_chunkhash[Index]])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {downloading_index_to_chunkhash[Index]}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = downloading_index_to_chunkhash[Index] == received_chunkhash_str
            if success:
                print(f"Successful received: {success}")
            else:
                print(f"Fail to received the chunk")

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
