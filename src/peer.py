import math
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
from time import time, sleep
from packet import udp_pkt
from config import *
import matplotlib.pyplot as plt
from datetime import datetime

# peer的个人信息
config = None
# peer输出的文件名
output_file = None
# TODO:实现发给多个peer不同chunk
"""接收方全局变量
chunkhash_to_idx: 当前peer需要下载的chunkhash和index的映射，下载完成后pop
        key:value -> chunkhash:index
    1) chunkhash:str : 由chunk经sha1算法生成的哈希值
    2) index:int : chunkhash在master.chunkhash里的序号
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
download_chunkhash_str_list: 所有待下载的chunk的chunkhash组成的list
downloaded = list() 完成下载的chunkhash
    
超时重传部分
unack_pkt = dict()
    (Index, ack_num, from_addr) : (time, pkt, dup_ack)
ack_pkt_map = dict() 记录已收到的pkt
    (Index, seq) : get_num
    str(chunkhash)+str(ack_num) : 1-收到，0-未收到

维护接收正确性
    DATA：收到seq=base_ack+1才接收，发送ack=base_ack+1, base_ack += 1;若seq=1，加入dict中，
chunkIndex_base_ack = dict() 
    Index : base_ack
    
维护连接的peer
connecting_peer = dict()
    from_addr : (last_communication_time, transfer_chunk_index)
connect_timeout : int 
need_download_index : list()  process 初始化，发送get/完成传输时pop，crash发送时加入

SR维护窗口部分
received_window = dict()
    (index, seq) : data
    
"""
chunkhash_to_idx = dict()
receiving_chunks = dict()
downloading_index_to_chunkhash = dict()
peer_chunkhash_map = dict()
download_chunkhash_str_list = list()
downloaded = list()
# TODO 修改将dup_ack加入到unack_pkt字典中
unack_pkt = dict()
ack_pkt = dict()
sample_RTT:float = 0.1

chunkIndex_base_ack = dict()

connecting_peer = dict()
connect_timeout = 3.
need_download_index = list()

received_window = dict()
RECE_WINDSIZE : int = 10

"""发送方全局变量
sending_index_to_chunkhash : 当前peer正在发送的chunk的chunkhash的字典
        key:value -> index:chunkhash
    1) index:int : chunkhash在master.chunkhash里的序号
    2) chunkhash:str : 由chunk经sha1算法生成的哈希值

SR变量维护
chunkIndex_base_ack = dict(), 发送方对于每个chunk的发送base
    chunk_Index ： base_ack
send_window_N = dict()
    chunkIndex : tuple(winsize_N, next_send)
SEND_WINDSIZE:int
"""
sending_index_to_chunkhash = dict()
# TODO 检查发送方是否维护chunkIndex_base_ack，作为发送base
# TODO：在开始发送时初始化，完全收到后pop
send_window_N = dict()
SEND_WINDSIZE : int = 10

# Time Out Recording , 只在DATA和ACK的传输过程中起作用
Estimated_RTT: float = 0
Dev_RTT: float = 0
Timeout_Interval: float = 0.5  # default: 0.1s

# 用于计时,当前START以毫秒为单位
# 只在发送DATA的时候开始计时,接收ACK报文的时候结束计时，才为完整的RTT
# 作为单独的计时器，因为有多个chunk，所以需要每个chunk一个计时器【因为窗口什么的都是按照chunk来分的】//但是不好改，单个计时器应该也可以
START = [0, False]

# 用来记录当前的peer收到了几个IHAVE
ihave_counter = None

# 滑动窗口协议相关 SR
"""发送方全局变量
cc_dup_ack_counter : 当前peer用于流量控制的ack counter
        key:value -> index:chunkhash
    1) tuple(from_address,seq_num) : 唯一表示一个来自其他peer发送过来的报文
    2) counter:int : 用来记录发送过来报文的数量
cwnd : float, 在之后使用使取整，这里因为
"""
cwnd = 1.
ssthresh = 64
cc_state = SS
cc_inter_state = original
cc_win_size = list()
cc_time = list()
cc_start = list()

"""随着输入状态而维护一些变量，画出图，若可用，将send_window限制为cwnd
dup_ack这里仅表示dup_ack为3的情况"""
def cc_fsm(cc_inter):
    global cwnd, ssthresh, cc_state, cc_inter_state, cc_start
    cc_inter_state = cc_inter
    if cc_state == SS:
        if cc_inter_state == original:
            cwnd += 1.
            ssthresh = 64
            cc_start = [time(), time()]
        elif cwnd >= ssthresh:
            cc_state = CA
        elif cc_inter_state == time_out or cc_inter_state == dup_ACK:
            ssthresh = max(math.floor(cwnd/2), 2)
            cwnd = 1.
        else:
            print(f'in cc_fsm, unknown situation ss')
        if cc_inter_state == new_ACK:
            cwnd += 1.
    elif cc_state == CA:
        if cc_inter_state == time_out:
            ssthresh = max(math.floor(cwnd/2), 2)
            cwnd = 1
            cc_state = SS
        elif cc_inter_state == new_ACK:
            cwnd = cwnd + 1/cwnd

        else:
            print(f'in cc_fsm, unknown situation ca')
    else:
        print(f'in cc_fsm, unknown situation other')


HAVE_DRAW = False
def cwnd_observe():
    global cc_start
    if len(cc_start) != 2:
        return
    if time() - cc_start[1] > 0.003:
        cc_win_size.append(int(cwnd))
        cc_time.append(time()-cc_start[0])
        cc_start[1] = time()


def draw_cwnd():
    # plt绘图
    now = datetime.now()
    now_time = now.strftime("%m-%d_%H-%M")
    plt.figure()
    # for port, record in sessions.items():
    #     plt.plot(record[0], record[1], ",", markersize=0.1)
    plt.plot(cc_time, cc_win_size)
    plt.legend()
    plt.xlim(0, cc_time[-1])
    plt.xlabel(f"Time (s) {cc_time[-1]}")
    plt.ylabel("Window Size")
    plt.savefig(f"congestion_control_winsize_{now_time}.png")

# 通过JSON序列化
def pack_payload(payload) -> bytes:
    return bytes(json.dumps(payload).encode('utf-8'))


# 通过JSON反序列化
def unpack_payload(payload: bytes):
    return json.loads(payload)


def update_timeout_interval():
    global Estimated_RTT, Dev_RTT, Timeout_Interval, sample_RTT
    Estimated_RTT = (1 - ALPHA) * Estimated_RTT + ALPHA * sample_RTT
    Dev_RTT = (1 - BETA) * Dev_RTT + BETA * abs(sample_RTT - Estimated_RTT)
    Timeout_Interval = Estimated_RTT + 4 * Dev_RTT


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
            need_download_index.append(index)

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
检查超时重传：这里是只有一个全局的计时器，最好是每个chunk一个全局计时器，然后超时之后只重发一个
"""

# TODO 系统的重传花费了很多时间，收到ack就发报文这点，有的是重复的ack，可以优化
# TODO 需要避免对不同peer发送同一个chunk的请求
# TODO:重传应该根据dup_ack，而且只在dup_ack=3重传，不然会对已crash的peer反复重传，这里暂时处理

def check_overtime(sock):
    """计时器超时，pop所有在base_ack之下的项，然后重传超时的项"""
    global START, Timeout_Interval
    if START[1] and time() - START[0] > Timeout_Interval:
    # check un_ack 是否有超时
        if_resend = False
        pop_unack = list()
        for key, value in unack_pkt.items():
            Index, ack_num, from_addr = key
            _time, next_data, dup_ack = value
            if ack_num <= chunkIndex_base_ack[Index]:
                pop_unack.append(key)
                continue
            if if_resend is False and time() - _time > Timeout_Interval:
                print(f'overtime resend {from_addr} index {Index} ack_num {ack_num} Timeout_Interval {Timeout_Interval}')
                sock.sendto(next_data, from_addr)
                unack_pkt[(Index, ack_num, from_addr)] = (time(), next_data, 0)
                if_resend = True
        if if_resend:
            START = [time(), True]
            Timeout_Interval *= 2
            cc_fsm(time_out)
        for key in pop_unack:
            unack_pkt.pop(key)
    # 观察cwnd窗口变化
    cwnd_observe()

"""
维护peer连接与下载
    先判断是否有断连接的，从peer_chunkhash_map中 pop 所有该peer  
    再检查是否有未下载完的块，开始请求（需要知道
        当前连接的peer, 传输过来的chunk_index: connecting_peer addr: (time, index)
    ）
    先获得需要下载的块的list（正在下载的不包括在内），然后寻找空余的peer，找到后发送GET报文
    
"""


def check_crash():
    crash_peer = list()
    for key, value in connecting_peer.items():
        peer_addr = key
        _time, index = value
        if time() - _time > max(connect_timeout, Timeout_Interval):
            crash_peer.append(peer_addr)
            need_download_index.append(index)
            # TODO 没考虑新peer加入的情况，没要求，但是可以考虑
            for key_p, value_p in peer_chunkhash_map.items():
                if peer_addr in value_p:
                    value_p.remove(peer_addr)
    for peer in crash_peer:
        connecting_peer.pop(peer)


def check_undownload(sock):
    if ihave_counter != 0:
        return
    if len(connecting_peer) >= config.max_conn:
        return
    if len(need_download_index) == len(connecting_peer):
        return
    wait_to_download_index = list()
    for chunk_hash, index in chunkhash_to_idx.items():
        wait_to_download_index.append(index)
    for peer, value in connecting_peer.items():
        _time, downloading_index = value
        if downloading_index in wait_to_download_index:
            wait_to_download_index.remove(downloading_index)
    # 找到需要下载的index，寻找peer发送请求
    for wait_index in need_download_index:
        if wait_index not in peer_chunkhash_map.keys():
            continue
        peer_list = peer_chunkhash_map[wait_index]
        for peer in peer_list:
            if peer not in connecting_peer.keys():
                chunkhash_str = downloading_index_to_chunkhash[wait_index]
                connecting_peer[peer] = (time(), wait_index)
                get_pkt = udp_pkt.get(wait_index, pack_payload(chunkhash_str))
                # chunkIndex_base_ack[wait_index] = 0
                print(f'sending GET index {wait_index} to {peer} in crash')
                sock.sendto(get_pkt, peer)
            if not peer in connecting_peer.keys():
                pass

""""
    chunkIndex_base_ack = dict(), 发送方对于每个chunk的发送base
        chunk_Index ： base_ack
    send_window_N = dict()
        chunkIndex : [winsize_N, next_send]
        next_send 也就是未发送的左端，ack
    
    send_base需要在外面维护
"""
def SR_send(Index, chunkhash_str, from_addr, sock):
    #     TODO：TCP/SR 的发送方
    # 若没有的话，就进行初始化。 对于其他的，就发送窗口内没有的
    global chunkIndex_base_ack, SEND_WINDSIZE, MAX_PAYLOAD, send_window_N

    if Index not in chunkIndex_base_ack.keys():
        chunkIndex_base_ack[Index] = 0
        if SEND_WINDSIZE * MAX_PAYLOAD <= len(config.haschunks[chunkhash_str]):
            send_window_N[Index] = [SEND_WINDSIZE, 0]
        else:
            # TODO 这里认为chunk_size一定会整除MAX_PAYLOAD
            send_size = int(len(config.haschunks[chunkhash_str]) / MAX_PAYLOAD)
            send_window_N[Index] = [send_size, 0]
    # TODO 判断下面是否准确，边界是由切片方式决定,
    # send_base的处理方式考虑了crash换peer的情况
    if send_window_N[Index][1] < send_window_N[Index][0] + chunkIndex_base_ack[Index]:
        send_base_seq = max(send_window_N[Index][1], chunkIndex_base_ack[Index])
        send_end_seq = min(send_window_N[Index][0] + chunkIndex_base_ack[Index], int(len(config.haschunks[chunkhash_str]) / MAX_PAYLOAD))
        send_end_seq = min(send_end_seq, send_base_seq+int(cwnd))
        print(f'SR sending index {Index} from seq {send_base_seq} to {send_end_seq} to {from_addr}')
        for send_seq in range(send_base_seq, send_end_seq):
            chunk_data = config.haschunks[chunkhash_str][send_seq*MAX_PAYLOAD:(send_seq+1)*MAX_PAYLOAD]
            data_pkt = udp_pkt.data(Index, send_seq+1, chunk_data)
            unack_pkt[(Index, send_seq + 1, from_addr)] = (time(), data_pkt, 0)
            if send_seq in [150]:
                continue
            sock.sendto(data_pkt, from_addr)
        send_window_N[Index][1] = send_end_seq


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
    global cwnd
    global START
    global config
    global ack_pkt
    global cc_state
    global HAVE_DRAW
    global sample_RTT
    global output_file
    global SEND_WINDSIZE
    global RECE_WINDSIZE
    global ihave_counter
    global cc_dup_ack_counter
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
        print(f"收到 GET 报文 get_Index {Index} from {from_addr}")
        # send back DATA
        # 建立map，对应所有需要发送的pkt
        if not START[1]:
            START = [time(), True]
        # 停等协议
        # chunk_data = config.haschunks[chunkhash_str][:MAX_PAYLOAD]
        # data_pkt = udp_pkt.data(Index, 1, chunk_data)
        # sock.sendto(data_pkt, from_addr)
        # unack_pkt[(Index, 1, from_addr)] = (time(), data_pkt, 0)
        # chunkIndex_base_ack[Index] = 0
    #     TCP/SR 发送方式
        cc_fsm(original)
        SR_send(Index, chunkhash_str, from_addr, sock)

    elif Type == ACK:
        # 收到ACK报文
        ack_num = Ack
        for key, value in unack_pkt.items():
            print(f'key : {key}')
        # update_timeout_interval(get_sample_rtt())
        print(f"收到 ACK 报文 ACK {Ack}")

        # 只有ack>=base_ack进入, 处理超时重传事件：pop对应index下ack<=base_ack的，然后若还有未应答的开启计时器，否则关闭
        # 处理冗余ack的事
        if ack_num <= chunkIndex_base_ack[Index]:
            # TODO 特判，对于最后一个包会发送
            if ack_num*MAX_PAYLOAD > len(config.haschunks[sending_index_to_chunkhash[Index]]):
                return
            if (Index, ack_num) not in ack_pkt.keys():
                ack_pkt[(Index, ack_num)] = 0
            else:
                # TODO 关闭dup_ack, 这里关闭的话改 0
                ack_pkt[(Index, ack_num)] += 1
                if ack_pkt[(Index, ack_num)] == 3:
                    print(f'fast retrans seq {ack_num}')
                    left = ack_num * MAX_PAYLOAD
                    right = left + MAX_PAYLOAD
                    chunk_data = config.haschunks[sending_index_to_chunkhash[Index]][left:right]
                    data_pkt = udp_pkt.data(Index, ack_num + 1, chunk_data)
                    sock.sendto(data_pkt, from_addr)
                    unack_pkt[(Index, ack_num + 1, from_addr)] = (time(), data_pkt, 0)
                    ack_pkt[(Index, ack_num)] = 0
                    cc_fsm(dup_ACK)
                else:
                    cc_fsm(new_ACK)
            return
        # 更新base_ack, 然后更新unack_pkt
        cc_fsm(new_ACK)
        if unack_pkt.get((Index, ack_num, from_addr)) is not None:
            _time, data, _ = unack_pkt.get((Index, ack_num, from_addr))
            sample_RTT = time() - _time
            update_timeout_interval()
            print(f'update timeout_interval {Timeout_Interval}')
            unack_pkt.pop((Index, ack_num, from_addr))
        chunkIndex_base_ack[Index] = ack_num
        pop_ack = list()
        start_timer = False
        for key, value in unack_pkt.items():
            _index, _ack_num, _ = key
            if _index == Index:
                if _ack_num <= chunkIndex_base_ack[Index]:
                    pop_ack.append(key)
                else:
                    start_timer = True
        for key in pop_ack:
            unack_pkt.pop(key)

        if start_timer:
            START = [time(), True]

        # 维护拥塞控制冗余ack counter
        # 若为冗余ACK则放弃发送的判断已在 ACK 中完成
        # if cc_dup_ack_counter.get(from_addr, Seq) is None:
        #     cc_dup_ack_counter[(from_addr, Seq)] = 1
        #     cwnd += 1
        # else:
        #     cc_dup_ack_counter[(from_addr, Seq)] += 1
        #     if cc_dup_ack_counter[(from_addr, Seq)] == 4:
        #         cc_state = CA
        # if (not HAVE_DRAW) and (ack_num+10) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
        #     draw_cwnd()
        #     HAVE_DRAW = True

        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished, 已被成功接收的文件大于chunk，相当于单个发送
            # draw_cwnd()
            # sleep(2)
            print(f"finished sending {sending_index_to_chunkhash[Index]}")

            key_list = list()
            for key, value in unack_pkt.items():
                index2, seq, from_addr = key
                _time, _, dup_ack = value
                if index2 == Index:
                    key_list.append(key)
            for key in key_list:
                unack_pkt.pop(key)
            pass
        else:
            # 确定下一个要传输的数据段的数据, 停等协议 TODO 因为这里每一个chunk都是512KB，在不改MAX_PAYLOAD的前提下，不需要像下面那样做处理
            # left = ack_num * MAX_PAYLOAD
            # right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            # next_data = config.haschunks[sending_index_to_chunkhash[Index]][left: right]
            # data_pkt = udp_pkt.data(Index, ack_num + 1, next_data)
            # unack_pkt[(Index, ack_num + 1, from_addr)] = (time(), data_pkt, 0)
            # print(f"成功接收，继续发送 DATA 报文 seq {ack_num + 1}")
            # sock.sendto(data_pkt, from_addr)
            # 维护窗口，然后进行SR传输
            SR_send(Index, sending_index_to_chunkhash[Index], from_addr, sock)
            if not START[1]:
                START = [time(), True]
            # 累积确认ACK
            # chunkIndex_base_ack[Index] = max(Ack, chunkIndex_base_ack[Index])

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
            # TODO 稀有优先，这里可以实现最少的chunk最先请求，但是还可以实现请求的peer拥有的块最少，这里可以有尽可能多个peer传输chunk过来
            need_download_index.sort(key=lambda x: len(peer_chunkhash_map[x]))
            sended_get = list()
            for index in need_download_index:
                # print(f'in need_download_index {index}')
                chunkhash_str = downloading_index_to_chunkhash[index]
                for addr in peer_chunkhash_map[index]:
                    # print(f'addr {addr} index {index} conn {connecting_peer.keys()}')
                    if addr not in connecting_peer.keys():
                        connecting_peer[addr] = (time(), index)
                        get_pkt = udp_pkt.get(index, pack_payload(chunkhash_str))
                        sock.sendto(get_pkt, addr)
                        print(f'sending GET index {index} to {addr}')
                        sended_get.append(index)
                        chunkIndex_base_ack[index] = 1
                        # print(chunkIndex_base_ack)
                        break
            for index in sended_get:
                need_download_index.remove(index)

            # for index, chunkhash_str in downloading_index_to_chunkhash.items():
            #     from_addr = peer_chunkhash_map[index].pop()
            #     get_pkt = udp_pkt.get(index, pack_payload(chunkhash_str))
            #     # 发送GET报文
            #     sock.sendto(get_pkt, from_addr)
            #     print(f'sending GET index {index} to {from_addr}')
            #     # 累积确认ack，初始化为0
            #     chunkIndex_base_ack[index] = 0
            #     need_download_index.pop(index)

    elif Type == DATA:
        connecting_peer[from_addr] = (time(), Index)
        # 收到DATA报文，这里需要判断这个报文来自的chunk对饮的chunkhash
        print(f"收到 DATA 报文 from {from_addr}, seq {Seq}")

        # TODO 采用累积确认ack的方式,使用pipeline的话这种方式就需要修改
        # if Seq != chunkIndex_base_ack[Index] + 1:
        #     print(f' dup, discard')
        #     print(f'received : {len(receiving_chunks[downloading_index_to_chunkhash[Index]])} index {Index}')
        #     # TODO 这里ack是多少没有想清楚
        #     ack_pkt = udp_pkt.ack(Index, chunkIndex_base_ack[Index])
        #     sock.sendto(ack_pkt, from_addr)
        #     print(f'发送 ACK to {from_addr} ack {chunkIndex_base_ack[Index]}')
        #     return
        # else:
        #     print(f' accept')
        #     chunkIndex_base_ack[Index] = Seq
        # receiving_chunks[downloading_index_to_chunkhash[Index]] += data
        # ack_pkt = udp_pkt.ack(Index, Seq)
        # sock.sendto(ack_pkt, from_addr)
        # print(f"发送 ACK 报文 to {from_addr}, Ack {Seq}")

        # TODO 采用TCP/SR的方式接收，接收窗口内的pkt，返回必要的ACK；这里chunkIndex_base_ack表示的是rcv_base,也就是完整接收的部分
        # TODO 这里的窗口长度怎么考虑？？
        print(f'base_ack {chunkIndex_base_ack[Index]} ')
        # 在base前一个窗口
        if (Seq >= chunkIndex_base_ack[Index] - RECE_WINDSIZE) and (Seq < chunkIndex_base_ack[Index]):
            ack_pkt = udp_pkt.ack(Index, chunkIndex_base_ack[Index]-1)
            sock.sendto(ack_pkt, from_addr)
            print(f"发送 ACK 报文 to {from_addr}, Ack {chunkIndex_base_ack[Index]-1} if-1")
        # 在窗口中
        elif (Seq >= chunkIndex_base_ack[Index]) and (Seq < chunkIndex_base_ack[Index] + RECE_WINDSIZE):
            # 可以将连续数据上传
            if Seq == chunkIndex_base_ack[Index]:
                rece_data = data
                rece_seq = Seq+1
                pop_rece_chunks = list()
                while (Index, rece_seq) in receiving_chunks.keys():
                    pop_rece_chunks.append((Index, rece_seq))
                    rece_data += receiving_chunks[(Index, rece_seq)]
                    rece_seq += 1
                for key in pop_rece_chunks:
                    receiving_chunks.pop(key)
                chunkIndex_base_ack[Index] = rece_seq
                receiving_chunks[downloading_index_to_chunkhash[Index]] += rece_data
                ack_pkt = udp_pkt.ack(Index, rece_seq-1)
                sock.sendto(ack_pkt, from_addr)
                print(f"发送 ACK 报文 to {from_addr}, Ack {rece_seq-1} if-2-1")
            # 放入dict中
            else:
                if (Index, Seq) not in receiving_chunks.keys():
                    receiving_chunks[(Index, Seq)] = data
                    ack_pkt = udp_pkt.ack(Index, chunkIndex_base_ack[Index]-1)
                    sock.sendto(ack_pkt, from_addr)
                    print(f"发送 ACK 报文 to {from_addr}, Ack {chunkIndex_base_ack[Index]-1} if-2-2")
        else:
            # print(f'其他情况的data，无动作，接收到的序号 {Seq} base_ack {chunkIndex_base_ack[Index]} if-3')
            ack_pkt = udp_pkt.ack(Index, chunkIndex_base_ack[Index]-1)
            sock.sendto(ack_pkt, from_addr)
            print(f'其他情况的data, 发送 ACK to {from_addr}, Ack {chunkIndex_base_ack[Index]-1}')


        # 判断是否接收结束
        assert len(receiving_chunks[downloading_index_to_chunkhash[Index]]) % 1024 == 0
        assert len(receiving_chunks[downloading_index_to_chunkhash[Index]]) <= CHUNK_DATA_SIZE
        print(f'received : {len(receiving_chunks[downloading_index_to_chunkhash[Index]])} index {Index}')
        print(f'CHUNK_DATA_SIZE {CHUNK_DATA_SIZE}')
        if len(receiving_chunks[downloading_index_to_chunkhash[Index]]) == CHUNK_DATA_SIZE:
            # TODO 若一个已经下载完成了，需要判断一下
            if downloading_index_to_chunkhash[Index] in downloaded:
                return
            draw_cwnd()
            # sleep(2)
            downloaded.append(downloading_index_to_chunkhash[Index])
            print(f'finish transfer finished {len(downloaded)} need {len(download_chunkhash_str_list)}')
            if len(downloaded) != len(download_chunkhash_str_list):
                return
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
            # target_hash = ["45acace8e984465459c893197e593c36daf653db", "3b68110847941b84e8d05417a5b2609122a56314"]
            with open(output_file, "rb") as download_file:
                download_fragment = pickle.load(download_file)
            sha1 = hashlib.sha1()
            sha1.update(download_fragment[downloading_index_to_chunkhash[Index]])
            # sha1.update(receiving_chunks[downloading_index_to_chunkhash[Index]])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {downloading_index_to_chunkhash[Index]}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = downloading_index_to_chunkhash[Index] == received_chunkhash_str
            if success:
                print(f"Successful received: {success}")
            else:
                print(f"Fail to received the chunk")
            #         接收之后从需要下载的字典中删去该chunk
            connecting_peer.pop(from_addr)
            print(f'check resources rece_pkt {len(receiving_chunks)}')

    else:
        raise ConnectionError("错误的udp_pkt类型")

def final_check():
    """
    当下载完两个chunk时打开检查
    """
    with open("test/tmp3/download_result.fragment", "rb") as download_file:
        download_fragment = pickle.load(download_file)
    target_hash = ["45acace8e984465459c893197e593c36daf653db", "3b68110847941b84e8d05417a5b2609122a56314"]
    if len(download_fragment[target_hash[0]]) == CHUNK_DATA_SIZE and len(download_fragment[target_hash[1]]) == CHUNK_DATA_SIZE:
        print(f'finish downloading two chunks {download_fragment.keys()}')
        for th in target_hash:
            sha1 = hashlib.sha1()
            sha1.update(download_fragment[th])
            received_hash_str = sha1.hexdigest()
            print(f'expected {th}, actual {received_hash_str}')


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
            check_crash()
            check_undownload(sock)
            # final_check()
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
