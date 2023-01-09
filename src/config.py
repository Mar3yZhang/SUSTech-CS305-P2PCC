import struct
# 所有Peer都共享的设置参数

# 报文类型
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024  # 512K
# 报文数据部分的最大载荷
MAX_PAYLOAD = 1024
PKT_FORMAT = '!HBBHHII'
HEADER_LEN = struct.calcsize(PKT_FORMAT)
# 以网络端作为大小端打包数据
MAGIC = 52305
TEAM = 35
# 表示当前字段这个包用不到
NO_USE = 0

# 超时
ALPHA: float = 0.125
BETA: float = 0.25

# 拥塞控制状态
SS = 0
CA = 1
FR = 2
# 其中的小状态,dup_ack表示dup_ack为3时，一般的dup_ack在外面处理
original = 0
new_ACK = 1
dup_ACK = 2
time_out = 3
cwnd_sst = 4