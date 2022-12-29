import os

command_list = []


def generate_fragment():
    """
    python3 make_data.py <input file > <output file > <num of chunks> <index>
    """
    command1 = "python3 " \
               "../util/make_data.py " \
               "foo.zip " \
               "data1.fragment " \
               "10 " \
               "1,2,3,4"

    command2 = "python3 " \
               "../util/make_data.py " \
               "foo.zip " \
               "data2.fragment " \
               "10 " \
               "5,6,7"

    command3 = "python3 " \
               "../util/make_data.py " \
               "foo.zip " \
               "data3.fragment " \
               "10 " \
               "8,9,10"

    command_list.append(command1)
    command_list.append(command2)
    command_list.append(command3)

# 如果需要实现peer自动查找缺漏的chunk并从其他peer下载的话，需要自动生成peer对应的download.chunkhash
def generate_download_info():
    command = "sed -n \"3p\" master.chunkhash > download.chunkhash"
    command_list.append(command)


generate_fragment()
generate_download_info()

for i in command_list:
    os.system(i)
