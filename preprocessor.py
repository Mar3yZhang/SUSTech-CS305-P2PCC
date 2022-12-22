import os

command_list = []


def generate_fragment():
    """
    python3 make_data.py <input file > <output file > <num of chunks> <index>
    """
    command1 = "python3 " \
               "util/make_data.py " \
               "example/ex_file.tar " \
               "./example/data1.fragment " \
               "4 " \
               "1,2"

    command2 = "python3 " \
               "util/make_data.py " \
               "example/ex_file.tar " \
               "./example/data2.fragment " \
               "4 " \
               "3,4"

    command_list.append(command1)
    command_list.append(command2)


def generate_download_info():
    command = "sed -n \"3p\" master.chunkhash > example/download.chunkhash"
    command_list.append(command)


generate_fragment()
generate_download_info()

for i in command_list:
    os.system(i)
