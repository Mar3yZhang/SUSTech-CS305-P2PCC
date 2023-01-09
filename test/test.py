import grader
import time
import pickle
import hashlib
import pytest
import os
import concurrency_visualizer

MAX_PAYLOAD = 1024


# def test_content():
#     with open("test/tmp3/download_result.fragment", "rb") as download_file:
#         download_fragment = pickle.load(download_file)
#
#     target_hash = ["45acace8e984465459c893197e593c36daf653db", "3b68110847941b84e8d05417a5b2609122a56314"]
#
#     for th in target_hash:
#         # assert th in download_fragment, f"download hash mismatch, target: {th}, has: {download_fragment.keys()}"
#         print(f'has {download_fragment.keys()}')
#         sha1 = hashlib.sha1()
#         sha1.update(download_fragment[th])
#         received_hash_str = sha1.hexdigest()
#         print(f'th {th} {th.strip()}')
#         print(f'rece {received_hash_str} {received_hash_str.strip()}')
# assert th.strip() == received_hash_str.strip(), f"received data mismatch, expect hash: {target_hash}, actual: {received_hash_str}"


def check_data():
    with open("test/tmp3/download_result.fragment", "rb") as download_file:
        download_fragment = pickle.load(download_file)
    with open("test/tmp3/data3-2.fragment", "rb") as data3_2_file:
        data3_2 = pickle.load(data3_2_file)
    with open("test/tmp3/data3-3.fragment", "rb") as data3_3_file:
        data3_3 = pickle.load(data3_3_file)

    print(f'check diff between data2 {data3_2.keys()}')
    chunk2 = '45acace8e984465459c893197e593c36daf653db'
    data_down2 = download_fragment[chunk2]
    data_2 = data3_2[chunk2]
    left = 0
    while left * MAX_PAYLOAD < len(data_2):
        if data_down2[left * MAX_PAYLOAD:(left + 1) * MAX_PAYLOAD] != data_2[left * MAX_PAYLOAD:(left + 1) * MAX_PAYLOAD]:
            print(f'diff of data2 at left {left}')
        left += 1

    print(f'check diff between data3 {data3_3.keys()}')
    chunk3 = '3b68110847941b84e8d05417a5b2609122a56314'
    data_down3 = download_fragment[chunk3]
    data_3 = data3_3[chunk3]
    left1 = 0
    left2 = 0
    while left * MAX_PAYLOAD < len(data_3):
        if data_down3[left1 * MAX_PAYLOAD:(left1 + 1) * MAX_PAYLOAD] != data_3[
                                                                          left2 * MAX_PAYLOAD:(left2 + 1) * MAX_PAYLOAD]:
            print(f'diff of data3 at left {left}')
            # left1 -= 1
        left1 += 1
        left2 += 1

if __name__ == "__main__":
    check_data()