import os
import json
import hmac
import hashlib
import heapq
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random
import time
import sys

# 定义一个全局变量来记录查询函数的执行时间
query_execution_time = 0  # 初始化全局变量

# 定义生成 HMAC 和加密所需的函数
def generate_hmac(key, message):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"Expected key to be bytes or bytearray, but got {type(key).__name__}")
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()


def encrypt_aes_ctr(key, iv, plaintext, output_length):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return ciphertext[:output_length]

def decrypt_aes_ctr(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_str = decrypted_data.decode('utf-8', 'ignore')
    return decrypted_str

def random_bytes(size):
    return os.urandom(size)

# 生成加密顶点对的 token 函数
def token(key, node_pair):
    # 打印 key 类型和 node_pair
    # print(f"token: key type: {type(key)}, node_pair: {node_pair}")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"Expected key to be bytes or bytearray, but got {type(key).__name__}")
    node_pair_str = f"{node_pair[0]}-{node_pair[1]}"
    key1 = generate_hmac(key, '1' + node_pair_str)
    encrypted_pair = generate_hmac(key1, node_pair_str).hex()
    return encrypted_pair

# Dijkstra 算法计算最短路径
def dijkstra(graph, start):
    dist = {start: 0}
    prev = {start: None}
    pq = [(0, start)]

    while pq:
        current_dist, u = heapq.heappop(pq)

        if current_dist > dist[u]:
            continue

        for v, weight in graph.get(u, []):
            distance = current_dist + weight
            if v not in dist or distance < dist[v]:
                dist[v] = distance
                prev[v] = u
                heapq.heappush(pq, (distance, v))

    return dist, prev

def get_shortest_path(prev, target):
    path = []
    while target is not None:
        path.append(target)
        target = prev[target]
    return path[::-1]

def compute_all_pairs_shortest_paths(graph):
    shortest_paths_dict = {}

    for u in graph:
        dist, prev = dijkstra(graph, u)
        for v in dist:
            if v == u:
                continue
            path = get_shortest_path(prev, v)
            if len(path) > 2:
                w = path[1]
                shortest_paths_dict[(u, v)] = (w, v)
            else:
                shortest_paths_dict[(u, v)] = (v, v)

    return shortest_paths_dict

# setup 方法实现
def setup(graph, encryption_key, big_block, small_block, data_size):
    # print(f"setup: encryption_key type before classification: {type(encryption_key)}")  # 调试输出

    # 计算所有顶点对的最短路径
    shortest_paths_dict = compute_all_pairs_shortest_paths(graph)

    gamma = defaultdict(list)
    node_pair_map = {}

    for node_pair, path_info in shortest_paths_dict.items():
        encrypted_pair = token(encryption_key, node_pair)
        key2 = generate_hmac(encryption_key, '2' + f"{node_pair[0]}-{node_pair[1]}")
        plaintext = json.dumps(path_info)

        # 获取下一对顶点的 token
        next_node_pair_token = token(encryption_key, path_info)

        # 加密路径信息并存储
        random_iv = random_bytes(16)
        ciphertext = encrypt_aes_ctr(key2, random_iv, plaintext, small_block * 40)
        gamma[encrypted_pair].append((next_node_pair_token, ciphertext, random_iv, key2))

        node_pair_map[encrypted_pair] = node_pair

    return gamma, node_pair_map



def query(gamma, encrypted_pair):
    path_chain = []
    current_pair = encrypted_pair

    while current_pair in gamma:
        encrypted_data = gamma[current_pair][0]
        next_token, ciphertext, iv, key2 = encrypted_data
        path_chain.append((current_pair, ciphertext, iv, key2))
        if next_token == current_pair:
            break
        current_pair = next_token

    return path_chain

def reveal(path_chain, node_pair_map):
    """
    解密路径链并还原为完整路径。

    该函数对加密路径链进行解密，并还原为完整的路径。

    参数：
    - path_chain: 由 query 函数返回的加密路径链。
    - node_pair_map: 映射加密顶点对和解密后的节点对的字典。

    返回：
    - 完整的解密路径。
    """
    if not path_chain:
        return []  # 如果路径链为空，直接返回空列表

    path = []

    # 处理路径链中的第一个加密顶点对
    first_encrypted_pair = path_chain[0][0]
    start_node_pair = node_pair_map.get(first_encrypted_pair)
    if start_node_pair:
        path.append(start_node_pair[0])  # 添加起点

    # 解密路径链中的每个加密段
    for encrypted_pair, ciphertext, iv, key2 in path_chain:
        decrypted_text = decrypt_aes_ctr(key2, iv, ciphertext)
        try:
            # 解密后的文本是 JSON 格式的节点对
            node_pair = json.loads(decrypted_text)
            path.append(node_pair[0])  # 添加当前节点
        except json.JSONDecodeError as e:
            print(f"JSON 解码错误: {e}")

    # 确保路径的终点被添加
    last_encrypted_pair = path_chain[-1][0]
    final_node_pair = node_pair_map.get(last_encrypted_pair)
    if final_node_pair and (not path or path[-1] != final_node_pair[1]):
        path.append(final_node_pair[1])  # 添加终点

    return path


def print_path(path):
    """
    打印解密后的路径。

    参数：
    - path: 解密后的路径列表。
    """
    if path:
        print(f"\n解密后的路径: {path}")
    else:
        print("路径为空，无法打印。")


def get_total_size(obj):
    """
    递归计算对象（包括列表、元组、字典等）及其包含的所有子对象的总大小。

    参数:
    obj -- 要计算大小的对象

    返回:
    对象的总大小（以字节为单位）
    """
    # 如果是基本数据类型（int, str, float等），直接返回其大小
    if isinstance(obj, (int, float, str, bool)):
        return sys.getsizeof(obj)

    # 如果是列表或元组，递归计算每个元素的大小
    elif isinstance(obj, (list, tuple)):
        total_size = sys.getsizeof(obj)  # 获取列表或元组本身的大小
        for item in obj:
            total_size += get_total_size(item)  # 递归计算每个元素的大小
        return total_size

    # 如果是字典，递归计算键值对的大小
    elif isinstance(obj, dict):
        total_size = sys.getsizeof(obj)  # 获取字典本身的大小
        for key, value in obj.items():
            total_size += get_total_size(key)  # 计算键的大小
            total_size += get_total_size(value)  # 计算值的大小
        return total_size

    # 如果是集合，递归计算每个元素的大小
    elif isinstance(obj, set):
        total_size = sys.getsizeof(obj)  # 获取集合本身的大小
        for item in obj:
            total_size += get_total_size(item)  # 递归计算每个元素的大小
        return total_size

    # 如果是其他类型的对象，返回对象的大小
    return sys.getsizeof(obj)

# 计算内存大小并自动调整单位的函数
def format_size(size_in_bytes):
    """
    根据内存大小（字节）选择合适的单位并格式化输出。
    """
    if size_in_bytes < 1024:
        return f"{size_in_bytes} Bytes"
    elif size_in_bytes < 1024 ** 2:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 ** 3:
        return f"{size_in_bytes / (1024 ** 2):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 ** 3):.2f} GB"

# 加载图
def load_graph(file_path):
    graph = defaultdict(list)
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('#'):
                continue
            from_node, to_node = map(int, line.strip().split())
            graph[from_node].append((to_node, 1))  # 默认权重为 1
    return graph

def get_lambda_value(query_execution_time):
    """
    根据查询时间动态选择合适的 lambda_value 以模拟网络延迟
    参数:
    - query_execution_time: 查询执行时间（毫秒）

    返回：
    - 合适的 lambda_value
    """
    if query_execution_time >= 0.1:
        # 查询时间接近 0.1ms，选择较小的 lambda_value
        return 10000
    elif query_execution_time >= 0.01:
        # 查询时间接近 0.01ms，选择中等的 lambda_value
        return 100000
    else:
        # 查询时间接近 0.001ms，选择较大的 lambda_value
        return 1000000


def run_query(vertex_class_key, gamma, node_pair_map, key, num_iterations):
    """
    运行查询和解密，并返回查询时间、解密时间、路径以及内存占用。
    参数:
    - vertex_class_key: 查询的顶点对键
    - gamma: 加密路径字典
    - node_pair_map: 映射加密顶点对和解密后的节点对的字典
    - key: 加密键
    - num_iterations: 查询的次数

    返回：
    - total_query_time: 总查询时间
    - total_reveal_time: 总解密时间
    - average_query_time: 平均查询时间
    - average_reveal_time: 平均解密时间
    - complete_paths: 解密后的路径链
    - memory_usage: 查询结果占用的内存
    """
    total_query_time = 0
    total_reveal_time = 0
    complete_paths = []

    for _ in range(num_iterations):
        # 查询加密路径链
        Query_start_time = time.perf_counter()
        encrypted_key = token(key, vertex_class_key)

        encrypted_paths = query(gamma, encrypted_key)

        Query_end_time = time.perf_counter()
        query_execution_time = (Query_end_time - Query_start_time) * 1000  # 转换为毫秒

        # 根据查询时间选择合适的 lambda_value
        lambda_value = get_lambda_value(query_execution_time)

        # 模拟网络延迟（符合指数分布）
        network_delay = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒

        # 将网络延迟转换为毫秒并加到查询时间上
        # print(f"\n初始查询时间: {query_execution_time}")
        total_execution_time = query_execution_time + (network_delay * 1000)  # 转换为毫秒
        # print(f"\n时延为: {network_delay * 1000}")

        total_query_time += total_execution_time  # 累加查询时间

        # 解密路径链
        if encrypted_paths:
            Reveal_start_time = time.perf_counter()
            complete_paths_iter = reveal(encrypted_paths, node_pair_map)
            Reveal_end_time = time.perf_counter()
            Reveal_execution_time = (Reveal_end_time - Reveal_start_time) * 1000  # 毫秒

            total_reveal_time += Reveal_execution_time  # 累加解密时间
            complete_paths = complete_paths_iter  # 保存完整路径
        else:
            print(f"\n未找到任何路径链: {vertex_class_key}")

    # 计算平均查询时间和平均解密时间
    average_query_time = total_query_time / num_iterations
    average_reveal_time = total_reveal_time / num_iterations

    # 计算内存占用
    memory_usage = get_total_size(encrypted_paths)  # 只需要计算一次

    return total_query_time, total_reveal_time, average_query_time, average_reveal_time, complete_paths, memory_usage


# 示例
# graph = {
#     'A': [('B', 1), ('C', 4)],
#     'B': [('A', 1), ('C', 2), ('D', 5)],
#     'C': [('A', 4), ('B', 2), ('D', 1)],
#     'D': [('B', 5), ('C', 1)]
# }

key = os.urandom(32)
file_path = "./dataset/p2p-Gnutella04.txt"  # 数据集相对路径
graph = load_graph(file_path)
gamma, node_pair_map= setup(graph, key, big_block=2, small_block=3, data_size=20)
print("Setup阶段完成")

# lambda_value = 10000
num_iterations = 1000  # 执行的次数


vertex_class_keys = [('0', '22463'), ('0', '22470'), ('0', '22471'), ('0', '22475'), ('0', '22476'), ('0', '22478'), ('0', '22487'), ('0', '22489'), ('0', '22496'), ('0', '22502'), ('0', '22504'), ('0', '22505'), ('0', '22506'), ('0', '22507'), ('0', '22510'), ('0', '22511'), ('0', '22515'), ('0', '22519'), ('0', '22524'), ('0', '22527'), ('0', '22535'), ('0', '22540'), ('0', '22544'), ('0', '22545'), ('0', '22548'), ('0', '22549'), ('0', '22550'), ('0', '22561'), ('0', '22562'), ('0', '22563'), ('0', '22565'), ('0', '22566'), ('0', '22568'), ('0', '22569'), ('0', '22571'), ('0', '22572'), ('0', '22575'), ('0', '22577'), ('0', '22589'), ('0', '22590'), ('0', '22593'), ('0', '22595'), ('0', '22601'), ('0', '22604'), ('0', '22613'), ('0', '22614'), ('0', '22615'), ('0', '22618'), ('0', '22625'), ('0', '22626')]


# 用于存储每个查询的平均查询时间
average_query_times = []

# 执行查询并输出结果
for vertex_class_key in vertex_class_keys:
    print(f"\n开始处理顶点对: {vertex_class_key}")

    # 执行查询并返回结果
    total_query_time, total_reveal_time, average_query_time, average_reveal_time, complete_paths, memory_usage = run_query(
        vertex_class_key, gamma, node_pair_map, key, num_iterations)

    # 输出结果
    print(f"平均查询时间: {average_query_time:.4f} 毫秒")
    print(f"平均解密时间: {average_reveal_time:.4f} 毫秒")
    print(f"查询结果的内存使用: {memory_usage:.0f} Bytes")

    # 打印路径（如果有的话）
    print_path(complete_paths)

    # 将当前顶点对的平均查询时间添加到列表中
    average_query_times.append(average_query_time)

# 初始化总查询时间
FANAL_query_time = 0

# 输出所有查询的平均查询时间并累加
print("\n所有查询的平均查询时间：")
for idx, avg_query_time in enumerate(average_query_times, start=1):
    print(f"查询 {idx} 的平均查询时间: {avg_query_time:.4f} 毫秒")

    # 累加查询时间
    FANAL_query_time += avg_query_time

# 输出总查询时间
print(f"\n所有查询的总平均查询时间: {FANAL_query_time:.4f} 毫秒")

size_gamma = get_total_size(gamma)
print(f"加密字典 gamma 所占内存大小: {format_size(size_gamma)}")


# vertex_class_key1 = ('0', '5188')
# vertex_class_key2 = ('0', '5189')
# vertex_class_key3 = ('0', '5191')
# vertex_class_key4 = ('0', '5192')
# vertex_class_key5 = ('0', '5193')
#
# # 初始化总查询时间和总解密时间
# total_query_time = 0
# total_reveal_time = 0
# num_iterations = 1000  # 执行的次数
#
# # 设置网络延迟的λ值
# lambda_value = 0.1  # λ值决定了延迟的平均值，数值越大网络延迟越小
#
# # print("\n开始解密路径链：")
# for _ in range(num_iterations):
#     # 查询加密路径链
#     Query_start_time1 = time.perf_counter()
#     encrypted_key1 = token(key, vertex_class_key1)
#
#
#
#     encrypted_paths1 = query(gamma, encrypted_key1)
#
#     Query_end_time1 = time.perf_counter()
#     query_execution_time1 = (Query_end_time1 - Query_start_time1) * 1000  # 毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay1 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time1 = query_execution_time1 + (network_delay1 * 1000)  # 转换为毫秒
#
#     total_query_time += query_execution_time1  # 累加查询时间
#
#
#
#     # 解密路径链
#     if encrypted_paths1:
#         Reveal_start_time1 = time.perf_counter()
#         complete_paths1 = reveal(encrypted_paths1, node_pair_map)
#         Reveal_end_time1 = time.perf_counter()
#         Reveal_execution_time1 = (Reveal_end_time1 - Reveal_start_time1) * 1000  # 毫秒
#
#         total_reveal_time += Reveal_execution_time1  # 累加解密时间
#     else:
#         print("\n未找到任何路径链。")
#
#
#
#
# # print(f"\nQuerying path: {vertex_class_key2}")
# # print(f"Querying with encrypted_key: {encrypted_key2}")
#
# # 初始化总查询时间、总解密时间
# total_query_time2 = 0
# total_reveal_time2 = 0
#
# # print("\n开始解密路径链：")
# for _ in range(num_iterations):
#     # 查询加密路径链
#     Query_start_time2 = time.perf_counter()
#     encrypted_key2 = token(key, vertex_class_key2)
#
#     encrypted_paths2 = query(gamma, encrypted_key2)
#
#     Query_end_time2 = time.perf_counter()
#     query_execution_time2 = (Query_end_time2 - Query_start_time2) * 1000  # 毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay2 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time2 = query_execution_time2 + (network_delay2 * 1000)  # 转换为毫秒
#
#     total_query_time2 += query_execution_time2  # 累加查询时间
#
#
#
#     # 解密路径链
#     if encrypted_paths2:
#         Reveal_start_time2 = time.perf_counter()
#         complete_paths2 = reveal(encrypted_paths2, node_pair_map)
#         Reveal_end_time2 = time.perf_counter()
#         Reveal_execution_time2 = (Reveal_end_time2 - Reveal_start_time2) * 1000  # 毫秒
#
#         total_reveal_time2 += Reveal_execution_time2  # 累加解密时间
#     else:
#         print("\n未找到任何路径链。")
#
#
# # 初始化总查询时间、总解密时间
# total_query_time3 = 0
# total_reveal_time3 = 0
#
# # print("\n开始解密路径链：")
# for _ in range(num_iterations):
#     # 查询加密路径链
#     Query_start_time3 = time.perf_counter()
#     encrypted_key3 = token(key, vertex_class_key3)
#
#     encrypted_paths3 = query(gamma, encrypted_key3)
#
#     Query_end_time3 = time.perf_counter()
#     query_execution_time3 = (Query_end_time3 - Query_start_time3) * 1000  # 毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay3 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time3 = query_execution_time3 + (network_delay3 * 1000)  # 转换为毫秒
#
#     total_query_time3 += query_execution_time3  # 累加查询时间
#
#
#
#     # 解密路径链
#     if encrypted_paths3:
#         Reveal_start_time3 = time.perf_counter()
#         complete_paths3 = reveal(encrypted_paths3, node_pair_map)
#         Reveal_end_time3 = time.perf_counter()
#         Reveal_execution_time3 = (Reveal_end_time3 - Reveal_start_time3) * 1000  # 毫秒
#
#         total_reveal_time3 += Reveal_execution_time3  # 累加解密时间
#     else:
#         print("\n未找到任何路径链。")
#
# # 初始化总查询时间、总解密时间
# total_query_time4 = 0
# total_reveal_time4 = 0
#
# # print("\n开始解密路径链：")
# for _ in range(num_iterations):
#     # 查询加密路径链
#     Query_start_time4 = time.perf_counter()
#     encrypted_key4 = token(key, vertex_class_key4)
#
#     encrypted_paths4 = query(gamma, encrypted_key4)
#
#     Query_end_time4 = time.perf_counter()
#     query_execution_time4 = (Query_end_time4 - Query_start_time4) * 1000  # 毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay4 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time4 = query_execution_time4 + (network_delay4 * 1000)  # 转换为毫秒
#
#     total_query_time4 += query_execution_time4  # 累加查询时间
#
#
#
#     # 解密路径链
#     if encrypted_paths4:
#         Reveal_start_time4 = time.perf_counter()
#         complete_paths4 = reveal(encrypted_paths4, node_pair_map)
#         Reveal_end_time4 = time.perf_counter()
#         Reveal_execution_time4 = (Reveal_end_time4 - Reveal_start_time4) * 1000  # 毫秒
#
#         total_reveal_time4 += Reveal_execution_time4  # 累加解密时间
#     else:
#         print("\n未找到任何路径链。")
#
#
# # 初始化总查询时间、总解密时间
# total_query_time5 = 0
# total_reveal_time5 = 0
#
# # print("\n开始解密路径链：")
# for _ in range(num_iterations):
#     # 查询加密路径链
#     Query_start_time5 = time.perf_counter()
#     encrypted_key5 = token(key, vertex_class_key5)
#
#     encrypted_paths5 = query(gamma, encrypted_key5)
#
#     Query_end_time5 = time.perf_counter()
#     query_execution_time5 = (Query_end_time5 - Query_start_time5) * 1000  # 毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay5 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time5 = query_execution_time5 + (network_delay5 * 1000)  # 转换为毫秒
#
#     total_query_time5 += query_execution_time5  # 累加查询时间
#
#
#
#     # 解密路径链
#     if encrypted_paths5:
#         Reveal_start_time5 = time.perf_counter()
#         complete_paths5 = reveal(encrypted_paths5, node_pair_map)
#         Reveal_end_time5 = time.perf_counter()
#         Reveal_execution_time5 = (Reveal_end_time5 - Reveal_start_time5) * 1000  # 毫秒
#
#         total_reveal_time5 += Reveal_execution_time5  # 累加解密时间
#     else:
#         print("\n未找到任何路径链。")
#
#
# # 计算平均查询时间和平均解密时间
# average_query_time = total_query_time / num_iterations
# average_reveal_time = total_reveal_time / num_iterations
#
#
# print(f"Querying path: {vertex_class_key1}")
# # 使用 print_path 函数输出路径
# print_path(complete_paths1)
#
# # 输出平均时间
# print(f"平均查询时间: {average_query_time:.4f} 毫秒")
# print(f"平均解密时间: {average_reveal_time:.4f} 毫秒")
# memory_usage1 = get_total_size(encrypted_paths1)
# print(f"加密最短路径链占用内存: {memory_usage1} Bytes")
#
#
# # 计算平均查询时间、平均解密时间
# average_query_time2 = total_query_time2 / num_iterations
# average_reveal_time2 = total_reveal_time2 / num_iterations
#
#
# print(f"Querying path: {vertex_class_key2}")
# # 使用 print_path 函数输出路径
# print_path(complete_paths2)
#
# # 计算内存占用（每次查询的结果内存使用量是固定的，查询结果结构相同）
# memory_usage2 = get_total_size(encrypted_paths2)  # 只需要计算一次
#
# # 输出平均时间和内存使用
# print(f"平均查询时间: {average_query_time2:.4f} 毫秒")
# print(f"平均解密时间: {average_reveal_time2:.4f} 毫秒")
# print(f"查询结果的内存使用: {memory_usage2:.0f} Bytes")
#
# # 计算平均查询时间、平均解密时间
# average_query_time3 = total_query_time3 / num_iterations
# average_reveal_time3 = total_reveal_time3 / num_iterations
#
# print(f"Querying path: {vertex_class_key3}")
#
# # 使用 print_path 函数输出路径
# print_path(complete_paths3)
#
# # 计算内存占用（每次查询的结果内存使用量是固定的，查询结果结构相同）
# memory_usage3 = get_total_size(encrypted_paths3)  # 只需要计算一次
#
# # 输出平均时间和内存使用
# print(f"平均查询时间: {average_query_time3:.4f} 毫秒")
# print(f"平均解密时间: {average_reveal_time3:.4f} 毫秒")
# print(f"查询结果的内存使用: {memory_usage3:.0f} Bytes")
#
#
# # 计算平均查询时间、平均解密时间
# average_query_time4 = total_query_time4 / num_iterations
# average_reveal_time4 = total_reveal_time4 / num_iterations
#
# print(f"Querying path: {vertex_class_key4}")
#
# # 使用 print_path 函数输出路径
# print_path(complete_paths4)
#
# # 计算内存占用（每次查询的结果内存使用量是固定的，查询结果结构相同）
# memory_usage4 = get_total_size(encrypted_paths4)  # 只需要计算一次
#
# # 输出平均时间和内存使用
# print(f"平均查询时间: {average_query_time4:.4f} 毫秒")
# print(f"平均解密时间: {average_reveal_time4:.4f} 毫秒")
# print(f"查询结果的内存使用: {memory_usage4:.0f} Bytes")
#
# # 计算平均查询时间、平均解密时间
# average_query_time5 = total_query_time5 / num_iterations
# average_reveal_time5 = total_reveal_time5 / num_iterations
#
# print(f"Querying path: {vertex_class_key5}")
#
# # 使用 print_path 函数输出路径
# print_path(complete_paths5)
#
# # 计算内存占用（每次查询的结果内存使用量是固定的，查询结果结构相同）
# memory_usage5 = get_total_size(encrypted_paths5)  # 只需要计算一次
#
# # 输出平均时间和内存使用
# print(f"平均查询时间: {average_query_time5:.4f} 毫秒")
# print(f"平均解密时间: {average_reveal_time5:.4f} 毫秒")
# print(f"查询结果的内存使用: {memory_usage5:.0f} Bytes")
