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

# 顶点分类和顶点对生成函数
def classify_vertices(graph, group_size):
    """
    将图的顶点按照指定的每组大小均匀分配到若干类别。

    参数:
    - graph: 图的邻接表表示，例如 {'A': [('B', 1), ('C', 4)]}。
    - group_size: 每组包含的顶点数量。

    返回:
    - groups: 分类后的顶点集合列表。
    - num_groups: 分类的总数。
    """
    vertices = list(graph.keys())  # 提取图中的顶点
    groups = []
    num_groups = (len(vertices) + group_size - 1) // group_size  # 计算需要的组数

    for i in range(num_groups):
        start_idx = i * group_size
        end_idx = min(start_idx + group_size, len(vertices))
        groups.append(vertices[start_idx:end_idx])

    return groups, num_groups


def generate_pairs_from_classified_to_unclassified(graph, groups):
    """
    根据分类集合与未分类顶点生成顶点对。

    参数:
    - graph: 图的邻接表表示，例如 {'A': [('B', 1), ('C', 4)]}。
    - groups: 分类的集合列表。

    返回:
    - pairs_from_classified: 分类到未分类的顶点对字典。
    """
    pairs_from_classified = defaultdict(list)

    for i, group in enumerate(groups):
        group_label = f"Group_{i+1}"
        for vertex in graph:  # 遍历图中的所有顶点
            pairs_from_classified[(group_label, vertex)] = [
                (classified_vertex, vertex) for classified_vertex in group
            ]

    return pairs_from_classified


def classify_and_generate_pairs(graph, groups):
    """
    根据分类集合生成分类内部的顶点对。

    参数:
    - graph: 图的邻接表表示，例如 {'A': [('B', 1), ('C', 4)]}。
    - groups: 分类的集合列表。

    返回:
    - classified_pairs: 分类内部的顶点对字典。
    """
    classified_pairs = defaultdict(list)

    for i, group in enumerate(groups):
        group_label = f"Group_{i + 1}"
        for vertex in graph:  # 遍历所有顶点
            classified_pairs[(vertex, group_label)] = [
                (vertex, target_vertex) for target_vertex in group
            ]

    return classified_pairs


def generate_token_dict(classified_pairs_or_pairs_from_classified, encryption_key, is_class=True):
    # print(f"generate_token_dict: encryption_key type: {type(encryption_key)}")  # 调试信息
    if not isinstance(encryption_key, (bytes, bytearray)):
        raise TypeError(f"Expected encryption_key to be bytes or bytearray, but got {type(encryption_key).__name__}")

    token_dict = defaultdict(list)

    for pair_key, pairs in classified_pairs_or_pairs_from_classified.items():
        # 打印 pair_key 和加密密钥类型
        # print(f"Processing pair_key: {pair_key}, encryption_key type: {type(encryption_key)}")

        # 正确生成加密键
        dict_key = token(encryption_key, pair_key) if is_class else token(encryption_key, pair_key)
        # print(f"Generated dict_key: {dict_key}")

        # 生成 tokens
        tokens = [token(encryption_key, pair) for pair in pairs if pair[0] != pair[1]]
        # print(f"Generated tokens: {tokens}")

        token_dict[dict_key].extend(tokens)

    return token_dict


def generate_token_dict_by_class(classified_pairs, key):
    # print(f"generate_token_dict_by_class: key type: {type(key)}")
    return generate_token_dict(classified_pairs, key, is_class=True)

def generate_token_dict_by_pairs(pairs_from_classified, key):
    # print(f"generate_token_dict_by_pairs: key type: {type(key)}")
    return generate_token_dict(pairs_from_classified, key, is_class=False)



# setup 方法实现
def setup(graph, encryption_key, big_block, small_block, data_size,group_size):
    # print(f"setup: encryption_key type before classification: {type(encryption_key)}")  # 调试输出

    # 计算所有顶点对的最短路径
    shortest_paths_dict = compute_all_pairs_shortest_paths(graph)

    # 顶点分类
    # vertices = list(graph.keys())
    groups,num_groups = classify_vertices(graph, group_size)

    # 输出分类结果
    print(f"分类结果：共 {num_groups} 个组。")
    for i, group in enumerate(groups):
        print(f"组 {i + 1}: {group}")

    # 输出分类结果
    # print("分类结果：")
    # print(f"V1: {V1}")
    # print(f"V2: {V2}")
    # print(f"V3: {V3}")

    # 生成顶点对
    classified_pairs = classify_and_generate_pairs(graph, groups)
    pairs_from_classified = generate_pairs_from_classified_to_unclassified(graph, groups)

    # 输出生成的顶点对
    # print("\n生成的分类顶点对 (classified_pairs)：")
    # for key, pairs in classified_pairs.items():
    #     print(f"  {key}: {pairs}")
    #
    # print("\n生成的非分类顶点对 (pairs_from_classified)：")
    # for key, pairs in pairs_from_classified.items():
    #     print(f"  {key}: {pairs}")

    # 检查密钥类型
    # print(f"setup: encryption_key type before token_dict_by_class: {type(encryption_key)}")

    # 生成加密字典
    token_dict_by_class = generate_token_dict_by_class(classified_pairs, encryption_key)
    token_dict_by_pairs = generate_token_dict_by_pairs(pairs_from_classified, encryption_key)
    # print("\nToken Dict by Class Keys:")
    # for dict_key in token_dict_by_class.keys():
    #     print(f"Key: {dict_key}")
    #
    # print("\nToken Dict by Pairs Keys:")
    # for dict_key in token_dict_by_pairs.keys():
    #     print(f"Key: {dict_key}")

    # 输出密钥类型检查
    # print(f"setup: encryption_key type after token_dict_by_class: {type(encryption_key)}")

    # 加密生成 gamma
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

    return gamma, node_pair_map, token_dict_by_class, token_dict_by_pairs, groups




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

def query_encrypted_paths(encrypted_key, gamma, token_dict_by_class, token_dict_by_pairs):
    """
    根据加密键查询加密路径链。

    参数：
    - encrypted_key: 输入的加密键（通过 token 生成）。
    - gamma: 加密路径字典。
    - token_dict_by_class: 按顶点分类生成的加密 token 字典。
    - token_dict_by_pairs: 按顶点对生成的加密 token 字典。

    返回：
    - 加密路径链的列表。
    """
    # 判断加密键是否属于 token_dict_by_class 或 token_dict_by_pairs
    tokens = token_dict_by_class.get(encrypted_key)
    if tokens is not None:
        # 直接在 token_dict_by_class 中找到对应的 tokens，跳过打印
        pass
    elif (tokens := token_dict_by_pairs.get(encrypted_key)) is not None:
        # 直接在 token_dict_by_pairs 中找到对应的 tokens，跳过打印
        pass
    elif encrypted_key in gamma:
        # 如果加密键直接在 gamma 中，则尝试构建路径链
        path_chain = query(gamma, encrypted_key)
        if path_chain:
            return [path_chain]
        else:
            return None
    else:
        # 如果加密键既不在 token_dict_by_class，也不在 token_dict_by_pairs，也不在 gamma 中
        return None

    # 查询 gamma 中对应的加密路径链
    encrypted_paths = []
    for token_key in tokens:
        # 使用 query 函数查询路径链
        path_chain = query(gamma, token_key)
        if path_chain:
            encrypted_paths.append(path_chain)

    return encrypted_paths




def reveal(encrypted_paths, node_pair_map):
    """
    解密路径链并还原为完整路径。

    该函数将解密多个加密路径链并还原为完整的路径。
    """
    complete_paths = []

    # 处理每条加密路径链
    for path_chain in encrypted_paths:
        path = []

        # 获取路径链中的第一个加密顶点对
        first_encrypted_pair = path_chain[0][0]
        start_node_pair = node_pair_map.get(first_encrypted_pair)
        if start_node_pair:
            path.append(start_node_pair[0])

        # 解密每个路径元素
        for encrypted_pair, ciphertext, iv, key2 in path_chain:
            decrypted_text = decrypt_aes_ctr(key2, iv, ciphertext)
            try:
                # 解密后的文本是 JSON 格式的路径信息
                node_pair = json.loads(decrypted_text)
                path.append(node_pair[0])  # 添加第一个顶点到路径
            except json.JSONDecodeError as e:
                print("Error decoding JSON:", e)

        # 确保路径链的最后一部分包含终点
        if path_chain:
            last_encrypted_pair = path_chain[-1][0]
            final_node_pair = node_pair_map.get(last_encrypted_pair)
            if final_node_pair and (not path or path[-1] != final_node_pair[1]):
                path.append(final_node_pair[1])  # 添加最后一个顶点到路径

        complete_paths.append(path)

    return complete_paths

def print_decrypted_paths(complete_paths):
    """
    输出解密后的路径链。

    该函数接受解密后的完整路径链，并打印每条路径。
    """
    for path in complete_paths:
        print(f"解密后的路径链: {path}")


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


# 示例
# graph = {
#     'A': [('B', 1), ('C', 4)],
#     'B': [('A', 1), ('C', 2), ('D', 5)],
#     'C': [('A', 4), ('B', 2), ('D', 1)],
#     'D': [('B', 5), ('C', 1)]
# }

key = os.urandom(32)
file_path = "./dataset/facebook_combined.txt"  # 数据集相对路径
graph = load_graph(file_path)
print(f"Main: key type before setup: {type(key)}")
gamma, node_pair_map, token_dict_by_class, token_dict_by_pairs, groups = setup(graph, key, big_block=2, small_block=3, data_size=10,group_size=5)

print("Setup阶段完成")
# 示例加密键
vertex_class_key1 = ('0', 'Group_732')
# vertex_class_key2 = ('Group_1', '1000')

# 设置网络延迟的λ值
# lambda_value = 10000  # λ值决定了延迟的平均值，数值越大网络延迟越小

# 初始化运行时间总和
total_query_time = 0
total_reveal_time = 0

# print("\n开始解密路径链：")
# 执行 1000 次
for _ in range(1000):
    # 记录查询开始时间
    Query_start_time1 = time.perf_counter()
    encrypted_key1 = token(key, vertex_class_key1)
    # print(f"Querying with encrypted_key: {encrypted_key1}")

    # 查询加密路径链
    encrypted_paths1 = query_encrypted_paths(encrypted_key1, gamma, token_dict_by_class, token_dict_by_pairs)

    # 记录查询结束时间
    Query_end_time1 = time.perf_counter()
    query_execution_time1 = (Query_end_time1 - Query_start_time1) * 1000  # 转换为毫秒

    # 根据查询时间选择合适的 lambda_value
    lambda_value = get_lambda_value(query_execution_time1)

    # 模拟网络延迟（符合指数分布）
    network_delay1 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒

    # 将网络延迟转换为毫秒并加到查询时间上
    total_execution_time1 = query_execution_time1 + (network_delay1 * 1000)  # 转换为毫秒

    total_query_time += total_execution_time1

    # 输出结果并执行解密操作
    if encrypted_paths1:


        # 记录解密开始时间
        Reveal_start_time1 = time.perf_counter()
        complete_paths1 = reveal(encrypted_paths1, node_pair_map)

        # 记录解密结束时间
        Reveal_end_time1 = time.perf_counter()
        Reveal_execution_time1 = (Reveal_end_time1 - Reveal_start_time1) * 1000  # 转换为毫秒
        total_reveal_time += Reveal_execution_time1

        # print(f"解密路径时间: {Reveal_execution_time1} 毫秒")
    else:
        print("\n未找到任何路径链。")



# 记录查询开始时间
# 初始化运行时间总和
# total_query_time2 = 0
# total_reveal_time2 = 0
#
# print("\n开始解密路径链：")
# # 执行 1000 次
# for _ in range(1000):
#     # 记录查询开始时间
#     Query_start_time2 = time.perf_counter()
#     encrypted_key2 = token(key, vertex_class_key2)
#     # print(f"\nQuerying with encrypted_key: {encrypted_key2}")
#
#     # 查询加密路径链
#     encrypted_paths2 = query_encrypted_paths(encrypted_key2, gamma, token_dict_by_class, token_dict_by_pairs)
#
#     # 记录查询结束时间
#     Query_end_time2 = time.perf_counter()
#     query_execution_time2 = (Query_end_time2 - Query_start_time2) * 1000  # 转换为毫秒
#
#     # 模拟网络延迟（符合指数分布）
#     network_delay2 = random.expovariate(lambda_value)  # 返回的是秒, 默认单位是秒
#
#     # 将网络延迟转换为毫秒并加到查询时间上
#     total_execution_time2 = query_execution_time2 + (network_delay2 * 1000)  # 转换为毫秒
#
#     total_query_time2 += query_execution_time2
#
#     # memory_usage2 = sys.getsizeof(encrypted_paths2)
#     # print(f"加密最短路径链占用内存: {memory_usage2} Bytes")
#
#     # 输出结果并执行解密操作
#     if encrypted_paths2:
#
#         # 记录解密开始时间
#         Reveal_start_time2 = time.perf_counter()
#         complete_paths2 = reveal(encrypted_paths2, node_pair_map)
#
#         # 记录解密结束时间
#         Reveal_end_time2 = time.perf_counter()
#         Reveal_execution_time2 = (Reveal_end_time2 - Reveal_start_time2) * 1000  # 转换为毫秒
#         total_reveal_time2 += Reveal_execution_time2
#
#         # print(f"解密路径时间: {Reveal_execution_time2} 毫秒")
#     else:
#         print("\n未找到任何路径链。")


# 计算平均时间
average_query_time = total_query_time / 1000
average_reveal_time = total_reveal_time / 1000

# # 计算平均时间
# average_query_time2 = total_query_time2 / 1000
# average_reveal_time2 = total_reveal_time2 / 1000


print(f"\n查询路径{vertex_class_key1}: ")
# 输出查询执行的时间
memory_usage1 = get_total_size(encrypted_paths1)
# 调用 print_decrypted_paths 函数输出解密后的路径
print_decrypted_paths(complete_paths1)
print(f"\n查询加密路径的平均时间: {average_query_time:.6f} 毫秒")
print(f"解密路径的平均时间: {average_reveal_time:.6f} 毫秒")
print(f"加密最短路径链占用内存: {memory_usage1} Bytes")

# 提取 vertex_class_key1 对应的顶点对
target_vertex, target_group = vertex_class_key1  # 解构获取顶点和目标组
group_number = int(target_group.split('_')[1]) - 1  # 提取组号，注意组号从 1 开始

# 提取目标组的顶点
if 0 <= group_number < len(groups):
    target_group_vertices = groups[group_number]  # 获取目标组的顶点列表
    vertex_pairs = [(target_vertex, str(vertex)) for vertex in target_group_vertices]
    print(f"顶点对: {vertex_pairs}")  # 输出最终的顶点对
else:
    print(f"组 {target_group} 不存在。")

# 计算加密字典所占用的内存大小
size_token_dict_by_class = get_total_size(token_dict_by_class)
size_token_dict_by_pairs = get_total_size(token_dict_by_pairs)
size_gamma = get_total_size(gamma)

# 计算总内存占用
total_memory_size = size_token_dict_by_class + size_token_dict_by_pairs + size_gamma

# 输出加密字典的内存大小，使用动态单位
print(f"\n加密字典 token_dict_by_class 所占内存大小: {format_size(size_token_dict_by_class)}")
print(f"加密字典 token_dict_by_pairs 所占内存大小: {format_size(size_token_dict_by_pairs)}")
print(f"加密字典 gamma 所占内存大小: {format_size(size_gamma)}")

# 输出总内存占用大小
print(f"\n所有加密字典总内存占用: {format_size(total_memory_size)}")

# print(f"\n查询路径{vertex_class_key2}: ")
# memory_usage2 = get_total_size(encrypted_paths2)
# # 调用 print_decrypted_paths 函数输出解密后的路径
# print_decrypted_paths(complete_paths2)
# print(f"\n查询加密路径的平均时间: {average_query_time2:.6f} 毫秒")
# print(f"解密路径的平均时间: {average_reveal_time2:.6f} 毫秒")
# print(f"加密最短路径链占用内存: {memory_usage2} Bytes")
