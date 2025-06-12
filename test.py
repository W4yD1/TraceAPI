import netifaces as ni
import struct

def is_32bit_or_64bit_exe(file_path):
    try:
        with open(file_path, "rb") as file:
            # 读取文件头
            file.seek(0x3C)  # PE 文件头偏移位置
            pe_offset = struct.unpack("I", file.read(4))[0]  # 获取 PE 文件头偏移

            # 跳转到 PE 文件头
            file.seek(pe_offset)
            pe_signature = file.read(4)  # 读取 PE 签名
            if pe_signature != b"PE\x00\x00":
                raise ValueError("Invalid PE signature")

            # 读取可选头的魔数
            file.seek(pe_offset + 0x18)  # 可选头偏移
            optional_header_magic = struct.unpack("H", file.read(2))[0]

            if optional_header_magic == 0x10B:  # 32 位
                return "32-bit"
            elif optional_header_magic == 0x20B:  # 64 位
                return "64-bit"
            else:
                raise ValueError("Unknown PE format")
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_local_ip():
    # 获取所有网络接口
    interfaces = ni.interfaces()
    for interface in interfaces:
        # 跳过回环接口
        if interface == "lo":
            continue
        # 获取接口的 IP 地址信息
        addrs = ni.ifaddresses(interface)
        if ni.AF_INET in addrs:
            ip_info = addrs[ni.AF_INET][0]
            if "addr" in ip_info:
                return ip_info["addr"]
    return None
import ctypes
from ctypes import wintypes

# 加载 DLL 文件
dll_path = r"./ProcessInjectionDll.dll"
dll = ctypes.WinDLL(dll_path)

# 定义 InjectByPID 函数的参数类型和返回值类型
# InjectByPID 函数的签名是：BOOL InjectByPID(uint32_t dwPID)
InjectByPID = dll.InjectByPID
InjectByPID.argtypes = [wintypes.DWORD]  # 参数类型为 uint32_t
InjectByPID.restype = wintypes.BOOL      # 返回值类型为 BOOL

# 调用 InjectByPID 函数
def inject_dll(pid):
    result = InjectByPID(pid)
    if result:
        print(f"注入成功！PID: {pid}")
    else:
        print(f"注入失败！PID: {pid}")

# 示例：注入到目标进程
target_pid = 6116  # 替换为目标进程的 PID
inject_dll(target_pid)