import subprocess
import os
import sys
import netifaces as ni
import time
import struct
import shutil
import argparse
import ctypes
from ctypes import wintypes


# 定义颜色代码
class Colors:
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"  # 重置颜色


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
    return "192.168.1.20"
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


def is_wsb_running():
    stdout = subprocess.check_output(["wsb", "list"], text=True)
    if stdout == "\n":
        return 0
    return 1


def start_wsb():
    stdout = subprocess.check_output(["wsb", "start"], text=True)
    if "Windows Sandbox environment started successfully:" in stdout:
        print("Starting Sanbox Successfully")
        sanbox_id = stdout.split("\n")[1].split(" ")[1].strip()
        print("Sanbox id is : ", sanbox_id)
        return sanbox_id
    return 0


def get_wsb_id():
    stdout = subprocess.check_output(["wsb", "list"], text=True)
    return stdout


def exit_running_sanbox():
    sanbox_id = get_wsb_id()
    stdout = subprocess.check_output(["wsb", "stop", "--id", sanbox_id], text=True)


def exec_wsb_command(command: str, wsb_id: str, dir: str, timeout: int = None):
    print(
        f"\033[34mwsb\033[0m",
        f"\033[34mexec\033[0m",
        f"\033[34m--id\033[0m",
        f"\033[34m{wsb_id}\033[0m",
        f"\033[34m-c\033[0m",
        f"\033[34m{command}\033[0m",
        f"\033[34m-r\033[0m",
        f"\033[34mSystem\033[0m",
        f"\033[34m-d\033[0m",
        f"\033[34m{dir}\033[0m",
    )
    try:
        stdout = subprocess.check_output(
            [
                "wsb",
                "exec",
                "--id",
                wsb_id,
                "-c",
                command,
                "-r",
                "System",
                "-d",
                dir,
            ],
            text=True,
            timeout=timeout,
        )
    except:
        print("timeout")
        pass


def exec_wsb_command_ex(command: str, wsb_id: str, dir: str):
    print(
        f"\033[34mwsb\033[0m",
        f"\033[34mexec\033[0m",
        f"\033[34m--id\033[0m",
        f"\033[34m{wsb_id}\033[0m",
        f"\033[34m-c\033[0m",
        f"\033[34m{command}\033[0m",
        f"\033[34m-r\033[0m",
        f"\033[34mSystem\033[0m",
        f"\033[34m-d\033[0m",
        f"\033[34m{dir}\033[0m",
    )
    stdout = subprocess.Popen(
        [
            "wsb",
            "exec",
            "--id",
            wsb_id,
            "-c",
            command,
            "-r",
            "System",
            "-d",
            dir,
        ],
        text=True,
    )


def file_mode(file_path: str, timeout: int):

    # check if file exist
    if not os.path.exists(file_path):
        print(f"错误: 文件 {file_path} 不存在。")
        sys.exit(1)

    # check if input file is a exe
    if not file_path.lower().endswith(".exe"):
        print(f"错误: {file_path} 不是一个有效的 .exe 文件。")
        sys.exit(1)

    file_abs_path = os.path.abspath(file_path)
    file_basename = os.path.basename(file_abs_path)

    # copy exe to Resource
    shutil.copy(file_abs_path, "./Resource")

    if is_wsb_running():
        exit_running_sanbox()
    sanbox_id = start_wsb()
    if sanbox_id == 0:
        print(f"{Colors.RED}Start Sanbox Failed{Colors.RESET}")
        if os.path.exists("./Resource/" + file_basename):
            os.remove("./Resource/" + file_basename)
        exit(0)

    # Starting http server
    process = subprocess.Popen(["python", "server.py"])

    # Transmit file
    host_ip = get_local_ip()
    print(f"{Colors.GREEN}从主机获取资源文件：{Colors.RESET}")
    for file in os.listdir("Resource"):
        exec_wsb_command(
            f'''powershell -c "wget http://{host_ip}:8048/download/{file} -OutFile 'C:\\sanbox\\{file}' -UseBasicParsing"''',
            sanbox_id,
            "C:\\sanbox",
        )

    # copy missing dll
    print(f"{Colors.GREEN}补充沙箱缺失的动态链接库：{Colors.RESET}")
    exec_wsb_command(
        '''powershell -c "cp C:\\sanbox\\msvcp140.dll C:\\Windows\\System32"''',
        sanbox_id,
        "C:\\sanbox",
    )
    exec_wsb_command(
        '''powershell -c "cp C:\\sanbox\\vcruntime140.dll C:\\Windows\\System32"''',
        sanbox_id,
        "C:\\sanbox",
    )
    exec_wsb_command(
        '''powershell -c "cp C:\\sanbox\\vcruntime140_1.dll C:\\Windows\\System32"''',
        sanbox_id,
        "C:\\sanbox",
    )

    # Patch exe
    # print(f"{Colors.GREEN}将trcapi.dll注入到待测文件：{Colors.RESET}")
    # if is_32bit_or_64bit_exe(file_abs_path) == "64-bit":
    #     exec_wsb_command(
    #         f'''powershell -c ".\\setdll.exe /d:trcapi64.dll .\\{file_basename}"''', sanbox_id, "C:\\sanbox"
    #     )
    # elif is_32bit_or_64bit_exe(file_abs_path) == "32-bit":
    #     exec_wsb_command(
    #         f'''powershell -c ".\\setdll.exe /d:trcapi32.dll .\\{file_basename}"''', sanbox_id, "C:\\sanbox"
    #     )
    # else:
    #     print(f"{Colors.RED}Get file arch Failed{Colors.RESET}")
    #     if os.path.exists("./Resource/" + file_basename):
    #         os.remove("./Resource/" + file_basename)
    #     exit(0)

    # Start logging pipe
    print(f"{Colors.GREEN}启动日志管道：{Colors.RESET}")
    exec_wsb_command_ex(
        '''powershell -c ".\\syelogd.exe -o res.txt"''', sanbox_id, "C:\\sanbox"
    )
    time.sleep(1)

    # Start tracing
    print(f"{Colors.GREEN}运行程序：{Colors.RESET}")
    if is_32bit_or_64bit_exe(file_abs_path) == "64-bit":
        exec_wsb_command(
            f'''powershell -c ".\\withdll.exe /d:trcapi64.dll .\\{file_basename}"''',
            sanbox_id,
            "C:\\sanbox",
            timeout,
        )
    elif is_32bit_or_64bit_exe(file_abs_path) == "32-bit":
        exec_wsb_command(
            f'''powershell -c ".\\withdll.exe /d:trcapi64.dll .\\{file_basename}"''',
            sanbox_id,
            "C:\\sanbox",
            timeout,
        )
    else:
        print(f"{Colors.RED}Get file arch Failed{Colors.RESET}")
        if os.path.exists("./Resource/" + file_basename):
            os.remove("./Resource/" + file_basename)
        exit(0)
    # exec_wsb_command(f'''powershell -c ".\\{file_basename}"''', sanbox_id, "C:\\sanbox")
    # exec_wsb_command(f'''powershell -c ".\\withdll.exe /d:trcapi32.dll .\\{file_basename}"''', sanbox_id, "C:\\sanbox")

    # Send result back
    print(f"{Colors.GREEN}将结果传回主机：{Colors.RESET}")
    exec_wsb_command(
        f'''powershell -c "Get-Content -Path 'res.txt' -Raw | Out-String | Set-Variable -Name 'DATA' ; Invoke-WebRequest -Uri 'http://{host_ip}:8048/upload' -Method POST -Body $DATA -ContentType 'text/plain' -UseBasicParsing"''',
        sanbox_id,
        "C:\\sanbox",
        10,
    )

    process.terminate()
    process.wait()

    if os.path.exists("./Resource/" + file_basename):
        os.remove("./Resource/" + file_basename)

    exit_running_sanbox()


def pid_mode(pid: int, timeout: int):
    # 加载 DLL 文件
    dll_path = r"./ProcessInjectionDll.dll"
    dll = ctypes.WinDLL(dll_path)

    # 定义 InjectByPID 函数的参数类型和返回值类型
    # InjectByPID 函数的签名是：BOOL InjectByPID(uint32_t dwPID)
    InjectByPID = dll.InjectByPID
    InjectByPID.argtypes = [wintypes.DWORD]  # 参数类型为 uint32_t
    InjectByPID.restype = wintypes.BOOL  # 返回值类型为 BOOL

    result = InjectByPID(pid)
    if result:
        print(f"注入成功！PID: {pid}")
    else:
        print(f"注入失败！PID: {pid}")

    try:
        stdout = subprocess.check_output(
            ["./Resource/syelogd.exe", "/o", "pid_mode_res"],
            text=True,
            timeout=timeout,
        )
    except:
        print("timeout")
        pass


def process_name_mode(name: str, timeout: int):
    # 加载 DLL 文件
    dll_path = r"./ProcessInjectionDll.dll"
    dll = ctypes.WinDLL(dll_path)

    # 定义 processNameToPid 函数的参数类型和返回值类型
    # processNameToPid 函数的签名是：DWORD processNameToPid(const std::wstring& processName)
    processNameToPid = dll.processNameToPid
    processNameToPid.argtypes = [ctypes.c_wchar_p]  # 参数类型为 const std::wstring&
    processNameToPid.restype = wintypes.DWORD  # 返回值类型为 DWORD

    # 定义 InjectByPID 函数的参数类型和返回值类型
    # InjectByPID 函数的签名是：BOOL InjectByPID(uint32_t dwPID)
    InjectByPID = dll.InjectByPID
    InjectByPID.argtypes = [wintypes.DWORD]  # 参数类型为 uint32_t
    InjectByPID.restype = wintypes.BOOL  # 返回值类型为 BOOL

    print(name)

    # 调用 processNameToPid 函数
    pid = processNameToPid(name)
    if pid == 0:
        print(f"未找到进程：{name}")
    else:
        print(f"找到进程：{name}，PID: {pid}")
        result = InjectByPID(pid)
        if result:
            print(f"注入成功！PID: {pid}")
        else:
            print(f"注入失败！PID: {pid}")

    try:
        stdout = subprocess.check_output(
            ["./Resource/syelogd.exe", "/o", "process_name_mode_res"],
            text=True,
            timeout=timeout,
        )
    except:
        print("timeout")
        pass


def main():
    parser = argparse.ArgumentParser(
        description="API Tracer，支持文件模式、PID模式和进程名模式，文件模式会将测试文件放入Windows沙箱并监控执行，PID模式指定当前主机内某个程序的PID并监控执行，进程名模式指定当前主机内某个程序的进程名并监控执行"
    )

    # 创建子命令解析器
    subparsers = parser.add_subparsers(dest="mode", help="选择模式")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="指定监控时间。")

    # 文件模式
    file_parser = subparsers.add_parser("file", help="文件模式")
    file_parser.add_argument("file_path", type=str, help="文件路径")

    # PID模式
    pid_parser = subparsers.add_parser("pid", help="PID模式")
    pid_parser.add_argument("pid", type=int, help="进程ID")

    # 进程名模式
    process_name_parser = subparsers.add_parser("name", help="进程名模式")
    process_name_parser.add_argument("name", type=str, help="进程名")

    args = parser.parse_args()

    timeout = args.timeout

    # 根据模式执行逻辑
    if args.mode == "file":
        file_path = args.file_path
        file_mode(file_path, timeout)
    elif args.mode == "pid":
        pid = args.pid
        pid_mode(pid, timeout)
    elif args.mode == "name":
        name = args.name
        process_name_mode(name, timeout)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
