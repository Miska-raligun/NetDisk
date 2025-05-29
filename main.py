import logging
from logging.handlers import RotatingFileHandler
from waitress import serve
from app import app as netdisk
import socket
from flask import request

def get_local_ip():
    """获取当前局域网 IP 地址"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# 添加请求日志功能
@netdisk.before_request
def log_request_info():
    logging.info(f"{request.remote_addr} - - {request.method} {request.path}")


from zeroconf import ServiceInfo, Zeroconf
import socket

# 添加 mDNS 广播服务
def register_mdns_service(ip: str, port: int = 443):
    desc = {}  # 你可以添加 {"path": "/"} 等信息

    info = ServiceInfo(
        type_="_https._tcp.local.",
        name="MioNetDisk._https._tcp.local.",
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties=desc,
        server="netdisk.local."
    )

    zeroconf = Zeroconf()
    zeroconf.register_service(info)
    return zeroconf


if __name__ == '__main__':
    # 日志格式（兼容中文）
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    file_handler = RotatingFileHandler('netdisk.log', maxBytes=1*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)

    # 避免 UnicodeEncodeError：强制设置 utf-8 控制台编码
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

    logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console_handler])

    local_ip = get_local_ip()
    logging.info(f"✅ netdisk start! address: http://{local_ip}:5000")

    # ✅ 注册 mDNS 服务
    try:
        mdns = register_mdns_service(local_ip, port=443)
        logging.info("✅ 已注册 Bonjour mDNS 服务为 https://netdisk.local")
    except Exception as e:
        logging.warning(f"⚠️ 注册 mDNS 失败: {e}")

    # ✅ 启动 Flask 网盘
    serve(netdisk, host='0.0.0.0', port=5000, threads=4)

    serve(netdisk, host='0.0.0.0', port=5000, threads=4)


