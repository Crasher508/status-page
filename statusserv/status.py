import socket
import asyncio
import requests
from mcstatus import JavaServer, BedrockServer

def requestWeb(url: str) -> bool:
    try:
        response = requests.get(url, timeout=10)
        return response.status_code == 200
    except:
        return False

def requestBedrock(host: str, port: int) -> bool:
    try:
        server = BedrockServer.lookup(address=f"{host}:{port}", timeout=1)
        return server.status()
    except:
        return False
    
def requestJava(host: str, port: int) -> bool:
    try:
        server = asyncio.run(JavaServer.async_lookup(address=f"{host}:{port}", timeout=1))
        return server.status()
    except:
        return False

def requestPort(host: str, port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host,port))
        return True
    except:
        return False

def checkStatus(host: str, port: int, protocol: str) -> str:
    reachable = False

    if protocol == "https" or protocol == "http":
        reachable = requestWeb(url=host)
    elif protocol == "mcbe":
        reachable = requestBedrock(host=host, port=port)
    elif protocol == "mcje":
        reachable = requestJava(host=host, port=port)
    elif protocol == "reachable":
        reachable = requestPort(host=host, port=port)

    if reachable:
        return "Online"
    else:
        return "Offline"