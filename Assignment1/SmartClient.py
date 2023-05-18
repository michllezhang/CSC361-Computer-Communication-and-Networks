import re
import ssl
import sys
import socket

PORT_1 = 80
PORT_2 = 443


def check_http2(host):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/2'])

    server = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=sys.argv[1])
    server.connect((host, PORT_2))

    if server.selected_alpn_protocol() != None:
        server.close()
        return True

    server.close()
    return False


def get_cookies_https(host):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = ssl.wrap_socket(server)
    server.connect((host, PORT_2))
    print("---Request begin---")
    print(f"GET http://{sys.argv[1]}/index.html HTTP/1.1")
    print(f"Host: {sys.argv[1]}")
    print("Connection: Keep-Alive\n")
    server.settimeout(2)
    server.send(f"GET / HTTP/1.1\r\nHOST:{sys.argv[1]}\r\n\r\n".encode())

    msg = server.recv(8192).decode(errors='ignore')

    print("---Request end---")
    print(" HTTP request sent, awaiting response...\n\n")
    print("---Response header ---")
    print(msg.split("<!DOCTYPE html>")[0])
    cookies = re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex
    print("---Response body ---")
    print(msg.split("<!DOCTYPE html>")[-1])

    code = int(msg.split()[1])
    if code >= 400:
        print("Error Code :", code, "https not supported")
        raise ConnectionError()

    try:
        while True:
            msg = server.recv(8192).decode(errors='ignore')
            if not msg:
                break
            print(msg)
            cookies = cookies + re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex
    except OSError:
        print("Request time out")

    server.close()
    return cookies


def get_cookies_http1(host):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, PORT_1))
    request = f"GET / HTTP/1.1\r\nHOST:{sys.argv[1]}\r\n\r\n"
    server.settimeout(2)
    server.sendall(request.encode())
    msg = server.recv(8192).decode(errors='ignore')

    cookies = re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex

    code = int(msg.split()[1])
    if code >= 400:
        print("Error Code :", code, "https not supported")
        raise ConnectionError()

    try:
        while True:
            msg = server.recv(8192).decode(errors='ignore')
            if not msg:
                break
            print(msg)
            cookies = cookies + re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex
    except OSError:
        print("Request time out")

    server.close()
    return cookies


def print_result(http2, cookies_https, cookies_http1):
    print("\nwebsite:", sys.argv[1], end="\n\n")
    if http2:
        print("1. Supports of http2: yes")
    else:
        print("1. Supports of http2: no")

    print("2. List of Cookies:")

    if cookies_https:
        for cookie in cookies_https:
            if re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie):
                print("cookie name:", re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie)[0][12:-1:], end="")
            if re.findall("[Ee]xpires=.*;", cookie):
                print(", expires time:", re.findall("[Ee]xpires=[\w\s,:-]*", cookie)[0][8::], end="")
            if re.findall("[Dd]omain=.*;", cookie):
                print(", domain name:", re.findall("[Dd]omain=[\w\.]*", cookie)[0][7::], end="")
            print()
    elif cookies_http1:
        for cookie in cookies_http1:
            if re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie):
                print("cookie name:", re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie)[0][12:-1:], end="")
            if re.findall("[Ee]xpires=.*;", cookie):
                print(", expires time:", re.findall("[Ee]xpires=[\w\s,:-]*", cookie)[0][8::], end="")
            if re.findall("[Dd]omain=.*;", cookie):
                print(", domain name:", re.findall("[Dd]omain=[\w\.]*", cookie)[0][7::], end="")
            print()

    if cookies_https:
        print("3. Password-protected: yes")
    else:
        print("3. Password-protected: no")


def main():
    try:
        host_name = socket.gethostbyname(sys.argv[1])
    except:
        print("Not available !!!\nPlease run program with proper host_name")
        exit()

    try:
        http2 = check_http2(host_name)
    except:
        http2 = False

    try:
        cookies_https = get_cookies_https(host_name)
    except:
        cookies_https = None

    try:
        cookies_http1 = get_cookies_http1(host_name)
    except:
        cookies_http1 = None

    print_result(http2, cookies_https, cookies_http1)


if __name__ == "__main__":
    main()
