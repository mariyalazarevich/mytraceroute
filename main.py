import os
import socket
import struct
import time
import select
import sys

ICMP_ECHO_REQUEST = 8  # Тип ICMP для эхо-запроса
ICMP_TIME_EXCEEDED = 11  # Тип ICMP для Time Exceeded
MAX_HOPS = 30          # Максимальное количество узлов (TTL)
TIMEOUT = 2.0          # Таймаут ожидания ответа (в секундах)
PACKETS_PER_HOP = 3    # Количество пакетов на один шаг

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xFFFFFFFF

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer

def create_packet(pid):
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, pid, 1)
    data = struct.pack("d", time.time())
    checksum_value = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_value), pid, 1)
    return header + data

def traceroute(dest_name):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print(f"Не удалось разрешить адрес: {dest_name}")
        return

    print(f"Трассировка маршрута до {dest_name} [{dest_addr}]")
    print()

    pid = os.getpid() & 0xFFFF
    ttl = 1

    while ttl <= MAX_HOPS:
        print(f"{ttl:<3}", end="")
        for _ in range(PACKETS_PER_HOP):
            # Создание сырого сокета для отправки и получения ICMP
            try:
                recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_socket.settimeout(TIMEOUT)
            except PermissionError:
                print("Для выполнения программы требуются права суперпользователя (sudo).")
                sys.exit(1)

            packet = create_packet(pid)
            send_time = time.time()

            try:
                # Отправка ICMP пакета
                send_socket.sendto(packet, (dest_addr, 0))

                # Ожидание ответа
                ready = select.select([recv_socket], [], [], TIMEOUT)
                if not ready[0]:
                    print(" *  ", end="")
                    continue

                recv_packet, addr = recv_socket.recvfrom(512)
                icmp_header = recv_packet[20:28]
                icmp_type, icmp_code, _, recv_pid, _ = struct.unpack("bbHHh", icmp_header)

                if icmp_type == ICMP_TIME_EXCEEDED:
                    # Ответ "Time Exceeded" от промежуточного маршрутизатора
                    rtt = (time.time() - send_time) * 1000
                    print(f" {addr[0]} ({rtt:.2f} ms) ", end="")
                elif icmp_type == 0 and recv_pid == pid:
                    # Эхо-ответ (целевая точка достигнута)
                    rtt = (time.time() - send_time) * 1000
                    print(f" {addr[0]} ({rtt:.2f} ms) ", end="")
                    addr = (dest_addr,)
                    break
                else:
                    print(" *  ", end="")
            except socket.error as e:
                print(f"Ошибка сокета: {e}")
                break
            finally:
                send_socket.close()
                recv_socket.close()

        print()
        ttl += 1

        if addr and addr[0] == dest_addr:
            print("Трассировка завершена.")
            break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Использование: {sys.argv[0]} <IP-адрес или доменное имя>")
        sys.exit(1)

    target = sys.argv[1]
    traceroute(target)