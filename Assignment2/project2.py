import sys
from struct import *


class global_Header:
    magic_num = None
    this_zone = None

    def __init__(self):
        magic_num = None
        this_zone = 0

    def set_magic_num(self, buffer):
        self.magic_num = buffer

    def set_this_zone(self, buffer):
        self.this_zone = unpack('BBBB', buffer)


class packet_header:
    ts_sec = None
    ts_usec = None
    incl_len = None

    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0

    def set_ts_sec(self, buffer):
        self.ts_sec = buffer[0] + buffer[1] * (2 ** 8) + buffer[2] * (2 ** 16) + buffer[3] * (2 ** 24)

    def get_ts_sec(self):
        return self.ts_sec

    def set_ts_usec(self, buffer):
        self.ts_usec = (buffer[0] + buffer[1] * (2 ** 8) + buffer[2] * (2 ** 16) + buffer[3] * (2 ** 24)) * (10 ** (-6))

    def get_ts_usec(self):
        return self.ts_usec

    def set_incl_len(self, buffer):
        incl_len = unpack('BBBB', buffer)
        self.incl_len = incl_len[3] * (2 ** 24) + incl_len[2] * (2 ** 16) + incl_len[1] * (2 ** 8) + incl_len[0]


class IP_header:
    src_ip = None
    dst_ip = None
    ip_header_len = None

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0

    def set_src_IP(self, buffer):
        self.src_ip = unpack('BBBB', buffer)

    def get_src_IP(self):
        return str(self.src_ip[0]) + "." + str(self.src_ip[1]) + "." + str(self.src_ip[2]) + "." + str(self.src_ip[3])

    def set_dst_IP(self, buffer):
        self.dst_ip = unpack('BBBB', buffer)

    def get_dst_IP(self):
        return str(self.dst_ip[0]) + "." + str(self.dst_ip[1]) + "." + str(self.dst_ip[2]) + "." + str(self.dst_ip[3])

    def set_ip_header_len(self, buffer):
        # ip_header_len = unpack('B', buffer)
        self.ip_header_len = (buffer % 16) * 4


class TCP_header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    tcp_header_len = 0
    flags = {}
    window_size = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.tcp_header_len = 0
        self.flags = {}
        self.window_size = 0

    def set_src_port(self, buffer):
        self.src_port = buffer

    def get_src_port(self):
        return self.src_port[0] * (2 ** 8) + self.src_port[1]

    def set_dst_port(self, buffer):
        self.dst_port = buffer

    def get_dst_port(self):
        return self.dst_port[0] * (2 ** 8) + self.dst_port[1]

    def set_seq_num(self, buffer):
        seq_num = unpack('BBBB', buffer)
        self.seq_num = seq_num[3] + seq_num[2] * (2 ** 8) + seq_num[1] * (2 ** 16) + seq_num[0] * (2 ** 24)
        # print(self.seq_num, buffer)

    def set_ack_num(self, buffer):
        ack_num = unpack('BBBB', buffer)
        self.ack_num = ack_num[3] + ack_num[2] * (2 ** 8) + ack_num[1] * (2 ** 16) + ack_num[0] * (2 ** 24)

    def set_tcp_header_len(self, buffer):
        self.tcp_header_len = buffer // 4

    def set_window_size(self, buffer):
        window_size = unpack('BB', buffer)
        self.window_size = window_size[1] + window_size[0] * (2 ** 8)

    def set_flags(self, buffer):
        # flags = unpack('B', buffer)
        fin = (buffer & 0b00000001)
        syn = (buffer & 0b00000010) >> 1
        rst = (buffer & 0b00000100) >> 2
        psh = (buffer & 0b00001000) >> 3
        ack = (buffer & 0b00010000) >> 4
        urg = (buffer & 0b00100000) >> 5
        ece = (buffer & 0b01000000) >> 6
        cwr = (buffer & 0b10000000) >> 7
        self.flags = (fin, syn, rst, psh, ack, urg, ece, cwr)

    def relative_seq_num(self, orig_seq_num):
        return self.seq_num - orig_seq_num

    def relative_ack_num(self, orig_ack_num):
        return self.ack_num - orig_ack_num


class packets:
    packet_header = None
    IP_header = None
    TCP_header = None
    packet_number = 0
    timestamp = 0
    payload = 0

    def __init__(self):
        self.packet_header = packet_header()
        self.IP_header = IP_header()
        self.TCP_header = TCP_header()
        self.packet_number = 0
        self.payload = 0
        self.timestamp = 0

    def get_timestamp(self):
        self.timestamp = self.packet_header.ts_sec + self.packet_header.ts_usec
        return self.timestamp

    def set_packet_number(self, packet_num):
        self.packet_number = packet_num

    def get_RTT(self, packet):
        return self.get_timestamp() - packet.get_timestamp()

    def set_payload_len(self, payload):
        self.payload = payload


class FileEndError(Exception):
    pass


def read_global_header(file):
    buffer = file.read(24)
    global_header = global_Header()
    global_header.set_magic_num(buffer[0:4])
    global_header.set_this_zone(buffer[8:12])


def read_packet(file, packet_number):
    buffer = file.read(16)
    packet = packets()
    packet.set_packet_number(packet_number)
    packet.packet_header.set_ts_sec(buffer[0:4])
    packet.packet_header.set_ts_usec(buffer[4:8])
    packet.packet_header.set_incl_len(buffer[8:12])

    file.read(14)

    buffer = file.read(20)
    packet.IP_header.set_ip_header_len(buffer[0])
    packet.IP_header.set_src_IP(buffer[12:16])
    packet.IP_header.set_dst_IP(buffer[16:20])
    if packet.IP_header.ip_header_len > 20:
        file.read(packet.IP_header.ip_header_len - 20)

    buffer = file.read(20)
    packet.TCP_header.set_src_port(buffer[0:2])
    packet.TCP_header.set_dst_port(buffer[2:4])
    packet.TCP_header.set_seq_num(buffer[4:8])
    packet.TCP_header.set_ack_num(buffer[8:12])
    packet.TCP_header.set_tcp_header_len(buffer[12])
    packet.TCP_header.set_flags(buffer[13])
    packet.TCP_header.set_window_size(buffer[14:16])
    if packet.TCP_header.tcp_header_len > 20:
        file.read(packet.TCP_header.tcp_header_len - 20)

    payload = packet.packet_header.incl_len - (14 + packet.IP_header.ip_header_len + packet.TCP_header.tcp_header_len)

    file.read(payload)
    packet.set_payload_len(payload)

    return packet


def packet_distribution_into_connection(packets):
    connections = []
    for packet in packets:
        if packet.TCP_header.flags[1] == 1 and packet.TCP_header.flags[4] == 0:
            new_conn = True
            for conn in connections:
                if (conn[0].TCP_header.src_port == packet.TCP_header.src_port
                        and conn[0].TCP_header.dst_port == packet.TCP_header.dst_port
                        and conn[0].IP_header.src_ip == packet.IP_header.src_ip
                        and conn[0].IP_header.dst_ip == packet.IP_header.dst_ip):
                    conn.append(packet)
                    new_conn = False
            if new_conn:
                new_connection = [packet]
                connections.append(new_connection)
        else:
            for conn in connections:
                if (conn[0].TCP_header.src_port == packet.TCP_header.dst_port
                        and conn[0].TCP_header.dst_port == packet.TCP_header.src_port
                        and conn[0].IP_header.src_ip == packet.IP_header.dst_ip
                        and conn[0].IP_header.dst_ip == packet.IP_header.src_ip):
                    conn.append(packet)
                elif (conn[0].TCP_header.src_port == packet.TCP_header.src_port
                      and conn[0].TCP_header.dst_port == packet.TCP_header.dst_port
                      and conn[0].IP_header.src_ip == packet.IP_header.src_ip
                      and conn[0].IP_header.dst_ip == packet.IP_header.dst_ip):
                    conn.append(packet)
    return connections


def print_IP_ports(conn, connection):
    print("Connection : {}".format(conn))
    print("Source Address : {}".format(connection[0].IP_header.get_src_IP()))
    print("Destination Address : {}".format(connection[0].IP_header.get_dst_IP()))
    print("Source Port : {}".format(connection[0].TCP_header.get_src_port()))
    print("Destination Port : {}".format(connection[0].TCP_header.get_dst_port()))


def print_general_statistics(complete_conn, reset_conn, connections):
    print("\nC) General Statistics : ")
    print("Total number of complete TCP connections : {}".format(len(complete_conn)))
    print("Number of reset TCP connections : {}".format(reset_conn))
    print("Number of TCP connections that were still open when the trace capture ended : {}".format(
        len(connections) - len(complete_conn)))


def print_complete_TCP_connections(complete_conn, connections, durations):
    # Three lists below for analysis of part D)
    window_size = []
    rtt_value = []
    packet_count = []

    print("\nD) Completete TCP connections : \n")
    print("Minimum time duration : {0:.6f} seconds".format(min(durations)))
    print("Mean time duration : {0:.6f} seconds".format(sum(durations) / len(durations)))
    print("Maximum time duration : {0:.6f} seconds\n".format(max(durations)))

    for i in complete_conn:
        for p in connections[i]:
            client_IP = connections[i][0].IP_header.get_src_IP()
            orig_seq_num = connections[i][0].TCP_header.seq_num
            orig_ack_num = connections[i][1].TCP_header.seq_num
            rtt_start_seq_num = p.TCP_header.relative_seq_num(orig_seq_num)

            if p.payload == 0 and p.TCP_header.flags[1] == 1:
                expected_ack_num = rtt_start_seq_num + 1
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(
                            orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break
            elif p.payload != 0:
                expected_ack_num = rtt_start_seq_num + p.payload
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(
                            orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break
            elif p.payload == 0 and p.TCP_header.flags[0] == 1:
                expected_ack_num = rtt_start_seq_num + 1
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(
                            orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break

            window_size.append(p.TCP_header.window_size)

        packet_count.append(len(connections[i]))

    print("Minimum RTT value : {0:.6f} seconds".format(min(rtt_value)))
    print("Mean RTT value : {0:.6f} seconds".format(sum(rtt_value) / len(rtt_value)))
    print("Maximum RTT value : {0:.6f} seconds\n".format(max(rtt_value)))

    print("Minimum number of packets including both send/received : {}".format(min(packet_count)))
    print("Mean number of packets including both send/received : {}".format(sum(packet_count) / len(packet_count)))
    print("Maximum number of packets including both send/received : {}\n".format(max(packet_count)))

    print("Minimum receive window size including both send/received : {} bytes".format(min(window_size)))
    print("Mean receive window size including both send/received : {0:.6f} bytes".format(
        sum(window_size) / len(window_size)))
    print("Maxinum receive window size including both send/received : {} bytes".format(max(window_size)))


def connection_analysis(connections):
    conn = 0
    reset_conn = 0
    complete_conn = []
    packet_count = []
    durations = []
    standard_time = connections[0][0].get_timestamp()

    print("A) Total number of connections : {}\n".format(len(connections)))
    print("-" * 60, end="\n\n")

    print("B) Connections' details :\n")
    for connection in connections:
        syn = 0
        fin = 0
        rst = 0
        fin_packet = 0
        data_bytes_to_client = 0
        data_bytes_to_server = 0
        packet_count_to_client = 0
        packet_count_to_server = 0

        conn += 1

        print_IP_ports(conn, connection)
        for p in connection:
            if p.TCP_header.flags[0] == 1:
                fin_packet = packet_count_to_client + packet_count_to_server
                fin += 1
            if p.TCP_header.flags[1] == 1:
                syn += 1
            if p.TCP_header.flags[2] == 1:
                rst += 1
            if p.IP_header.get_src_IP() == connection[0].IP_header.get_src_IP():
                packet_count_to_server += 1
                data_bytes_to_server += p.payload
            elif p.IP_header.get_dst_IP() == connection[0].IP_header.get_src_IP():
                packet_count_to_client += 1
                data_bytes_to_client += p.payload

        if rst == 0:
            print("Status : S{}F{}".format(syn, fin))
        else:
            reset_conn += 1
            print("Status : S{}F{}\R".format(syn, fin))
        if syn > 0 and fin > 0:
            complete_conn.append(conn - 1)
            start_time = connection[0].get_timestamp() - standard_time
            end_time = connection[fin_packet].get_timestamp() - standard_time
            print("Start Time : {0:.6f} seconds".format(start_time))
            print("End Time : {0:.6f} seconds".format(end_time))
            print("Duration : {0:.6f} seconds".format(end_time - start_time))
            print("Number of Packets sent from Source to Destination : {}".format(packet_count_to_server))
            print("Number of Packets sent from Destination to Source : {}".format(packet_count_to_client))
            print("Total number of packets : {}".format(packet_count_to_client + packet_count_to_server))
            print("Number of data bytes sent from Source to Destination : {}".format(data_bytes_to_server))
            print("Number of data bytes sent from Destination to Source : {}".format(data_bytes_to_client))
            print("Total number of data bytes : {}".format(data_bytes_to_client + data_bytes_to_server))
            packet_count.append(packet_count_to_client + packet_count_to_server)
            durations.append(end_time - start_time)
        print("END\n", "-" * 60, sep="")
    print_general_statistics(complete_conn, reset_conn, connections)
    print_complete_TCP_connections(complete_conn, connections, durations)


def main():
    packets = []
    packet_number = 1
    argc = len(sys.argv)

    if argc < 2 or argc > 2:
        print("please provide right file name")
        exit()
    file_name = sys.argv[1]

    with open(file_name, "rb") as file:
        read_global_header(file)
        while True:
            try:
                packets.append(read_packet(file, packet_number))
                packet_number += 1
            except:
                break
    connections = packet_distribution_into_connection(packets)
    connection_analysis(connections)


if __name__ == "__main__":
    main()
