# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct


class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.next_send_seq = 0
        self.next_recv_seq = 0
        self.recv_buffer = {}

    def send(self, data_bytes: bytes) -> None:
        header_size = 4
        max_payload = 1472 - header_size
        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i + max_payload]
            header = struct.pack("!I", self.next_send_seq)
            self.next_send_seq += 1
            packet = header + chunk
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        while True:
            data, addr = self.socket.recvfrom()
            seq_num = struct.unpack("!I", data[:4])[0]
            payload = data[4:]
            if seq_num not in self.recv_buffer:
                self.recv_buffer[seq_num] = payload
            assembled = b""
            while self.next_recv_seq in self.recv_buffer:
                assembled += self.recv_buffer.pop(self.next_recv_seq)
                self.next_recv_seq += 1
            if assembled:
                return assembled

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        pass
