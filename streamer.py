from lossy_socket import LossyUDP
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import time
import hashlib
import threading


class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.next_send_seq = 0
        self.next_rec_seq = 0
        self.base_seq = 0

        self.rec_buffer = {}
        self.send_buffer = {}

        self.FIN = False
        self.FIN_SEQ = None
        self.FIN_ACK = False

        self.closed = False

        self.lock = threading.Lock()

        self.executor = ThreadPoolExecutor(max_workers=2)
        self.executor.submit(self.listener)
        self.executor.submit(self.retransmit)

    def listener(self):
        while not self.closed:
            try:
                data, addr = self.socket.recvfrom()
                if not data or len(data) < 21:
                    continue
                
                packet_type = struct.unpack("!B", data[:1])[0]
                seq_num = struct.unpack("!I", data[1:5])[0]
                received_hash = data[5:21]
                payload = data[21:]
                computed_hash = hashlib.md5(data[:5] + payload).digest()

                if received_hash != computed_hash:
                    continue

                if packet_type == 0: # data
                    if seq_num not in self.rec_buffer:
                        self.rec_buffer[seq_num] = payload
                    header = struct.pack("!BI", 1, seq_num)
                    ack = header + hashlib.md5(header).digest()

                    self.socket.sendto(ack, addr)
                elif packet_type == 1: # ACK
                    with self.lock:
                        if self.FIN_SEQ is not None and seq_num == self.FIN_SEQ:
                            self.FIN_ACK = True
                        if seq_num >= self.base_seq:
                            remove_keys = [key for key in self.send_buffer if key <= seq_num]
                            for key in remove_keys:
                                del self.send_buffer[key]
                            if seq_num >= self.base_seq:
                                self.base_seq = seq_num + 1
                elif packet_type == 2: # FIN
                    header = struct.pack("!BI", 1, seq_num)
                    ack = header + hashlib.md5(header).digest()

                    self.socket.sendto(ack, addr)
                    self.FIN = True

            except Exception as e:
                print(e)

    def retransmit(self):
        while not self.closed:
            time.sleep(0.01)
            with self.lock:
                if self.send_buffer:
                    earliest_seq = min(self.send_buffer.keys())
                    _, last_time = self.send_buffer[earliest_seq]
                    
                    if time.time() - last_time >= 0.25:
                        for seq in sorted(self.send_buffer.keys()):
                            packet, _ = self.send_buffer[seq]
                            self.send_buffer[seq] = (packet, time.time())
                            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        max_payload = 1451

        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i + max_payload]
            with self.lock:
                seq_num = self.next_send_seq
                header = struct.pack("!BI", 0, seq_num)
                packet = header + hashlib.md5(header + chunk).digest() + chunk

                self.send_buffer[seq_num] = (packet, time.time())
                self.next_send_seq += 1
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

        while True:
            with self.lock:
                if not self.send_buffer:
                    break
            time.sleep(0.01)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        assembled = b""
        while True:
            if self.next_rec_seq in self.rec_buffer:
                while self.next_rec_seq in self.rec_buffer:
                    assembled += self.rec_buffer.pop(self.next_rec_seq)
                    self.next_rec_seq += 1
                return assembled
            time.sleep(0.01)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        while True:
            with self.lock:
                if not self.send_buffer:
                    break
            time.sleep(0.01)

        with self.lock:
            self.FIN_SEQ = self.next_send_seq
            self.next_send_seq += 1
            self.FIN_ACK = False

        header = struct.pack("!BI", 2, self.FIN_SEQ)
        fin = header + hashlib.md5(header).digest()

        while not self.FIN_ACK:
            self.socket.sendto(fin, (self.dst_ip, self.dst_port))
            start_time = time.time()

            while time.time() - start_time < 0.25:
                time.sleep(0.01)
                with self.lock:
                    if self.FIN_ACK:
                        break

        while not self.FIN:
            time.sleep(0.01)

        # sleep 2 sec because we have to?
        time.sleep(2)

        # then close
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)