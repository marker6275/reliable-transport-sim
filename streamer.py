# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

import struct
import time
from concurrent.futures import ThreadPoolExecutor

class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Sequence numbers for data
        self.next_send_seq = 0       # next sequence number for sending
        self.next_recv_seq = 0       # next sequence number expected for receiving

        self.receive_buffer = {}     # store out-of-order data
        self.closed = False

        # Flags and state for stop-and-wait
        self.ack_received = False    # indicates we've received ACK for the *current* packet
        self.last_ack_seq = -1       # which sequence number was last ACKed?

        # FIN handshake states
        self.fin_sent = False
        self.fin_acked = False
        self.received_peer_fin = False

        # Start background listener thread
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

    def listener(self):
        """Continuously receive packets (data, ACK, FIN, FIN_ACK)."""
        while not self.closed:
            try:
                data, addr = self.socket.recvfrom()
                if not data:
                    continue  # could be a spurious wakeup
                
                if len(data) < 5:
                    # We need at least 1 byte for packet_type + 4 for sequence
                    continue

                packet_type = data[0]  # first byte
                seq_num = struct.unpack("!I", data[1:5])[0]
                payload = data[5:]

                if packet_type == 0:
                    # DATA packet
                    # store or buffer the chunk
                    self.receive_buffer[seq_num] = payload
                    # send ACK
                    self.send_ack(seq_num, addr)

                elif packet_type == 1:
                    # ACK packet
                    # Mark ack_received if it matches the chunk we're waiting on
                    self.ack_received = True
                    self.last_ack_seq = seq_num

                elif packet_type == 2:
                    # FIN
                    self.received_peer_fin = True
                    # Respond with FIN_ACK
                    self.send_fin_ack(seq_num, addr)

                elif packet_type == 3:
                    # FIN_ACK
                    self.fin_acked = True

            except Exception as e:
                if not self.closed:
                    print("Listener died with error:", e)

    def send_ack(self, seq_num: int, addr):
        """Send an ACK (packet_type=1) for the given seq_num."""
        packet_type = 1  # ACK
        header = struct.pack("!B", packet_type) + struct.pack("!I", seq_num)
        self.socket.sendto(header, addr)

    def send_fin(self, seq_num: int, addr):
        """Send a FIN (packet_type=2) with the given seq_num."""
        # In a simple design, the seq_num might just be self.next_send_seq or a special code
        packet_type = 2
        header = struct.pack("!B", packet_type) + struct.pack("!I", seq_num)
        self.socket.sendto(header, addr)

    def send_fin_ack(self, seq_num: int, addr):
        """Send a FIN_ACK (packet_type=3) with the given seq_num."""
        packet_type = 3
        header = struct.pack("!B", packet_type) + struct.pack("!I", seq_num)
        self.socket.sendto(header, addr)

    def send(self, data_bytes: bytes) -> None:
        """
        Stop-and-wait: for each chunk, keep sending until ack is received or we time out (0.25s).
        Then move to next chunk.
        """
        header_size = 5  # 1 byte type + 4 bytes seq_num
        max_payload = 1472 - header_size

        offset = 0
        while offset < len(data_bytes):
            chunk = data_bytes[offset : offset + max_payload]
            offset += max_payload

            # Build data packet (type=0 => data)
            packet_type = 0
            seq = self.next_send_seq
            self.next_send_seq += 1

            header = struct.pack("!B", packet_type) + struct.pack("!I", seq)
            packet = header + chunk

            # Repeatedly send until we get an ACK or kill signal
            acked = False
            while not acked and not self.closed:
                self.ack_received = False
                self.socket.sendto(packet, (self.dst_ip, self.dst_port))

                # Wait up to 0.25s for an ACK
                start_wait = time.time()
                while time.time() - start_wait < 0.25 and not self.closed:
                    if self.ack_received and self.last_ack_seq == seq:
                        acked = True
                        break
                    time.sleep(0.01)

                # If we never got the correct ack_received => loop and resend
            if self.closed:
                break

    def recv(self) -> bytes:
        """
        Return the next in-order data (next_recv_seq).
        Blocks until the next segment arrives, then any contiguous segments after it.
        """
        assembled = b""
        while True:
            # Deliver all contiguous data starting at next_recv_seq
            while self.next_recv_seq in self.receive_buffer:
                assembled += self.receive_buffer.pop(self.next_recv_seq)
                self.next_recv_seq += 1

            # If we have something, return it now
            if assembled:
                return assembled

            # Otherwise, wait briefly for the next chunk
            time.sleep(0.01)
            if self.closed:
                # If the socket is closed and we have nothing new, return empty
                return b""

    def close(self) -> None:
        """
        1) Because stop-and-wait ensures data was fully ACKed, we don't re-check data.
        2) Send FIN repeatedly until FIN_ACK arrives (0.25s timeout).
        3) Wait until we receive a FIN from the other side.
        4) Wait 2 seconds.
        5) Stop the listener (self.closed=True) and self.socket.stoprecv().
        """
        # Step 2: Send FIN repeatedly until FIN_ACK arrives
        self.fin_sent = True
        fin_seq = 99999999  # any special number, or self.next_send_seq
        while not self.fin_acked:
            self.send_fin(fin_seq, (self.dst_ip, self.dst_port))
            start_wait = time.time()
            while time.time() - start_wait < 0.25:
                if self.fin_acked:
                    break
                time.sleep(0.01)

        # Step 3: Wait for peer's FIN
        while not self.received_peer_fin:
            time.sleep(0.01)

        # Step 4: Wait 2 seconds
        time.sleep(2)

        # Step 5: Stop listener
        self.closed = True
        self.socket.stoprecv()
        print("Streamer closed cleanly.")
