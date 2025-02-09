# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

import hashlib
import struct
import time
from concurrent.futures import ThreadPoolExecutor

###################################################
# Helper function to compute MD5
###################################################
def compute_md5(data: bytes) -> bytes:
    """Return the 16-byte MD5 digest of 'data'."""
    md5 = hashlib.md5()
    md5.update(data)
    return md5.digest()

###################################################
# Constants for your packet format
###################################################
HEADER_SIZE_WITHOUT_MD5 = 1 + 4  # 1 byte packet_type + 4 bytes seq_num
MD5_SIZE = 16  # We store 16-byte MD5 at the front
MAX_UDP_PAYLOAD = 1472

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

    ###################################################
    # Packet Builder / Parser with MD5
    ###################################################
    def build_packet(self, packet_type: int, seq_num: int, payload: bytes) -> bytes:
        """
        Build the final packet:
          [16-byte MD5][1-byte packet_type][4-byte seq_num][payload]
        The MD5 covers everything *after* its own field (i.e., it covers the packet_type, seq_num, payload).
        """
        # Build the portion that the MD5 covers
        # We'll do: (1-byte type) + (4-byte seq) + payload
        header_without_md5 = struct.pack("!B", packet_type) + struct.pack("!I", seq_num)
        data_for_md5 = header_without_md5 + payload

        # Compute MD5 of that
        md5_hash = compute_md5(data_for_md5)

        # Final packet = MD5(16 bytes) + data_for_md5
        final_packet = md5_hash + data_for_md5
        return final_packet

    def parse_packet(self, data: bytes):
        """
        Parse the packet:
          data[0:16]   => MD5
          data[16:17] => packet_type
          data[17:21] => seq_num
          data[21:]   => payload
        Returns: (is_valid, packet_type, seq_num, payload)
        If invalid MD5, return (False, None, None, None)
        """
        if len(data) < MD5_SIZE + HEADER_SIZE_WITHOUT_MD5:
            # Too short to even read MD5 + type + seq
            return (False, None, None, None)

        md5_received = data[:MD5_SIZE]
        rest = data[MD5_SIZE:]  # the part we hashed

        # Recompute MD5 of 'rest'
        md5_computed = compute_md5(rest)
        if md5_computed != md5_received:
            # Corrupted!
            return (False, None, None, None)

        # If valid, parse out packet_type + seq_num
        packet_type = rest[0]
        seq_num = struct.unpack("!I", rest[1:5])[0]
        payload = rest[5:]
        return (True, packet_type, seq_num, payload)

    ###################################################
    # Listener with corruption check
    ###################################################
    def listener(self):
        """Continuously receive packets (data, ACK, FIN, FIN_ACK) with MD5 checks."""
        while not self.closed:
            try:
                data, addr = self.socket.recvfrom()
                if not data:
                    continue  # spurious?

                # parse and validate MD5
                is_valid, packet_type, seq_num, payload = self.parse_packet(data)
                if not is_valid:
                    # Corrupted => discard, do *not* ACK
                    continue

                # Now proceed with normal logic
                if packet_type == 0:
                    # DATA packet
                    self.receive_buffer[seq_num] = payload
                    # send ACK
                    ack_packet = self.build_packet(1, seq_num, b'')
                    self.socket.sendto(ack_packet, addr)

                elif packet_type == 1:
                    # ACK packet
                    self.ack_received = True
                    self.last_ack_seq = seq_num

                elif packet_type == 2:
                    # FIN
                    self.received_peer_fin = True
                    # respond with FIN_ACK
                    fin_ack_packet = self.build_packet(3, seq_num, b'')
                    self.socket.sendto(fin_ack_packet, addr)

                elif packet_type == 3:
                    # FIN_ACK
                    self.fin_acked = True

            except Exception as e:
                if not self.closed:
                    print("Listener died with error:", e)

    ###################################################
    # Sending (Stop-and-wait with corruption check)
    ###################################################
    def send(self, data_bytes: bytes) -> None:
        """
        Stop-and-wait: for each chunk, keep sending until ack is received or we time out (0.25s).
        Then move to next chunk.
        Now each packet includes an MD5.
        """
        # 16-byte MD5 + 1-byte type + 4-byte seq => 16 + 1 + 4 = 21
        # so max payload = 1472 - 21 = 1451
        header_size = MD5_SIZE + HEADER_SIZE_WITHOUT_MD5
        max_payload = MAX_UDP_PAYLOAD - header_size

        offset = 0
        while offset < len(data_bytes):
            chunk = data_bytes[offset : offset + max_payload]
            offset += max_payload

            seq = self.next_send_seq
            self.next_send_seq += 1

            # Build data packet (type=0 => data)
            packet = self.build_packet(0, seq, chunk)

            # Repeatedly send until we get an ACK or kill signal
            acked = False
            while not acked and not self.closed:
                self.ack_received = False
                self.last_ack_seq = -1
                self.socket.sendto(packet, (self.dst_ip, self.dst_port))

                # Wait up to 0.25s for an ACK
                start_wait = time.time()
                while time.time() - start_wait < 0.25 and not self.closed:
                    if self.ack_received and self.last_ack_seq == seq:
                        acked = True
                        break
                    time.sleep(0.01)

                # If we never got the correct ack => loop and resend

            if self.closed:
                break

    ###################################################
    # Receiving
    ###################################################
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

    ###################################################
    # Close / Teardown with FIN handshake
    ###################################################
    def close(self) -> None:
        """
        1) Because stop-and-wait ensures data was fully ACKed, we don't re-check data.
        2) Send FIN repeatedly until FIN_ACK arrives (0.25s timeout).
        3) Wait until we receive a FIN from the other side.
        4) Wait 2 seconds.
        5) Stop the listener (self.closed=True) and self.socket.stoprecv().
        """
        # Step 2: Send FIN repeatedly until FIN_ACK arrives
        fin_seq = 99999999  # any special number, or self.next_send_seq
        while not self.fin_acked:
            fin_packet = self.build_packet(2, fin_seq, b'')
            self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
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
