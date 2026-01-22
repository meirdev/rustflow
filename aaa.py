import socket

# Define configuration
UDP_IP = "0.0.0.0"  # Listen on all available network interfaces
UDP_PORT = 2055
BUFFER_SIZE = 4096  # Standard buffer size

# Create a UDP socket (SOCK_DGRAM)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening for UDP packets on port {UDP_PORT}...")

try:
    while True:
        # Receive data (blocking)
        # We assign to '_' to indicate the data is intentionally ignored
        _, addr = sock.recvfrom(BUFFER_SIZE)
        
        # Optional: Print sender address to confirm receipt without storing data
        # print(f"Received packet from {addr}")

except KeyboardInterrupt:
    print("\nStopping listener...")
finally:
    sock.close()
