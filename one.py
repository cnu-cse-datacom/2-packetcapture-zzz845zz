import socket
recv_socket=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
data = recv_socket.recvfrom(65535)
print(data)
