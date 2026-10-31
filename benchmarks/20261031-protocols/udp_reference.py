import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9090))
while True:
    b,a=s.recvfrom(65535);s.sendto(b,a)
