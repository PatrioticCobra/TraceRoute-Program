import socket

HOST = "127.0.0.1"
PORT = 12345
address = (HOST, PORT)


try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(address)
    client_data = client_socket.recv(1024).decode().strip()
    print(client_data)
except Exception as e:
    print("There was an error:", e)
finally:
    if client_socket:
        client_socket.close()




