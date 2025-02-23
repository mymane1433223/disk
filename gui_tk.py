import tkinter as tk
from tkinter import filedialog
import socket
import hashlib
import threading


def calculate_md5(bytecode):
    md5_hash = hashlib.md5()
    md5_hash.update(bytecode)
    return md5_hash.hexdigest()


def send_with_length(sock, data):
    length = len(data).to_bytes(4, byteorder='big')
    sock.send(length)
    sock.send(data)


def receive_with_length(sock):
    length_bytes = sock.recv(4)
    length = int.from_bytes(length_bytes, byteorder='big')
    data = b''
    while len(data) < length:
        remaining = length - len(data)
        data += sock.recv(min(4096, remaining))
    return data


def upload_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    try:
        days = float(days_entry.get())
    except ValueError:
        status_label.config(text="请输入有效的天数！")
        return

    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
        file_name = file_path.split('/')[-1]
        file_size = len(file_content)
        md5 = calculate_md5(file_content)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('47.94.245.67', 17862))

        send_with_length(s, str(days).encode('utf-8'))
        send_with_length(s, file_name.encode('utf-8'))
        send_with_length(s, str(file_size).encode('utf-8'))
        send_with_length(s, file_content)
        send_with_length(s, md5.encode('utf-8'))

        while True:
            response = receive_with_length(s).decode('utf-8')
            if response == 'sb':
                md5 = calculate_md5(file_content)
                send_with_length(s, file_content)
                send_with_length(s, md5.encode('utf-8'))
            elif response == 'nb':
                status_label.config(text="文件上传成功！")
                s.close()
                break
    except Exception as e:
        status_label.config(text=f"文件上传出错: {str(e)}")


def download_file():
    file_name = file_name_entry.get()
    if not file_name:
        status_label.config(text="请输入文件名！")
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('47.94.245.67', 17863))

        send_with_length(s, file_name.encode('utf-8'))

        while True:
            file_size_bytes = receive_with_length(s)
            file_size = int.from_bytes(file_size_bytes, byteorder='big')
            file_content = receive_with_length(s)
            received_md5_bytes = receive_with_length(s)
            received_md5 = received_md5_bytes.decode('utf-8')
            local_md5 = calculate_md5(file_content)

            if local_md5 == received_md5:
                save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                         filetypes=[("All files", "*.*")])
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(file_content)
                    status_label.config(text="文件下载成功！")
                    send_with_length(s, "nb".encode('utf-8'))
                s.close()
                break
            else:
                send_with_length(s, "retry".encode('utf-8'))
    except Exception as e:
        status_label.config(text=f"文件下载出错: {str(e)}")


root = tk.Tk()
root.title("文件上传与下载")

# 上传部分
upload_frame = tk.Frame(root)
upload_frame.pack(pady=10)

tk.Label(upload_frame, text="选择文件上传，设置保存天数:").pack()
days_entry = tk.Entry(upload_frame)
days_entry.pack()
upload_button = tk.Button(upload_frame, text="上传文件", command=lambda: threading.Thread(target=upload_file).start())
upload_button.pack()

# 下载部分
download_frame = tk.Frame(root)
download_frame.pack(pady=10)

tk.Label(download_frame, text="输入文件名下载:").pack()
file_name_entry = tk.Entry(download_frame)
file_name_entry.pack()
download_button = tk.Button(download_frame, text="下载文件", command=lambda: threading.Thread(target=download_file).start())
download_button.pack()

# 状态显示
status_label = tk.Label(root, text="")
status_label.pack(pady=10)

root.mainloop()