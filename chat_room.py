import sys
import socket
import threading
import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QTextEdit,
    QLineEdit,
    QPushButton,
    QLabel,
    QHBoxLayout,
    QListWidget,
    QInputDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QTextCursor, QIcon


class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.server_socket = None
        self.client_socket = None
        self.contacts_file = "contacts.json"
        self.contacts = {}
        self.messages = {}
        self.current_contact = None
        self.stop_threads = False
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.port = 12345
        self.packet_info = None
        self.init_ui()
        self.load_contacts()
        self.start_server()

    def init_ui(self):
        self.setWindowTitle("MI_Chatroom")
        self.setWindowIcon(QIcon("whatsapp_icon.png"))
        self.setGeometry(100, 100, 900, 600)
        self.setStyleSheet("background-color: #f0f0f0; font-family: Arial;")

        main_layout = QHBoxLayout()

        # Contacts panel
        self.contacts_list = QListWidget(self)
        self.contacts_list.itemClicked.connect(self.select_contact)
        self.contacts_list.setStyleSheet(
            "QListWidget {background-color: #ffffff; border: 1px solid #ccc; padding: 5px;} "
            "QListWidget::item {padding: 10px; margin: 5px; border-radius: 5px;} "
            "QListWidget::item:hover {background-color: #d3d3d3;} "
            "QListWidget::item:selected {background-color: #4CAF50; color: white;}"
        )

        self.add_contact_button = QPushButton("Add New Contact", self)
        self.add_contact_button.clicked.connect(self.add_contact)
        self.add_contact_button.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;"
        )

        self.change_ip_button = QPushButton("Change Contact IP", self)
        self.change_ip_button.clicked.connect(self.change_contact_ip)
        self.change_ip_button.setStyleSheet(
            "background-color: #FFA500; color: white; font-weight: bold;"
        )

        contacts_layout = QVBoxLayout()
        contacts_label = QLabel("Contacts")
        contacts_label.setFont(QFont("Arial", 12, QFont.Bold))
        contacts_layout.addWidget(contacts_label)
        contacts_layout.addWidget(self.contacts_list)
        contacts_layout.addWidget(self.add_contact_button)
        contacts_layout.addWidget(self.change_ip_button)

        # Chat panel
        self.chat_display = QTextEdit(self)
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet(
            "background-color: #ffffff; border: 1px solid #ccc; padding: 10px;"
        )
        self.chat_display.setFont(QFont("Arial", 10))

        self.selected_contact_label = QLabel("Select a contact to start chatting")
        self.selected_contact_label.setAlignment(Qt.AlignCenter)
        self.selected_contact_label.setStyleSheet(
            "background-color: #2196F3; color: white; font-size: 14px; padding: 10px; font-weight: bold;"
        )

        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText("Type your message...")
        self.message_input.setStyleSheet(
            "background-color: #ffffff; border: 1px solid #ccc; padding: 5px;"
        )
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)
        self.send_button.setStyleSheet(
            "background-color: #2196F3; color: white; font-weight: bold; width: 80px;"
        )

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        chat_layout = QVBoxLayout()
        chat_layout.addWidget(self.selected_contact_label)
        chat_layout.addWidget(self.chat_display)
        chat_layout.addLayout(input_layout)

        main_layout.addLayout(contacts_layout, 1)
        main_layout.addLayout(chat_layout, 3)

        self.setLayout(main_layout)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.local_ip, self.port))
        self.server_socket.listen(5)

        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while not self.stop_threads:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                ).start()
            except Exception as e:
                print(f"Server Error: {e}")
                break

    def handle_client(self, conn, addr):
        while not self.stop_threads:
            try:
                # message = conn.recv(1024).decode("utf-8")
                message = conn.recv(1024)
                if message:
                    self.receive_message(message, addr)
            except Exception as e:
                print(f"Client Error: {e}")
                break

    def load_contacts(self):
        try:
            with open(self.contacts_file, "r") as file:
                data = json.load(file)
                self.contacts = data.get("contacts", {})
                self.messages = data.get("messages", {})
                self.update_contacts_list()
        except FileNotFoundError:
            self.contacts = {}
            self.messages = {}

    def save_contacts(self):
        data = {"contacts": self.contacts, "messages": self.messages}
        with open(self.contacts_file, "w") as file:
            json.dump(data, file, indent=4)

    def update_contacts_list(self):
        self.contacts_list.clear()
        for name, ip in self.contacts.items():
            unread_count = self.get_unread_count(name)
            display_text = f"{name} ({unread_count})" if unread_count > 0 else name
            self.contacts_list.addItem(display_text)

    def get_unread_count(self, contact_name):
        if contact_name in self.messages:
            return sum(1 for msg in self.messages[contact_name] if msg[-1] == "Unread")
        return 0

    def mark_messages_as_read(self, contact_name):
        if contact_name in self.messages:
            for i, (msg, timestamp, sender, status) in enumerate(self.messages[contact_name]):
                if status == "Unread":
                    self.messages[contact_name][i] = (msg, timestamp, sender, "Read")
            self.save_contacts()

    def add_contact(self):
        name, ok = QInputDialog.getText(self, "Add Contact", "Enter friend's name:")
        if ok and name:
            ip, ok = QInputDialog.getText(self, "Add Contact", "Enter friend's IP:")
            if ok and ip:
                self.contacts[name] = ip
                self.messages[name] = []
                self.update_contacts_list()
                self.save_contacts()

    def change_contact_ip(self):
        name, ok = QInputDialog.getItem(self, "Change Contact IP", "Select contact:", list(self.contacts.keys()), editable=False)
        if ok and name:
            new_ip, ok = QInputDialog.getText(self, "Change IP", f"Enter new IP for {name}:")
            if ok and new_ip:
                self.contacts[name] = new_ip
                self.save_contacts()
                self.update_contacts_list()

    def select_contact(self, item):
        name = item.text().split(" (")[0]
        self.current_contact = name
        self.chat_display.clear()

        if name in self.messages:
            self.mark_messages_as_read(name)
            for msg, timestamp, sender, _ in self.messages[name]:
                alignment = Qt.AlignRight if sender == "You" else Qt.AlignLeft
                self.add_message_to_display(f"{msg}\n[{timestamp}]", alignment)

        self.selected_contact_label.setText(f"Chat with {name}")
        self.send_button.setEnabled(True)
        self.update_contacts_list()

    def add_message_to_display(self, message, alignment):
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)

        block_format = cursor.blockFormat()
        block_format.setAlignment(alignment)
        cursor.setBlockFormat(block_format)

        cursor.insertText(message + "\n\n")

    def send_message(self):
        if not self.current_contact:
            self.chat_display.append("Please select a contact to send a message.")
            return

        message = self.message_input.text().strip()
        if message:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.add_message_to_display(f"{message}\n[{timestamp}]", Qt.AlignRight)

            if self.current_contact in self.contacts:
                ip = self.contacts[self.current_contact]
                threading.Thread(
                    target=self.send_to_socket,
                    args=(ip, self.port, message),
                    daemon=True,
                ).start()

            self.messages[self.current_contact].append((message, timestamp, "You", "Read"))
            self.save_contacts()
            self.message_input.clear()

    def xor_encrypt_decrypt(self,data):
        key = b"mysecretkey"
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def send_to_socket(self, ip, port, message):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            encrypted_message = self.xor_encrypt_decrypt(message.encode("utf-8"))
            sock.sendall(encrypted_message)

            local_ip, local_port = sock.getsockname()
            remote_ip, remote_port = sock.getpeername()

            # Original packet information using socket attributes
            self.packet_info = {
                "Source IP": local_ip,
                "Source Port": local_port,
                "Destination IP": remote_ip,
                "Destination Port": remote_port,
                "Content": encrypted_message,
            }

            print("Packet Info:", self.packet_info)
            sock.close()
        except Exception as e:
            print(f"Error sending message to {ip}: {e}")

    def receive_message(self, message, addr):
        timestamp = datetime.now().strftime("%H:%M:%S")
        sender_ip = addr[0]

        # Find the contact name associated with the sender's IP
        contact_name = None
        for name, ip in self.contacts.items():
            if ip == sender_ip:
                contact_name = name
                break

        if contact_name:
            # Display packet attributes
            packet_info = {
                "Source IP": sender_ip,
                "Source Port": addr[1],
                "Destination IP": self.local_ip,
                "Destination Port": self.port,
                "Content": message,
            }
            print("Packet Info:", packet_info)
            message = self.xor_encrypt_decrypt(message)
            message = message.decode('utf-8')
            self.messages[contact_name].append((message, timestamp, "Them", "Unread"))
            self.save_contacts()

            if self.current_contact == contact_name:
                self.add_message_to_display(f"{message}\n[{timestamp}]", Qt.AlignLeft)

        self.update_contacts_list()

    def closeEvent(self, event):
        self.stop_threads = True
        if self.server_socket:
            self.server_socket.close()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    chat_client = ChatClient()
    chat_client.show()
    sys.exit(app.exec_())
