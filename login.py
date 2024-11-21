import sys
import requests
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# API-URL
LOGIN_URL = "https://apiddai-e6agacg9fxdhgxah.germanywestcentral-01.azurewebsites.net/login"


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Login")
        self.setFixedSize(400, 300)

        # Zentrales Widget erstellen
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout erstellen
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setAlignment(Qt.AlignCenter)
        self.layout.setSpacing(15)

        # Hintergrundfarbe setzen
        self.setStyleSheet("background-color: #00274d; color: #ffffff;")

        # Überschrift
        self.header_label = QLabel("DeepDetectAI Login")
        self.header_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.header_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.header_label)

        # Benutzername-Eingabe
        self.username_label = QLabel("Benutzername:")
        self.username_label.setFont(QFont("Arial", 12))
        self.layout.addWidget(self.username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Benutzername eingeben")
        self.username_input.setStyleSheet("padding: 5px; background-color: #ffffff; color: #000000;")
        self.layout.addWidget(self.username_input)

        # Passwort-Eingabe
        self.password_label = QLabel("Passwort:")
        self.password_label.setFont(QFont("Arial", 12))
        self.layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Passwort eingeben")
        self.password_input.setStyleSheet("padding: 5px; background-color: #ffffff; color: #000000;")
        self.layout.addWidget(self.password_input)

        # Login-Button
        self.login_button = QPushButton("Anmelden")
        self.login_button.setFont(QFont("Arial", 12, QFont.Bold))
        self.login_button.setStyleSheet("background-color: #00509e; color: #ffffff; padding: 8px;")
        self.login_button.clicked.connect(self.handle_login)
        self.layout.addWidget(self.login_button)

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Fehler", "Bitte Benutzername und Passwort eingeben.")
            return

        try:
            # Anfrage an die API senden
            response = requests.post(LOGIN_URL, json={"username": username, "password": password})
            if response.status_code == 200:
                data = response.json()
                user_id = data['user_id']
                tenant_id = data['tenant_id']

                QMessageBox.information(
                    self,
                    "Erfolg",
                    f"Login erfolgreich!\nBenutzer-ID: {user_id}\nTenant-ID: {tenant_id}"
                )
                self.close()
            elif response.status_code == 401:
                QMessageBox.critical(self, "Fehler", "Ungültige Anmeldedaten.")
            else:
                QMessageBox.critical(self, "Fehler", f"Unbekannter Fehler: {response.status_code}")
        except requests.RequestException as e:
            QMessageBox.critical(self, "Fehler", f"Netzwerkfehler: {e}")


def main():
    app = QApplication(sys.argv)

    # Dark Theme
    app.setStyleSheet(
        """
        QLabel { color: #ffffff; }
        QLineEdit { border-radius: 5px; padding: 5px; }
        QPushButton { border-radius: 5px; }
        """
    )

    window = LoginWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
