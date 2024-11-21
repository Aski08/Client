import psutil
import time
import json
from ping3 import ping
import requests
import logging
from ipaddress import ip_address, ip_network

# Logging konfigurieren
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Konfigurationsdetails laden
CONFIG_PATH = "config.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

TEAMS_IP_RANGES = config["teams_ip_ranges"]
TEAMS_PORTS = set(config["teams_ports"])
INTERVAL = config["interval"]
CHECK_INTERVAL = config["check_interval"]

class Client:
    def __init__(self, user_data):
        self.base_api_url = config["base_api_url"]
        self.api_token = user_data["token"]
        self.tenant_id = user_data["tenant_id"]
        self.user_id = user_data["user_id"]

    def ensure_valid_token(self):
        """
        Stellt sicher, dass ein gültiger Token verfügbar ist. (Optional: Implementieren)
        """
        pass  # Optional: Token erneuern, falls benötigt

    def send_to_api(self, endpoint, data):
        """
        Sendet Daten an einen spezifischen API-Endpunkt.
        """
        url = f"{self.base_api_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "X-Tenant-ID": self.tenant_id,
            "X-User-ID": self.user_id
        }

        try:
            response = requests.post(url, headers=headers, data=json.dumps(data))
            response.raise_for_status()
            logging.info(f"Daten erfolgreich an {endpoint} gesendet: {data}")
        except requests.RequestException as e:
            logging.error(f"Fehler beim Senden der Daten an {endpoint}: {e}")

    def ip_in_range(self, ip, ip_ranges):
        """
        Prüft, ob eine IP-Adresse in einem der angegebenen IP-Bereiche liegt.
        """
        for ip_range in ip_ranges:
            if ip_address(ip) in ip_network(ip_range):
                return True
        return False

    def is_teams_meeting_active(self):
        """
        Prüft, ob ein Teams-Meeting aktiv ist.
        """
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.raddr and conn.raddr.port in TEAMS_PORTS:
                    if self.ip_in_range(conn.raddr.ip, TEAMS_IP_RANGES):
                        logging.info(f"Teams-Meeting erkannt: {conn.raddr.ip}:{conn.raddr.port}")
                        return True
            except Exception:
                continue
        return False

    def measure_latency(self, target_host):
        """
        Misst die Latenzzeit (Round Trip Time) in Millisekunden.
        """
        latency = ping(target_host, timeout=1)
        return latency * 1000 if latency else None

    def measure_bandwidth(self):
        """
        Misst die Bandbreite (Upload/Download-Bytes pro Sekunde).
        """
        net1 = psutil.net_io_counters()
        time.sleep(1)
        net2 = psutil.net_io_counters()

        upload_speed = (net2.bytes_sent - net1.bytes_sent) / 1
        download_speed = (net2.bytes_recv - net1.bytes_recv) / 1

        return {
            "upload_speed_kbps": upload_speed / 1024,
            "download_speed_kbps": download_speed / 1024,
        }

    def measure_packet_loss(self, target_host, ping_count=5):
        """
        Misst Paketverluste durch mehrfache Ping-Anfragen.
        """
        successful_pings = sum(ping(target_host, timeout=1) is not None for _ in range(ping_count))
        packet_loss = ((ping_count - successful_pings) / ping_count) * 100
        return packet_loss

    def collect_metrics(self):
        """
        Hauptprogramm für das Sammeln und Senden von Netzwerkmetriken.
        """
        while True:
            try:
                logging.info("Netzwerkmetriken werden gesammelt...")

                latency = self.measure_latency("teams.microsoft.com")
                latency_data = {
                    "tenant_id": self.tenant_id,
                    "user_id": self.user_id,
                    "timestamp": time.time(),
                    "latency_ms": latency
                }
                self.send_to_api("latency_monitoring", latency_data)

                bandwidth = self.measure_bandwidth()
                bandwidth_data = {
                    "tenant_id": self.tenant_id,
                    "user_id": self.user_id,
                    "timestamp": time.time(),
                    "upload_speed_kbps": bandwidth["upload_speed_kbps"],
                    "download_speed_kbps": bandwidth["download_speed_kbps"]
                }
                self.send_to_api("bitrate_monitoring", bandwidth_data)

                packet_loss = self.measure_packet_loss("teams.microsoft.com")
                anomaly_data = {
                    "tenant_id": self.tenant_id,
                    "user_id": self.user_id,
                    "timestamp": time.time(),
                    "packet_loss_percentage": packet_loss
                }
                self.send_to_api("anomaly_detection", anomaly_data)

                time.sleep(INTERVAL)
            except KeyboardInterrupt:
                logging.info("Skript beendet.")
                break
            except Exception as e:
                logging.error(f"Fehler: {e}")

    def run(self):
        """
        Startet das Hauptprogramm.
        """
        while True:
            if self.is_teams_meeting_active():
                logging.info("Teams-Meeting erkannt. Starte Metrikensammlung...")
                self.collect_metrics()
            else:
                logging.info("Kein aktives Teams-Meeting erkannt.")
            time.sleep(CHECK_INTERVAL)
