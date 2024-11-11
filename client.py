import os
import logging
import requests
import time
from scapy.all import sniff
from scapy.layers.inet import IP, UDP, TCP
from scapy.arch import get_if_list
from statistics import mean, stdev
import threading
from threading import Lock
import socket
import sys
from datetime import datetime
from collections import deque
import numpy as np
import jwt  # Stellen Sie sicher, dass PyJWT installiert ist
from jwt import ExpiredSignatureError, InvalidTokenError
from tenacity import retry, stop_after_attempt, wait_exponential
from dotenv import load_dotenv
from urllib.parse import urljoin

# Laden der Umgebungsvariablen aus der .env-Datei
load_dotenv()

# Zugriff auf die Umgebungsvariablen
LOGIN_USERNAME = os.getenv('LOGIN_USERNAME')
LOGIN_PASSWORD = os.getenv('LOGIN_PASSWORD')
SECRET_KEY = os.getenv('SECRET_KEY')  # Falls benötigt
API_BASE_URL = os.getenv('API_BASE_URL')

# Überprüfen der notwendigen Umgebungsvariablen
if not LOGIN_USERNAME or not LOGIN_PASSWORD:
    print("LOGIN_USERNAME und/oder LOGIN_PASSWORD sind nicht gesetzt.")
    sys.exit(1)

if not API_BASE_URL:
    print("API_BASE_URL ist nicht gesetzt.")
    sys.exit(1)

# Logging Setup
logging.basicConfig(
    level=logging.INFO,  # Temporär DEBUG-Level setzen für mehr Details
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('teams_monitoring.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('teams_monitoring')

# Debugging-Logs hinzufügen
logger.info(f"API_BASE_URL: {API_BASE_URL}")
logger.info(f"Username: {LOGIN_USERNAME}")
logger.info(f"Password: {LOGIN_PASSWORD}")

# Erweiterte Konfiguration
MONITORING_CONFIG = {
    'hosts': [
        'teams.microsoft.com',
        'teams.live.com',
        'teams.office.com'
    ],
    'ports': {
        'tcp': [443, 80, 4443, 5061, 50000, 50001, 50002, 50003],  # Erweiterte TCP-Ports
        'udp': [3478, 3479, 3480, 3481, 50000, 50001, 50002, 50003]
    },
    'intervals': {
        'latency': 5,      # Sekunden zwischen Latenz-Messungen
        'bitrate': 10,     # Sekunden für Bitraten-Messung
        'baseline': 30,    # Sekunden zwischen Baseline-Updates
        'stats': 30        # Sekunden zwischen Statistik-Updates
    },
    'baseline': {
        'window_size': 50,           # Größe des Beobachtungsfensters
        'min_samples': 10,           # Mindestanzahl für Baseline-Berechnung
        'anomaly_threshold': 0.5,    # Schwellwert für Anomalie-Erkennung
        'update_interval': 30,       # Intervall für Baseline-Updates
        'weights': {
            'mean_deviation': 0.4,
            'std_deviation': 0.3,
            'iqr_violation': 0.3
        }
    },
    'meeting_types': {
        'video': {
            'min_bitrate': 2.0,      # Mbps
            'min_packet_size': 1000   # Bytes
        },
        'audio': {
            'max_bitrate': 0.5,      # Mbps
            'max_packet_size': 500    # Bytes
        },
        'screenshare': {
            'min_bitrate': 1.5       # Mbps
        }
    },
    'deepfake_detection': {
        'analysis': {
            'window_size': 5,           # Sekunden für Echtzeit-Analyse
            'min_packets': 50,          # Mindestanzahl Pakete für Analyse
            'correlation_threshold': 0.7 # Schwellwert für Korrelationsanalyse
        },
        'timing_patterns': {
            'latency_variation': 0.2,   # Max. erlaubte Latenz-Variation
            'burst_interval': 0.1,      # Typisches Burst-Interval in Sekunden
            'timing_regularity': 0.8    # Mindest-Regularität der Pakete
        },
        'metrics': {
            'bitrate_stability': 0.85,  # Erwartete Bitrate-Stabilität
            'compression_ratio': 0.7,   # Typisches Kompressionsverhältnis
            'packet_rhythm': 0.9        # Erwartete Paketrhythmus-Regularität
        }
    }
}

# API-Endpoints basierend auf API_BASE_URL aus der .env-Datei
API_CONFIG = {
    'endpoints': {
        'login': '/login',
        'latency': '/latency_monitoring',
        'bitrate': '/bitrate_monitoring',
        'anomaly': '/anomaly_detection',
        'deepfake': '/deepfake_detection'
    }
}

# Globale Variablen
token = None

def is_token_expired(token):
    """Überprüft, ob das JWT-Token abgelaufen ist"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get('exp')
        if exp:
            return datetime.utcfromtimestamp(exp) < datetime.utcnow()
    except Exception as e:
        logger.error(f"Fehler beim Überprüfen des Tokens: {e}")
    return True

def get_token():
    """Authentifizierungs-Token vom API-Server abrufen"""
    try:
        endpoint = API_CONFIG['endpoints']['login']
        full_url = urljoin(API_BASE_URL + '/', endpoint.lstrip('/'))
        logger.debug(f"Sending POST request to URL: {full_url}")
        response = requests.post(
            full_url,
            json={"username": LOGIN_USERNAME, "password": LOGIN_PASSWORD},
            timeout=5,
            verify=False  # Temporär für lokale Tests deaktiviert
        )
        logger.debug(f"Response Status Code: {response.status_code}")
        response.raise_for_status()
        token_data = response.json()
        token = token_data.get("token")
        if not token:
            logger.error("Kein Token im Antwortkörper gefunden.")
            return None
        logger.info("Token erfolgreich abgerufen.")
        return token
    except requests.exceptions.RequestException as e:
        logger.error(f"Fehler beim Token-Abruf: {e}")
        return None

def get_token_with_refresh():
    """Gibt das aktuelle Token zurück oder erneuert es, falls es abgelaufen ist"""
    global token
    if not token or is_token_expired(token):
        logger.info("Token ist abgelaufen oder nicht vorhanden. Erneuere Token.")
        token = get_token()
    return token

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def send_post_request(endpoint, payload):
    """Sendet POST-Anfragen mit Wiederholungsmechanismus"""
    try:
        current_token = get_token_with_refresh()
        if not current_token:
            logger.error("Kein gültiges Token vorhanden.")
            return None

        # Bestimmen, ob SSL-Verifizierung erforderlich ist
        verify_ssl = API_BASE_URL.startswith('https://')

        # Korrekte URL-Konstruktion mit urljoin
        full_url = urljoin(API_BASE_URL + '/', endpoint.lstrip('/'))
        logger.debug(f"Sending POST request to URL: {full_url}")

        response = requests.post(
            full_url,
            headers={"Authorization": f"Bearer {current_token}"},
            json=payload,
            timeout=5,
            verify=verify_ssl  # SSL-Verifizierung basierend auf dem Schema
        )

        logger.debug(f"Response Status Code: {response.status_code}")
        if response.status_code == 401:
            logger.warning("Token abgelaufen oder ungültig. Erneuere Token.")
            token = get_token_with_refresh()
            response = requests.post(
                full_url,
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
                timeout=5,
                verify=verify_ssl
            )

        response.raise_for_status()
        logger.info(f"Erfolgreich Daten an {endpoint} gesendet.")
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error beim Senden an {endpoint}: {e}")
        if 'response' in locals():
            logger.error(f"Antwortinhalt: {response.text}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Fehler beim Senden von Daten an {endpoint}: {e}")
        raise

class PacketBuffer:
    """Speichert und verwaltet Netzwerkpakete mit Metadaten"""
    def __init__(self):
        self.packets = deque(maxlen=5000)  # Maximale Anzahl von Paketen im Puffer
        self.lock = Lock()
        self.metadata = {
            'last_analysis': time.time(),
            'packet_count': 0,
            'total_bytes': 0
        }
        self.logger = logging.getLogger('teams_monitoring.buffer')

    def add_packet(self, packet):
        try:
            timestamp = getattr(packet, 'sniff_time', None)
            if timestamp is None:
                timestamp = packet.time  # Fallback zu packet.time
            else:
                timestamp = timestamp.timestamp()  # datetime zu Timestamp konvertieren
            packet_data = {
                'raw_packet': packet,
                'timestamp': timestamp,
                'size': len(packet),
                'protocol': 'UDP' if UDP in packet else 'TCP' if TCP in packet else 'unknown'
            }

            with self.lock:
                self.packets.append(packet_data)
                self.metadata['packet_count'] += 1
                self.metadata['total_bytes'] += packet_data['size']
                self.logger.debug(f"Paket zum Buffer hinzugefügt. Aktuelle Größe: {len(self.packets)}")
                self.logger.debug(f"Paket-Timestamp: {packet_data['timestamp']:.6f}")
        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen des Pakets: {e}", exc_info=True)

    def get_packets(self, clear=True):
        """Gibt alle Pakete zurück und leert optional den Puffer"""
        with self.lock:
            packets = list(self.packets)
            if clear:
                self.packets.clear()
                self.metadata['packet_count'] = 0
                self.metadata['total_bytes'] = 0
            return packets

    def get_duration(self):
        if not self.packets:
            return 0.0
        try:
            with self.lock:
                first_timestamp = self.packets[0]['timestamp']
                last_timestamp = self.packets[-1]['timestamp']
                duration = last_timestamp - first_timestamp
                self.logger.debug(f"Erstes Paket-Timestamp: {first_timestamp:.6f}")
                self.logger.debug(f"Letztes Paket-Timestamp: {last_timestamp:.6f}")
                self.logger.debug(f"Berechnete Dauer: {duration:.6f}")
                if duration <= 0:
                    duration = time.time() - first_timestamp
                    self.logger.debug(f"Angepasste Dauer (aktueller Zeitpunkt): {duration:.6f}")
                return duration
        except Exception as e:
            self.logger.error(f"Fehler bei Dauerberechnung: {e}", exc_info=True)
            return 0.0

    def get_statistics(self):
        with self.lock:
            duration = self.get_duration()
            self.logger.debug(f"Berechnete Dauer: {duration:.6f}")
            if duration <= 0:
                self.logger.debug("Dauer <= 0, Statistiken können nicht berechnet werden")
                return None

            packet_count = self.metadata['packet_count']
            total_bytes = self.metadata['total_bytes']
            self.logger.debug(f"Anzahl Pakete: {packet_count}")
            self.logger.debug(f"Gesamtbytes: {total_bytes}")

            if packet_count == 0:
                self.logger.debug("Anzahl Pakete ist 0, Statistiken können nicht berechnet werden")
                return None

            # Convert duration to seconds with higher precision
            bitrate = (total_bytes * 8) / duration / 1e6  # Mbps
            avg_packet_size = total_bytes / packet_count

            self.logger.debug(f"Berechnete Bitrate: {bitrate:.6f} Mbps")
            self.logger.debug(f"Durchschnittliche Paketgröße: {avg_packet_size:.2f} Bytes")

            return {
                'packet_count': packet_count,
                'total_bytes': total_bytes,
                'duration': duration,
                'bitrate': bitrate,
                'avg_packet_size': avg_packet_size
            }

class NetworkBaseline:
    def __init__(self, config=None):
        self.config = config or MONITORING_CONFIG['baseline']
        self.latency_history = deque(maxlen=self.config['window_size'])
        self.bitrate_history = deque(maxlen=self.config['window_size'])
        self.packet_size_history = deque(maxlen=self.config['window_size'])
        self.baseline_lock = Lock()
        self.baselines = {
            'video': {},
            'audio': {},
            'screenshare': {}
        }
        self.logger = logging.getLogger('teams_monitoring.baseline')

    def calculate_adaptive_baseline(self, data_points):
        try:
            if not data_points or len(data_points) < self.config['min_samples']:
                self.logger.debug(f"Zu wenig Datenpunkte für Baseline: {len(data_points) if data_points else 0}")
                return None

            data_array = np.array(data_points)
            if not np.all(np.isfinite(data_array)):
                self.logger.warning("Ungültige Werte in Datenpunkten gefunden")
                data_array = data_array[np.isfinite(data_array)]

            if len(data_array) < self.config['min_samples']:
                return None

            q1 = np.percentile(data_array, 25)
            q3 = np.percentile(data_array, 75)
            iqr = q3 - q1

            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            filtered_data = data_array[(data_array >= lower_bound) & (data_array <= upper_bound)]

            if len(filtered_data) == 0:
                self.logger.warning("Keine Datenpunkte nach Ausreißer-Filterung")
                return None

            return {
                'mean': float(np.mean(filtered_data)),
                'std': float(np.std(filtered_data)) if len(filtered_data) > 1 else 0,
                'median': float(np.median(filtered_data)),
                'q1': float(q1),
                'q3': float(q3),
                'iqr': float(iqr),
                'sample_count': len(filtered_data)
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Baseline-Berechnung: {str(e)}")
            return None

    def update_baseline(self, network_data):
        try:
            if not all(key in network_data for key in ['bitrate', 'avg_packet_size']):
                self.logger.error(f"Unvollständige Netzwerkdaten: {network_data}")
                return

            meeting_type = self.detect_meeting_type(network_data)

            with self.baseline_lock:
                self.bitrate_history.append(network_data['bitrate'])
                self.packet_size_history.append(network_data['avg_packet_size'])
                if 'latency' in network_data:
                    self.latency_history.append(network_data['latency'])

                bitrate_baseline = self.calculate_adaptive_baseline(list(self.bitrate_history))
                packet_size_baseline = self.calculate_adaptive_baseline(list(self.packet_size_history))
                latency_baseline = self.calculate_adaptive_baseline(list(self.latency_history)) if self.latency_history else None

                if not bitrate_baseline or not packet_size_baseline:
                    self.logger.warning("Nicht genügend Daten für Baseline-Berechnung")
                    return

                baseline = {
                    'bitrate': bitrate_baseline,
                    'packet_size': packet_size_baseline,
                    'latency': latency_baseline,
                    'timestamp': datetime.now().isoformat(),
                    'meeting_type': meeting_type
                }

                self.baselines[meeting_type] = baseline

                if bitrate_baseline and packet_size_baseline:
                    self.logger.info(f"""Baseline aktualisiert für {meeting_type}:
    - Bitrate: {bitrate_baseline['mean']:.2f} Mbps (±{bitrate_baseline['std']:.2f})
    - Paketgröße: {packet_size_baseline['mean']:.0f} Bytes (±{packet_size_baseline['std']:.0f})
    - Samples: {bitrate_baseline['sample_count']}""")

        except Exception as e:
            self.logger.error(f"Fehler bei Baseline-Update: {str(e)}")
            self.logger.debug(f"Netzwerkdaten: {network_data}")

    def detect_meeting_type(self, data):
        try:
            config = MONITORING_CONFIG['meeting_types']

            if (data['bitrate'] >= config['video']['min_bitrate'] and
                    data['avg_packet_size'] >= config['video']['min_packet_size']):
                return 'video'
            elif (data['bitrate'] <= config['audio']['max_bitrate'] and
                  data['avg_packet_size'] <= config['audio']['max_packet_size']):
                return 'audio'
            elif data['bitrate'] >= config['screenshare']['min_bitrate']:
                return 'screenshare'
            return 'unknown'

        except Exception as e:
            self.logger.error(f"Fehler bei Meeting-Typ-Erkennung: {e}")
            return 'unknown'

    def calculate_anomaly_score(self, current_data):
        try:
            meeting_type = self.detect_meeting_type(current_data)
            baseline = self.baselines.get(meeting_type, {})

            if not baseline or 'bitrate' not in baseline:
                return 0.0

            anomaly_score = 0
            weights = self.config['weights']

            bitrate_baseline = baseline['bitrate']
            if bitrate_baseline:
                mean_deviation = abs(current_data['bitrate'] - bitrate_baseline['mean']) / bitrate_baseline['mean']
                if mean_deviation > 0.5:
                    anomaly_score += weights['mean_deviation']

                if bitrate_baseline['std'] > 0:
                    z_score = abs(current_data['bitrate'] - bitrate_baseline['mean']) / bitrate_baseline['std']
                    if z_score > 2:
                        anomaly_score += weights['std_deviation']

                if (current_data['bitrate'] < (bitrate_baseline['q1'] - 1.5 * bitrate_baseline['iqr']) or
                        current_data['bitrate'] > (bitrate_baseline['q3'] + 1.5 * bitrate_baseline['iqr'])):
                    anomaly_score += weights['iqr_violation']

            return anomaly_score

        except Exception as e:
            self.logger.error(f"Fehler bei Anomalie-Berechnung: {e}")
            return 0.0

class PacketAnalyzer:
    """Erweiterte Paketanalyse mit Echtzeit-Mustererkennung"""

    def __init__(self, config):
        self.config = config
        self.packet_buffer = deque(maxlen=1000)
        self.pattern_history = deque(maxlen=100)
        self.lock = Lock()

    def analyze_packet(self, packet):
        """Detaillierte Analyse eines einzelnen Pakets"""
        try:
            packet_data = {
                'timestamp': time.time(),
                'size': len(packet),
                'protocol': 'UDP' if UDP in packet else 'TCP' if TCP in packet else 'unknown',
                'sequence_pattern': self._extract_sequence_pattern(packet),
                'timing_pattern': self._extract_timing_pattern(packet)
            }

            with self.lock:
                self.packet_buffer.append(packet_data)

            return packet_data
        except Exception as e:
            logging.error(f"Fehler bei Paketanalyse: {e}")
            return None

    def _extract_protocol_features(self, packet):
        """Analysiert Protokoll-spezifische Features"""
        features = {
            'flags': [],
            'options': {},
            'header_size': 0
        }

        try:
            if IP in packet:
                features['header_size'] = packet[IP].ihl * 4
                if TCP in packet:
                    tcp = packet[TCP]
                    features['flags'] = [
                        'FIN' if tcp.flags.F else None,
                        'SYN' if tcp.flags.S else None,
                        'RST' if tcp.flags.R else None,
                        'PSH' if tcp.flags.P else None,
                        'ACK' if tcp.flags.A else None,
                        'URG' if tcp.flags.U else None
                    ]
                    features['flags'] = [f for f in features['flags'] if f]
                    features['options'] = {
                        'window_size': tcp.window,
                        'urgent_pointer': tcp.urgptr if tcp.flags.U else 0
                    }
                elif UDP in packet:
                    features['options'] = {
                        'length': packet[UDP].len
                    }
        except Exception as e:
            logging.error(f"Fehler bei Protokollanalyse: {e}")

        return features

    def _extract_sequence_pattern(self, packet):
        """Extrahiert Sequenzmuster aus Paket"""
        pattern = {
            'header_entropy': self._calculate_entropy(packet),
            'payload_structure': self._analyze_payload(packet),
            'protocol_features': self._extract_protocol_features(packet)
        }
        return pattern

    def _extract_timing_pattern(self, packet):
        """Analysiert zeitliche Muster"""
        with self.lock:
            if len(self.packet_buffer) < 2:
                return {'interval': 0, 'regularity': 1.0}

            last_packet = self.packet_buffer[-1]
            second_last_packet = self.packet_buffer[-2]
            interval = last_packet['timestamp'] - second_last_packet['timestamp']

            # Berechnung der Regularität über die letzten 10 Intervalle
            intervals = [
                self.packet_buffer[i]['timestamp'] - self.packet_buffer[i - 1]['timestamp']
                for i in range(max(1, len(self.packet_buffer) - 10), len(self.packet_buffer))
            ]

            if not intervals:
                return {'interval': 0, 'regularity': 1.0}

            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            regularity = 1.0 - (std_interval / mean_interval) if mean_interval > 0 else 1.0

            return {
                'interval': mean_interval,
                'regularity': regularity
            }

    def _calculate_entropy(self, packet):
        """Berechnet Entropie der Paketdaten"""
        try:
            data = bytes(packet)
            _, counts = np.unique(data, return_counts=True)
            probabilities = counts / len(data)
            entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
            return entropy
        except:
            return 0

    def _analyze_payload(self, packet):
        """Analysiert Payload-Struktur"""
        if IP in packet:
            if UDP in packet:
                payload = bytes(packet[UDP].payload)
            elif TCP in packet:
                payload = bytes(packet[TCP].payload)
            else:
                return {}

            return {
                'size': len(payload),
                'entropy': self._calculate_entropy(payload),
                'pattern_type': self._detect_pattern_type(payload)
            }
        return {}

    def _detect_pattern_type(self, payload):
        """Erkennt Muster im Payload"""
        if len(payload) < 64:
            return 'small'

        entropy = self._calculate_entropy(payload)
        if entropy > 7.5:
            return 'encrypted'
        elif entropy > 6.0:
            return 'compressed'
        else:
            return 'raw'

class DeepfakeDetector:
    """Erweiterte Deepfake-Erkennung mit Echtzeitanalyse"""

    def __init__(self, config):
        self.config = config
        self.packet_analyzer = PacketAnalyzer(config)
        self.metrics_history = deque(maxlen=1000)
        self.lock = Lock()
        self.logger = logging.getLogger('teams_monitoring.deepfake')

    def analyze_stream(self, packets, duration):
        """Hauptanalyse-Funktion"""
        try:
            # Grundlegende Metriken
            basic_metrics = self._calculate_basic_metrics(packets, duration)

            if not basic_metrics:
                self.logger.debug("Keine grundlegenden Metriken berechnet.")
                return None

            # Erweiterte Analysen
            timing_analysis = self._analyze_timing_patterns(packets)
            compression_analysis = self._analyze_compression_patterns(packets)
            correlation_analysis = self._perform_correlation_analysis(packets)

            # Kombinierte Bewertung
            risk_score = self._calculate_risk_score(
                basic_metrics,
                timing_analysis,
                compression_analysis,
                correlation_analysis
            )

            result = {
                'timestamp': datetime.now().isoformat(),
                'risk_score': risk_score,
                'metrics': basic_metrics,
                'timing_analysis': timing_analysis,
                'compression_analysis': compression_analysis,
                'correlation': correlation_analysis
            }

            with self.lock:
                self.metrics_history.append(result)

            return result

        except Exception as e:
            self.logger.error(f"Fehler bei Stream-Analyse: {e}")
            return None

    def _calculate_basic_metrics(self, packets, duration):
        if not packets:
            return None

        try:
            packet_sizes = [p['size'] for p in packets]
            timestamps = [p['timestamp'] for p in packets]
            intervals = np.diff(timestamps)

            return {
                'packet_count': len(packets),
                'bitrate': sum(packet_sizes) * 8 / duration / 1e6,  # Mbps
                'avg_packet_size': np.mean(packet_sizes),
                'std_packet_size': np.std(packet_sizes),
                'avg_interval': np.mean(intervals) if len(intervals) > 0 else 0,
                'std_interval': np.std(intervals) if len(intervals) > 0 else 0
            }
        except Exception as e:
            self.logger.error(f"Fehler bei Metrik-Berechnung: {e}")
            return None

    def _analyze_timing_patterns(self, packets):
        """Analysiert zeitliche Muster im Detail"""
        timing_patterns = {
            'regularity': self._calculate_timing_regularity(packets),
            'burst_patterns': self._analyze_burst_patterns(packets),
            'rhythm_consistency': self._analyze_rhythm_consistency(packets)
        }
        return timing_patterns

    def _calculate_timing_regularity(self, packets):
        """Berechnet die Regularität der Paketzeitabstände"""
        timestamps = [p['timestamp'] for p in packets]  # Zugriff auf das timestamp-Feld
        intervals = np.diff(timestamps)

        if len(intervals) < 2:
            return 1.0

        return 1.0 - (np.std(intervals) / np.mean(intervals)) if np.mean(intervals) > 0 else 1.0

    def _analyze_compression_patterns(self, packets):
        """Analysiert Kompressionsmuster"""
        try:
            # Zugriff auf raw_packet für die Payload-Analyse
            payloads = []
            for p in packets:
                raw_packet = p['raw_packet']
                if TCP in raw_packet:
                    payloads.append(bytes(raw_packet[TCP].payload))
                elif UDP in raw_packet:
                    payloads.append(bytes(raw_packet[UDP].payload))
                else:
                    payloads.append(b'')

            entropies = [self.packet_analyzer._calculate_entropy(p) for p in payloads if p]

            return {
                'avg_entropy': np.mean(entropies) if entropies else 0,
                'entropy_stability': 1.0 - (np.std(entropies) / np.mean(entropies)) if entropies and np.mean(entropies) > 0 else 0,
                'compression_ratio': self._estimate_compression_ratio(payloads)
            }
        except Exception as e:
            self.logger.error(f"Fehler bei der Kompressionsmuster-Analyse: {e}")
            return {'avg_entropy': 0, 'entropy_stability': 1.0, 'compression_ratio': 1.0}

    def _perform_correlation_analysis(self, packets):
        """Führt Korrelationsanalyse zwischen verschiedenen Metriken durch"""
        if len(packets) < self.config['analysis']['min_packets']:
            return {}

        try:
            sizes = [p['size'] for p in packets]
            timestamps = [p['timestamp'] for p in packets]
            intervals = np.diff(timestamps)

            correlations = {
                'size_time': np.corrcoef(sizes[:-1], intervals)[0, 1] if len(intervals) > 0 else 0,
                'size_pattern': self._analyze_size_pattern_correlation(sizes),
                'timing_pattern': self._analyze_timing_pattern_correlation(intervals)
            }

            return correlations
        except Exception as e:
            self.logger.error(f"Fehler bei der Korrelationsanalyse: {e}")
            return {}

    def _calculate_risk_score(self, basic_metrics, timing_analysis, compression_analysis, correlation_analysis):
        """Berechnet den endgültigen Risiko-Score"""
        scores = []

        # Timing-basierte Scores
        if timing_analysis['regularity'] < self.config['timing_patterns']['timing_regularity']:
            scores.append(0.7)

        # Kompressions-basierte Scores
        if compression_analysis['compression_ratio'] < self.config['metrics']['compression_ratio']:
            scores.append(0.6)

        # Korrelations-basierte Scores
        if abs(correlation_analysis.get('size_time', 0)) > self.config['analysis']['correlation_threshold']:
            scores.append(0.8)

        return np.mean(scores) if scores else 0.0

    def _analyze_burst_patterns(self, packets):
        """Analysiert Burst-Muster in den Paketen"""
        if not packets:
            return {'burst_count': 0, 'avg_burst_size': 0, 'burst_regularity': 1.0}

        try:
            burst_threshold = 0.1  # 100ms
            bursts = []
            current_burst = [packets[0]]

            for i in range(1, len(packets)):
                time_diff = packets[i]['timestamp'] - packets[i - 1]['timestamp']
                if time_diff < burst_threshold:
                    current_burst.append(packets[i])
                else:
                    if len(current_burst) > 1:
                        bursts.append(current_burst)
                    current_burst = [packets[i]]

            if len(current_burst) > 1:
                bursts.append(current_burst)

            if not bursts:
                return {'burst_count': 0, 'avg_burst_size': 0, 'burst_regularity': 1.0}

            burst_sizes = [len(b) for b in bursts]
            return {
                'burst_count': len(bursts),
                'avg_burst_size': np.mean(burst_sizes),
                'burst_regularity': 1.0 - (np.std(burst_sizes) / np.mean(burst_sizes)) if burst_sizes else 1.0
            }
        except Exception as e:
            self.logger.error(f"Fehler bei Burst-Analyse: {e}")
            return {'burst_count': 0, 'avg_burst_size': 0, 'burst_regularity': 1.0}

    def _analyze_rhythm_consistency(self, packets):
        """Analysiert die Konsistenz des Paketrhythmus"""
        if not packets:
            return {'consistency': 1.0, 'pattern_strength': 0.0}

        try:
            timestamps = [p['timestamp'] for p in packets]
            intervals = np.diff(timestamps)

            if len(intervals) < 2:
                return {'consistency': 1.0, 'pattern_strength': 0.0}

            # Rhythmus-Konsistenz basierend auf Intervall-Varianz
            consistency = 1.0 - (np.std(intervals) / np.mean(intervals)) if np.mean(intervals) > 0 else 1.0

            # FFT für Periodizitätserkennung
            fft = np.abs(np.fft.fft(intervals))
            dominant_freq = np.max(fft[1:]) / len(intervals)

            return {
                'consistency': max(0.0, min(1.0, consistency)),
                'pattern_strength': dominant_freq
            }
        except Exception as e:
            self.logger.error(f"Fehler bei Rhythmus-Analyse: {e}")
            return {'consistency': 1.0, 'pattern_strength': 0.0}

    def _estimate_compression_ratio(self, payloads):
        """Schätzt das Kompressionsverhältnis der Payloads"""
        if not payloads:
            return 1.0

        try:
            # Einfache Schätzung basierend auf Entropie
            entropies = [self.packet_analyzer._calculate_entropy(p) for p in payloads if p]
            if not entropies:
                return 1.0

            avg_entropy = np.mean(entropies)
            max_entropy = 8.0  # Maximale Entropie für Bytes

            # Höhere Entropie deutet auf höhere Kompression hin
            return avg_entropy / max_entropy
        except Exception as e:
            self.logger.error(f"Fehler bei Kompressions-Analyse: {e}")
            return 1.0

    def _analyze_size_pattern_correlation(self, sizes):
        """Analysiert Korrelationen in Paketgrößen-Mustern"""
        if len(sizes) < 3:
            return 0.0

        try:
            # Autokorrelation für Mustererkennung
            auto_corr = np.correlate(sizes, sizes, mode='full')
            # Normalisierung
            auto_corr = auto_corr[len(auto_corr) // 2:] / auto_corr[len(auto_corr) // 2]

            # Stärke der Muster basierend auf Autokorrelation
            pattern_strength = np.mean(np.abs(auto_corr[1:10]))
            return pattern_strength
        except Exception as e:
            self.logger.error(f"Fehler bei Größenmuster-Analyse: {e}")
            return 0.0

    def _analyze_timing_pattern_correlation(self, intervals):
        """Analysiert Korrelationen in Timing-Mustern"""
        if len(intervals) < 3:
            return 0.0

        try:
            # Autokorrelation für Timing-Mustererkennung
            auto_corr = np.correlate(intervals, intervals, mode='full')
            # Normalisierung
            auto_corr = auto_corr[len(auto_corr) // 2:] / auto_corr[len(auto_corr) // 2]

            # Periodizität basierend auf Autokorrelation
            periodicity = np.mean(np.abs(auto_corr[1:10]))
            return periodicity
        except Exception as e:
            self.logger.error(f"Fehler bei Timing-Muster-Analyse: {e}")
            return 0.0

    def _calculate_risk_score(self, basic_metrics, timing_analysis, compression_analysis, correlation_analysis):
        """Berechnet den endgültigen Risiko-Score"""
        scores = []

        # Timing-basierte Scores
        if timing_analysis['regularity'] < self.config['timing_patterns']['timing_regularity']:
            scores.append(0.7)

        # Kompressions-basierte Scores
        if compression_analysis['compression_ratio'] < self.config['metrics']['compression_ratio']:
            scores.append(0.6)

        # Korrelations-basierte Scores
        if abs(correlation_analysis.get('size_time', 0)) > self.config['analysis']['correlation_threshold']:
            scores.append(0.8)

        return np.mean(scores) if scores else 0.0

def get_default_interface():
    """Ermittelt das Standard-Netzwerk-Interface"""
    try:
        interfaces = get_if_list()
        logger.info(f"Verfügbare Interfaces: {interfaces}")

        # Prüfe zuerst die common_interfaces
        common_interfaces = ["en0", "en1", "eth0", "wlan0", "Wi-Fi", "Ethernet"]
        for interface in common_interfaces:
            if interface in interfaces:
                logger.info(f"Verwende bekanntes Interface: {interface}")
                return interface

        # Wenn kein bekanntes Interface gefunden wurde, nimm das erste
        if interfaces:
            logger.info(f"Verwende erstes verfügbares Interface: {interfaces[0]}")
            return interfaces[0]

        logger.error("Keine Netzwerk-Interfaces gefunden")
        return None

    except Exception as e:
        logger.error(f"Fehler bei der Interface-Erkennung: {e}", exc_info=True)
        return None

def monitor_bitrate(interface, baseline_manager, deepfake_detector):
    """Überwacht die Bitrate mit verbesserter Baseline-Analyse und Deepfake-Erkennung"""
    logger = logging.getLogger('teams_monitoring.bitrate')
    logger.info(f"Starte Bitraten-Monitoring auf Interface {interface}...")

    packet_buffer = PacketBuffer()
    last_analysis_time = time.time()

    def is_teams_packet(packet):
        try:
            if IP in packet:
                src_port = None
                dst_port = None
                if UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                if src_port or dst_port:
                    is_teams = (
                        (src_port in MONITORING_CONFIG['ports']['tcp'] or
                         dst_port in MONITORING_CONFIG['ports']['tcp']) if TCP in packet
                        else (src_port in MONITORING_CONFIG['ports']['udp'] or
                              dst_port in MONITORING_CONFIG['ports']['udp'])
                    )
                    if is_teams:
                        logger.debug(f"Teams-Paket gefunden: {packet.summary()}")
                    return is_teams
            return False
        except Exception as e:
            logger.error(f"Fehler bei Paket-Analyse: {str(e)}", exc_info=True)
            return False

    def process_packets():
        try:
            packets = packet_buffer.get_packets(clear=True)

            if not packets:
                return

            stats = packet_buffer.get_statistics()

            if not stats:
                return

            network_data = {
                'bitrate': float(stats['bitrate']),
                'packet_count': int(stats['packet_count']),
                'avg_packet_size': float(stats['avg_packet_size']),
                'timestamp': datetime.now().isoformat()
            }
            logger.info(f"Netzwerk-Daten: Bitrate: {network_data['bitrate']:.2f} Mbps, Pakete: {network_data['packet_count']}, Durchschnittliche Paketgröße: {network_data['avg_packet_size']:.2f} Bytes")

            # Baseline Update und Anomalie-Erkennung
            if network_data['bitrate'] > 0 and network_data['avg_packet_size'] > 0:
                baseline_manager.update_baseline(network_data)
                anomaly_score = baseline_manager.calculate_anomaly_score(network_data)
                logger.info(f"Anomalie-Score: {anomaly_score:.2f}")

                # Senden der Bitraten-Ergebnisse an das Backend
                try:
                    meeting_type = baseline_manager.detect_meeting_type(network_data)
                    if anomaly_score > MONITORING_CONFIG['baseline']['anomaly_threshold']:
                        status = "anomaly detected"
                        details = {
                            "type": "bitrate",
                            "value": network_data['bitrate'],
                            "avg_packet_size": network_data['avg_packet_size'],
                            "timestamp": network_data['timestamp'],
                            "status": "anomaly",
                            "anomalies": []
                        }
                        if anomaly_score >= MONITORING_CONFIG['baseline']['weights']['mean_deviation']:
                            details['anomalies'].append("mean_deviation")
                        if anomaly_score >= MONITORING_CONFIG['baseline']['weights']['std_deviation']:
                            details['anomalies'].append("std_deviation")
                        if anomaly_score >= MONITORING_CONFIG['baseline']['weights']['iqr_violation']:
                            details['anomalies'].append("iqr_violation")
                    else:
                        status = "normal"
                        details = {
                            "bitrate": network_data['bitrate'],
                            "avg_packet_size": network_data['avg_packet_size'],
                            "timestamp": network_data['timestamp'],
                            "host": "unknown"  # Optional, falls erforderlich
                        }

                    payload_bitrate = {
                        "status": status,
                        "bitrate": network_data['bitrate'],
                        "avg_packet_size": network_data['avg_packet_size'],
                        "timestamp": network_data['timestamp'],
                        "meeting_type": meeting_type
                    }
                    if status == "anomaly detected":
                        payload_bitrate.update({"details": details})

                    send_post_request(API_CONFIG['endpoints']['bitrate'], payload_bitrate)

                except Exception as e:
                    logger.error(f"Fehler beim Senden der Bitraten-Daten an API: {e}")

                # Deepfake-Analyse
                deepfake_result = deepfake_detector.analyze_stream(packets, stats['duration'])
                if deepfake_result and deepfake_result['risk_score'] > 0.7:
                    logger.warning(f"Möglicher Deepfake erkannt. Risk Score: {deepfake_result['risk_score']:.2f}")

                # Senden der Anomalie-Daten an das Backend
                try:
                    if anomaly_score > MONITORING_CONFIG['baseline']['anomaly_threshold']:
                        payload_anomaly = {
                            "status": status,
                            "bitrate": network_data['bitrate'],
                            "packet_count": network_data['packet_count'],
                            "avg_packet_size": network_data['avg_packet_size'],
                            "anomaly_score": anomaly_score,
                            "meeting_type": meeting_type,
                            "timestamp": network_data['timestamp']
                        }
                        send_post_request(API_CONFIG['endpoints']['anomaly'], payload_anomaly)

                    if deepfake_result:
                        payload_deepfake = {
                            'status': 'received',
                            'risk_score': deepfake_result['risk_score'],
                            'analysis': deepfake_result,
                            'timestamp': deepfake_result['timestamp']
                        }
                        send_post_request(API_CONFIG['endpoints']['deepfake'], payload_deepfake)
                except Exception as e:
                    logger.error(f"Fehler beim Senden der Anomalie- und Deepfake-Daten an API: {e}")

        except Exception as e:
            logger.error(f"Fehler bei der Paketverarbeitung: {e}")

    while True:
        try:
            packets = sniff(
                iface=interface,
                timeout=MONITORING_CONFIG['intervals']['bitrate'],
                lfilter=is_teams_packet
            )

            for packet in packets:
                packet_buffer.add_packet(packet)

            current_time = time.time()
            if (
                len(packet_buffer.packets) >= 100 and
                current_time - last_analysis_time >= MONITORING_CONFIG['intervals']['bitrate']
            ):
                process_packets()
                last_analysis_time = current_time

        except Exception as e:
            logger.error(f"Fehler bei der Paketverarbeitung: {e}", exc_info=True)

        time.sleep(1)

def monitor_latency(baseline_manager):
    """Überwacht kontinuierlich die Latenz zu Teams-Servern und sendet die Ergebnisse"""
    logger = logging.getLogger('teams_monitoring.latency')
    logger.info("Starte Latenz-Monitoring...")

    latency_threshold = 100  # Beispielwert in ms

    while True:
        for host in MONITORING_CONFIG['hosts']:
            try:
                sock = socket.create_connection((host, 443), timeout=5)
                start_time = time.time()
                sock.send(b'')
                latency = (time.time() - start_time) * 1000  # ms
                sock.close()

                logger.info(f"Latenz zu {host}: {latency:.2f}ms")

                # Berechnung des Status basierend auf dem Schwellenwert
                if latency > latency_threshold:
                    status = "anomaly detected"
                    details = {
                        "type": "latency",
                        "value": latency,
                        "host": host,
                        "timestamp": datetime.now().isoformat(),
                        "status": "anomaly"
                    }
                else:
                    status = "normal"
                    details = {
                        "latency": latency,
                        "host": host,
                        "timestamp": datetime.now().isoformat()
                    }

                # Senden der Latenz-Ergebnisse an das Backend
                payload_latency = {
                    "status": status,
                    "latency": latency,
                    "host": host,
                    "timestamp": datetime.now().isoformat()
                }

                if status == "anomaly detected":
                    payload_latency["details"] = details

                send_post_request(API_CONFIG['endpoints']['latency'], payload_latency)

                break  # Erfolgreiche Messung, gehe zum nächsten Zyklus

            except (socket.timeout, socket.error) as e:
                logger.warning(f"Verbindungsfehler zu {host}: {e}")
                continue

        time.sleep(MONITORING_CONFIG['intervals']['latency'])

def main():
    """Hauptfunktion des Monitoring-Systems"""
    logger.info("Teams Monitoring System wird gestartet...")

    # Prüfe Berechtigungen
    try:
        test_packet = sniff(count=1, timeout=1)
        logger.info("Paket-Sniffing erfolgreich getestet")
    except Exception as e:
        logger.error(f"Keine Berechtigung für Packet Sniffing: {e}")
        logger.error("Bitte Skript mit sudo/Administrator-Rechten ausführen")
        return

    global token
    token = get_token_with_refresh()
    if not token:
        logger.error("Konnte keinen API-Token abrufen. System wird beendet.")
        return

    interface = get_default_interface()
    if not interface:
        logger.error("Kein geeignetes Netzwerk-Interface gefunden. System wird beendet.")
        return

    logger.info(f"Verwende Netzwerk-Interface: {interface}")

    # Monitoring-Komponenten initialisieren
    baseline_manager = NetworkBaseline()
    deepfake_detector = DeepfakeDetector(MONITORING_CONFIG['deepfake_detection'])

    threads = []

    # Thread für Latenz-Monitoring
    latency_thread = threading.Thread(
        target=monitor_latency,
        args=(baseline_manager,),
        daemon=True,
        name="LatencyMonitor"
    )

    # Thread für Bitraten-Monitoring mit Deepfake-Erkennung
    bitrate_thread = threading.Thread(
        target=monitor_bitrate,
        args=(interface, baseline_manager, deepfake_detector),
        daemon=True,
        name="BitrateMonitor"
    )

    threads.extend([latency_thread, bitrate_thread])

    for thread in threads:
        logger.info(f"Starte Thread: {thread.name}")
        thread.start()

    try:
        while True:
            for thread in threads:
                if not thread.is_alive():
                    logger.error(f"Thread {thread.name} ist gestoppt!")
            time.sleep(MONITORING_CONFIG['intervals']['stats'])
    except KeyboardInterrupt:
        logger.info("System wird beendet...")
    except Exception as e:
        logger.error(f"Unerwarteter Fehler im Hauptprozess: {e}")
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()
