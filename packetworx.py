import pyshark
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os
from datetime import datetime
import numpy as np

class PacketWorx:
    def __init__(self, pcap_file=None, interface=None):
        self.pcap_file = pcap_file
        self.interface = interface
        self.model_file = 'packet_classifier.joblib'
        self.anomaly_model_file = 'anomaly_detector.joblib'
        self.model = self.load_model()
        self.anomaly_model = self.load_anomaly_model()
        self.features = [
            'length', 'source_port', 'destination_port', 'time_of_day',
            'protocol_number', 'packet_size_variance', 'source_bytes', 'destination_bytes'
        ]

    def read_pcap(self):
        if self.pcap_file:
            capture = pyshark.FileCapture(self.pcap_file)
        elif self.interface:
            capture = pyshark.LiveCapture(interface=self.interface)
        else:
            raise ValueError("No pcap file or interface provided.")
       
        packets = []
        source_bytes = {}
        destination_bytes = {}

        for packet in capture:
            try:
                length = int(packet.length)
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                if src_ip not in source_bytes:
                    source_bytes[src_ip] = 0
                if dst_ip not in destination_bytes:
                    destination_bytes[dst_ip] = 0

                source_bytes[src_ip] += length
                destination_bytes[dst_ip] += length

                packet_info = {
                    'packet_number': packet.number,
                    'timestamp': packet.sniff_time,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'protocol': packet.transport_layer,
                    'length': length,
                    'time_of_day': packet.sniff_time.hour * 3600 + packet.sniff_time.minute * 60 + packet.sniff_time.second,
                    'protocol_number': self.get_protocol_number(packet.transport_layer),
                    'source_bytes': source_bytes[src_ip],
                    'destination_bytes': destination_bytes[dst_ip]
                }
               
                if hasattr(packet, 'tcp'):
                    packet_info['source_port'] = int(packet.tcp.srcport)
                    packet_info['destination_port'] = int(packet.tcp.dstport)
                elif hasattr(packet, 'udp'):
                    packet_info['source_port'] = int(packet.udp.srcport)
                    packet_info['destination_port'] = int(packet.udp.dstport)
                else:
                    packet_info['source_port'] = 0
                    packet_info['destination_port'] = 0

                packets.append(packet_info)

            except AttributeError:
                pass

        df = pd.DataFrame(packets)
        df['packet_size_variance'] = df['length'].rolling(window=10).var()
        df.fillna(0, inplace=True)

        return df

    def get_protocol_number(self, protocol):
        if protocol == 'TCP':
            return 6
        elif protocol == 'UDP':
            return 17
        return 0

    def train_model(self, df):
        features = df[self.features].fillna(0)
        labels = df['protocol'].apply(lambda x: 1 if x == 'TCP' else 0)  # Dummy labels for example
       
        model = GradientBoostingClassifier()
        model.fit(features, labels)
        dump(model, self.model_file)

    def train_anomaly_model(self, df):
        features = df[self.features].fillna(0)
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        pca = PCA(n_components=0.95)
        features_reduced = pca.fit_transform(features_scaled)
        anomaly_model = IsolationForest(contamination=0.01)
        anomaly_model.fit(features_reduced)
        dump((scaler, pca, anomaly_model), self.anomaly_model_file)

    def load_model(self):
        if os.path.exists(self.model_file):
            return load(self.model_file)
        return None

    def load_anomaly_model(self):
        if os.path.exists(self.anomaly_model_file):
            return load(self.anomaly_model_file)
        return None

    def classify_packets(self, df):
        if self.model:
            features = df[self.features].fillna(0)
            predictions = self.model.predict(features)
            df['classification'] = predictions
        else:
            df['classification'] = np.nan
        return df

    def detect_anomalies(self, df):
        if self.anomaly_model:
            scaler, pca, anomaly_model = self.anomaly_model
            features = df[self.features].fillna(0)
            features_scaled = scaler.transform(features)
            features_reduced = pca.transform(features_scaled)
            df['anomaly_score'] = anomaly_model.decision_function(features_reduced)
            df['anomaly'] = anomaly_model.predict(features_reduced)
        else:
            df['anomaly_score'] = np.nan
            df['anomaly'] = np.nan
        return df

    def run(self):
        df = self.read_pcap()

        if self.model is None:
            self.train_model(df)
            self.model = self.load_model()

        if self.anomaly_model is None:
            self.train_anomaly_model(df)
            self.anomaly_model = self.load_anomaly_model()
       
        if self.model:
            df = self.classify_packets(df)

        if self.anomaly_model:
            df = self.detect_anomalies(df)

        print(df)

    def suggest_filter(self):
        if self.model:
            print("Suggested filter: tcp or udp")

    def highlight_suspicious_packets(self):
        df = self.read_pcap()
        if self.model:
            df = self.classify_packets(df)
            suspicious_packets = df[df['classification'] == 1]
            print("Suspicious packets:")
            print(suspicious_packets)

    def highlight_anomalous_packets(self):
        df = self.read_pcap()
        if self.anomaly_model:
            df = self.detect_anomalies(df)
            anomalous_packets = df[df['anomaly'] == -1]
            print("Anomalous packets:")
            print(anomalous_packets)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PacketWorx: An AI assistant for Wireshark.")
    parser.add_argument('--pcap', type=str, help="Path to the pcap file.")
    parser.add_argument('--interface', type=str, help="Network interface for live capture.")
    parser.add_argument('--filter', action='store_true', help="Suggest a filter for Wireshark.")
    parser.add_argument('--highlight', action='store_true', help="Highlight suspicious packets.")
    parser.add_argument('--anomalies', action='store_true', help="Highlight anomalous packets.")

    args = parser.parse_args()

    packetworx = PacketWorx(pcap_file=args.pcap, interface=args.interface)

    if args.filter:
        packetworx.suggest_filter()
    elif args.highlight:
        packetworx.highlight_suspicious_packets()
    elif args.anomalies:
        packetworx.highlight_anomalous_packets()
    else:
        packetworx.run()