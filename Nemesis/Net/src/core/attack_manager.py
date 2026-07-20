from dataclasses import dataclass
from typing import Optional, List
from ..utils.logging_utils import setup_logger
from ..attacks.syn_flood import SynFloodAttack, SynFloodConfig
from ..attacks.arp_spoof import ARPSpoofAttack, ARPSpoofConfig
from ..attacks.ping_flood import PingFloodAttack, PingFloodConfig

logger = setup_logger("attack_manager")


@dataclass
class AttackConfig:
    attack_type: str
    target_ips: List[str]
    source_ip: Optional[str] = None
    payload: Optional[str] = None
    num_packets: Optional[int] = None
    gateway_ip: Optional[str] = None


class AttackManager:
    def __init__(self):
        self.logger = logger
        self.current_attacks = []

    def validate_config(self, config: AttackConfig) -> bool:
        """Valida la configuración del ataque."""
        if not config.target_ips:
            self.logger.error("No se especificaron IPs objetivo")
            return False

        if config.attack_type not in ["syn_flood", "arp_spoof", "ping_flood"]:
            self.logger.error(
                f"Tipo de ataque no válido: {config.attack_type}")
            return False

        if config.attack_type == "arp_spoof" and not config.gateway_ip:
            self.logger.error("Se requiere IP del gateway para ARP spoofing")
            return False

        return True

    def start_attack(self, config: AttackConfig):
        """Inicia un ataque basado en la configuración."""
        if not self.validate_config(config):
            return

        try:
            if config.attack_type == "syn_flood":
                syn_config = SynFloodConfig(
                    target_ip=config.target_ips[0],
                    source_ip=config.source_ip,
                    packet_count=config.num_packets
                )
                attack = SynFloodAttack(syn_config)
            elif config.attack_type == "arp_spoof":
                arp_config = ARPSpoofConfig(
                    target_ip=config.target_ips[0],
                    gateway_ip=config.gateway_ip,
                    packet_count=config.num_packets,
                )
                attack = ARPSpoofAttack(arp_config)
            elif config.attack_type == "ping_flood":
                ping_config = PingFloodConfig(
                    target_ip=config.target_ips[0],
                    packet_count=config.num_packets
                )
                attack = PingFloodAttack(ping_config)

            self.current_attacks.append(attack)
            attack.start_attack()

        except Exception as e:
            self.logger.error(f"Error al iniciar el ataque: {e}")

    def stop_all_attacks(self):
        """Detiene todos los ataques activos."""
        for attack in self.current_attacks:
            try:
                attack.stop_attack()
            except Exception as e:
                self.logger.error(f"Error al detener ataque: {e}")

        self.current_attacks.clear()
