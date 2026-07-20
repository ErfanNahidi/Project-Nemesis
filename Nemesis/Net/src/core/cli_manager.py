import argparse
import json
from rich.console import Console
from rich.table import Table
from ..utils.logging_utils import setup_logger
from .attack_manager import AttackManager, AttackConfig

console = Console()
logger = setup_logger("cli_manager")


class CLIManager:
    def __init__(self):
        self.attack_manager = AttackManager()
        self.config = self.load_config()

    def load_config(self) -> dict:
        """Carga la configuración desde config.json."""
        try:
            with open('config/config.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error al cargar configuración: {e}")
            return {"n_threads": 5, "n_packets": 50}

    def create_parser(self) -> argparse.ArgumentParser:
        """Crea y configura el parser de argumentos."""
        parser = argparse.ArgumentParser(
            description="Herramienta de pruebas de seguridad de red",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument("-i", "--ip", help="IP objetivo")
        parser.add_argument("-s", "--source", help="IP origen")
        parser.add_argument("-f", "--file", type=str,
                            help="Archivo con IPs objetivo")
        parser.add_argument("-n", "--number", type=int,
                            help="Número de paquetes")
        parser.add_argument("--threads", type=int, help="Número de threads")
        parser.add_argument(
            "--interface", type=str, help="Interfaz de red a usar")

        attack_group = parser.add_mutually_exclusive_group(required=True)
        attack_group.add_argument(
            "--arp", help="Ataque ARP Spoofing, IP del Host/Gateway", type=str)
        attack_group.add_argument(
            "--syn", action="store_true", help="Ataque SYN Flood")
        attack_group.add_argument(
            "--icmp", action="store_true", help="Ataque ICMP Flood")

        return parser

    def display_attack_info(self, config: AttackConfig):
        """Muestra información del ataque en una tabla."""
        table = Table(title="Configuración del Ataque")

        table.add_column("Parámetro", style="cyan")
        table.add_column("Valor", style="green")

        table.add_row("Tipo de Ataque", config.attack_type)
        table.add_row("IPs Objetivo", ", ".join(config.target_ips))
        if config.source_ip:
            table.add_row("IP Origen", config.source_ip)
        if config.num_packets:
            table.add_row("Número de Paquetes", str(config.num_packets))

        console.print(table)

    def run(self):
        """Ejecuta la interfaz de línea de comandos."""
        parser = self.create_parser()
        args = parser.parse_args()

        try:
            # Preparar configuración del ataque
            target_ips = []
            if args.ip:
                target_ips.append(args.ip)
            elif args.file:
                with open(args.file, 'r') as f:
                    target_ips.extend(line.strip()
                                      for line in f if line.strip())

            # Determinar tipo de ataque
            attack_type = None
            if args.arp:
                attack_type = "arp_spoof"
            elif args.syn:
                attack_type = "syn_flood"
            elif args.icmp:
                attack_type = "ping_flood"

            config = AttackConfig(
                attack_type=attack_type,
                target_ips=target_ips,
                source_ip=args.source,
                num_packets=args.number or self.config["n_packets"],
                gateway_ip=args.arp if attack_type == "arp_spoof" else None,
            )

            self.display_attack_info(config)
            self.attack_manager.start_attack(config)

        except KeyboardInterrupt:
            logger.info("Deteniendo ataque por solicitud del usuario...")
            self.attack_manager.stop_all_attacks()
        except Exception as e:
            logger.error(f"Error durante la ejecución: {e}")
