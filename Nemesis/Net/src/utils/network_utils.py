import ipaddress
from scapy.all import get_if_list, conf
from ..utils.logging_utils import setup_logger

logger = setup_logger("network_utils")


def validate_ip(ip: str) -> bool:
    """Valida una dirección IP."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_interface_list() -> list:
    """Obtiene lista de interfaces de red disponibles."""
    return get_if_list()


def get_default_interface() -> str:
    """Obtiene la interfaz de red predeterminada."""
    return conf.iface


def enable_ip_forwarding() -> bool:
    """Habilita el reenvío de IP en sistemas Linux."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        return True
    except Exception as e:
        logger.error(f"Error al habilitar IP forwarding: {e}")
        return False