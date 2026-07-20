import logging
from rich.logging import RichHandler
from rich.console import Console
from datetime import datetime
import os

console = Console()


def setup_logger(name: str) -> logging.Logger:
    """Configura y retorna un logger personalizado."""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Handler para archivo
    file_handler = logging.FileHandler(
        f"logs/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Handler para consola con Rich
    console_handler = RichHandler()
    console_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
