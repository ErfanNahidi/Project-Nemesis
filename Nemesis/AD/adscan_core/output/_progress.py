"""Progress bars, status spinners, and ScanProgressTracker."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Optional

from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.status import Status

import adscan_core.output._state as _state
from adscan_core.output._log import print_info, print_info_verbose, print_warning  # noqa: F401
from adscan_core.output._panels import print_phase_header, print_step_status
from adscan_core.theme import ADSCAN_PRIMARY


__all__ = [
    "create_progress",
    "create_status",
    "create_progress_simple",
    "create_status_simple",
    "ScanProgressTracker",
]


@contextmanager
def create_progress(
    show_spinner: bool = True,
    show_percentage: bool = True,
    show_time_remaining: bool = False,
    show_time_elapsed: bool = False,
    transient: bool = False,
):
    """Create a Rich Progress context manager with brand styling.

    This provides a consistent progress bar interface for operations that have
    measurable progress (file downloads, installation steps, scanning targets, etc.).

    Args:
        show_spinner: Show animated spinner (default: True)
        show_percentage: Show percentage completion (default: True)
        show_time_remaining: Show estimated time remaining (default: False)
        show_time_elapsed: Show time elapsed (default: False)
        transient: Remove progress bar when complete (default: False)

    Yields:
        Progress: Rich Progress object for tracking tasks

    Examples:
        # Basic progress bar for multiple items
        with create_progress() as progress:
            task = progress.add_task("[cyan]Installing tools...", total=len(tools))
            for tool in tools:
                progress.update(task, description=f"[cyan]Installing {tool}...")
                install_tool(tool)
                progress.advance(task)

        # Progress with time estimation
        with create_progress(show_time_remaining=True) as progress:
            task = progress.add_task("[cyan]Downloading...", total=file_size)
            for chunk in download_chunks():
                progress.update(task, advance=len(chunk))

        # Multiple concurrent tasks
        with create_progress() as progress:
            task1 = progress.add_task("[cyan]Task 1...", total=100)
            task2 = progress.add_task("[green]Task 2...", total=50)
            # Update tasks independently
            progress.update(task1, advance=10)
            progress.update(task2, advance=5)
    """
    console = _state._get_console()

    # Build columns based on options
    columns: list[ProgressColumn] = []

    if show_spinner:
        columns.append(SpinnerColumn(spinner_name="dots", style=ADSCAN_PRIMARY))

    columns.append(TextColumn("[progress.description]{task.description}"))
    columns.append(BarColumn(complete_style=ADSCAN_PRIMARY, finished_style="green"))

    if show_percentage:
        columns.append(TaskProgressColumn())

    if show_time_remaining:
        columns.append(TimeRemainingColumn())

    if show_time_elapsed:
        columns.append(TimeElapsedColumn())

    # Create progress with brand styling
    progress = Progress(
        *columns,
        console=console,
        transient=transient,
        expand=False,
    )

    try:
        with progress:
            yield progress
    finally:
        pass


@contextmanager
def create_status(
    message: str,
    spinner: str = "dots",
    spinner_style: Optional[str] = None,
):
    """Create a Rich Status context manager with brand styling.

    This provides an animated spinner for indeterminate operations (operations
    where progress cannot be measured, like waiting for network response,
    analyzing data, etc.).

    Args:
        message: Status message to display
        spinner: Spinner animation style (default: "dots")
            Available: dots, line, pipe, simpleDots, star, arrow, bouncingBar,
                      bouncingBall, clock, earth, moon, etc.
        spinner_style: Color style for spinner (default: brand primary color)

    Yields:
        Status: Rich Status object for updating message

    Examples:
        # Basic spinner
        with create_status("Scanning domain..."):
            results = scan_domain()

        # Update message during operation
        with create_status("Initializing...") as status:
            init_tools()
            status.update("Connecting to domain...")
            connect()
            status.update("Analyzing results...")
            analyze()

        # Different spinner style
        with create_status("Processing...", spinner="bouncingBar"):
            long_operation()
    """
    console = _state._get_console()

    # Use brand color if no style specified
    if spinner_style is None:
        spinner_style = ADSCAN_PRIMARY

    # Create status with brand styling
    status = Status(
        message,
        console=console,
        spinner=spinner,
        spinner_style=spinner_style,
    )

    try:
        with status:
            yield status
    finally:
        pass


def create_progress_simple(total: int, description: str = "Processing...") -> tuple:
    """Create a simple progress bar with single task (convenience wrapper).

    This is a simplified version of create_progress() for the common case of
    tracking a single operation with known total steps.

    Args:
        total: Total number of steps
        description: Description to display (supports Rich markup)

    Returns:
        Tuple of (progress_context, task_id) ready to use

    Examples:
        # Simple usage
        progress, task = create_progress_simple(len(items), "[cyan]Processing items...")
        with progress:
            for item in items:
                process(item)
                progress.advance(task)

        # Update description during processing
        progress, task = create_progress_simple(100, "[cyan]Starting...")
        with progress:
            for i in range(100):
                progress.update(task, description=f"[cyan]Processing {i+1}/100...")
                work()
                progress.advance(task)
    """
    console = _state._get_console()

    progress = Progress(
        SpinnerColumn(spinner_name="dots", style=ADSCAN_PRIMARY),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=ADSCAN_PRIMARY, finished_style="green"),
        TaskProgressColumn(),
        console=console,
        expand=False,
    )

    # Create task (must be done before entering context)
    task_id = progress.add_task(description, total=total)

    return progress, task_id


def create_status_simple(message: str) -> Status:
    """Create a simple status spinner (convenience wrapper).

    This is a simplified version of create_status() for quick spinner creation.

    Args:
        message: Status message to display (supports Rich markup)

    Returns:
        Status object ready to use with 'with' statement

    Examples:
        # Simple usage
        with create_status_simple("Loading..."):
            load_data()

        # Update message
        status = create_status_simple("Initializing...")
        with status:
            init()
            status.update("Processing...")
            process()
    """
    console = _state._get_console()
    return Status(
        message, console=console, spinner="dots", spinner_style=ADSCAN_PRIMARY
    )


class ScanProgressTracker:
    """Helper class to track and display scan progress in real-time.

    This class provides a clean API for managing multi-step scan workflows,
    automatically handling progress display, status updates, and final summaries.

    Example:
        tracker = ScanProgressTracker("Unauthenticated Scan", total_steps=3)

        tracker.start_step("SMB Scan")
        perform_smb_scan()
        tracker.complete_step()

        tracker.start_step("LDAP Enumeration")
        perform_ldap_enum()
        tracker.complete_step()

        tracker.start_step("Kerberos User Enum")
        perform_kerberos_enum()
        tracker.complete_step()

        tracker.print_summary({"hosts_found": 15, "users_enumerated": 150})
    """

    def __init__(
        self,
        workflow_name: str,
        total_steps: int,
        phase_number: Optional[int] = None,
        total_phases: Optional[int] = None,
    ):
        """Initialize scan progress tracker.

        Args:
            workflow_name: Name of the workflow/scan
            total_steps: Total number of steps in this workflow
            phase_number: Current phase number (optional)
            total_phases: Total number of phases (optional)
        """
        self.workflow_name = workflow_name
        self.total_steps = total_steps
        self.phase_number = phase_number
        self.total_phases = total_phases

        self.current_step = 0
        self.completed_steps = 0
        self.failed_steps = 0
        self.skipped_steps = 0

        self.current_step_name: Optional[str] = None
        self.start_time = None
        self.step_start_time = None

    def start(self, details: Optional[Dict[str, str]] = None) -> None:
        """Start the workflow and display phase header.

        Args:
            details: Optional details to display in phase header
        """
        import time

        # Use monotonic clock so workflow durations are robust to system
        # clock adjustments during long-running operations.
        self.start_time = time.monotonic()

        print_phase_header(
            self.workflow_name,
            phase_number=self.phase_number,
            total_phases=self.total_phases,
            details=details,
        )

    def start_step(self, step_name: str, details: Optional[str] = None) -> None:
        """Start a new step in the workflow.

        Args:
            step_name: Name of the step
            details: Optional details about the step
        """
        import time

        self.current_step += 1
        self.current_step_name = step_name
        # Use monotonic clock to keep step timing stable even if system
        # clock changes between steps.
        self.step_start_time = time.monotonic()

        print_step_status(
            step_name,
            status="running",
            step_number=self.current_step,
            total_steps=self.total_steps,
            details=details,
        )

    def complete_step(self, details: Optional[str] = None) -> None:
        """Mark current step as completed.

        Args:
            details: Optional completion details
        """
        if self.current_step_name:
            self.completed_steps += 1
            print_step_status(
                self.current_step_name,
                status="completed",
                step_number=self.current_step,
                total_steps=self.total_steps,
                details=details,
            )
            self.current_step_name = None

    def fail_step(self, details: Optional[str] = None) -> None:
        """Mark current step as failed.

        Args:
            details: Optional failure details
        """
        if self.current_step_name:
            self.failed_steps += 1
            print_step_status(
                self.current_step_name,
                status="failed",
                step_number=self.current_step,
                total_steps=self.total_steps,
                details=details,
            )
            self.current_step_name = None

    def skip_step(self, step_name: str, details: Optional[str] = None) -> None:
        """Skip a step in the workflow.

        Args:
            step_name: Name of the step to skip
            details: Optional reason for skipping
        """
        self.current_step += 1
        self.skipped_steps += 1
        print_step_status(
            step_name,
            status="skipped",
            step_number=self.current_step,
            total_steps=self.total_steps,
            details=details,
        )

    def print_summary(
        self, additional_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """Print final workflow summary.

        Args:
            additional_results: Optional additional results to include in summary
        """
        import time

        # Lazy import to avoid circular dependency with adscan_core.rich_output
        from adscan_core.output._scan import print_workflow_summary

        duration = (
            time.monotonic() - self.start_time if self.start_time is not None else 0
        )

        # Determine overall status
        if self.failed_steps > 0:
            status = "Partial" if self.completed_steps > 0 else "Failed"
        elif self.completed_steps == self.total_steps:
            status = "Success"
        else:
            status = "Partial"

        # Build results dict
        results = {
            "status": status,
            "steps_completed": self.completed_steps,
            "steps_total": self.total_steps,
            "duration": duration,
        }

        # Add step breakdown if there were failures or skips
        if self.failed_steps > 0:
            results["steps_failed"] = self.failed_steps
        if self.skipped_steps > 0:
            results["steps_skipped"] = self.skipped_steps

        # Merge additional results
        if additional_results:
            results.update(additional_results)

        print_workflow_summary(self.workflow_name, results)
