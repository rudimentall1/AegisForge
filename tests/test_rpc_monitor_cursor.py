from shared.task_queue import TaskQueue
from agents.rpc_monitor import load_or_initialize_cursor, save_cursor


def test_rpc_monitor_cursor_survives_process_restart(tmp_path):
    db_path = tmp_path / "agent_farm.db"
    first_queue = TaskQueue(db_path)
    try:
        assert load_or_initialize_cursor(first_queue, "base", 100) == 99
        save_cursor(first_queue, "base", 100)
    finally:
        first_queue.db.close()

    restarted_queue = TaskQueue(db_path)
    try:
        # A restart must resume from the durable cursor, not jump to the new tip.
        assert load_or_initialize_cursor(restarted_queue, "base", 150) == 100
    finally:
        restarted_queue.db.close()


def test_rpc_monitor_cursor_initializes_at_tip_without_historical_backfill(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    try:
        assert load_or_initialize_cursor(queue, "arbitrum", 0) == 0
        row = queue.db.execute(
            "SELECT last_processed_block FROM rpc_monitor_cursors WHERE chain = ?",
            ("arbitrum",),
        ).fetchone()
        assert row == (0,)
    finally:
        queue.db.close()
