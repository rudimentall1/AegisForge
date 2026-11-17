from shared.task_queue import TaskQueue

q = TaskQueue()

targets = [
    {"chain": "arbitrum", "address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "name": "WETH Arbitrum"},
    {"chain": "base", "address": "0x4200000000000000000000000000000000000006", "name": "WETH Base"},
    {"chain": "optimism", "address": "0x4200000000000000000000000000000000000006", "name": "WETH Optimism"},
    {"chain": "ethereum", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "name": "WETH Ethereum"},
    {"chain": "bsc", "address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "name": "WETH BSC"}
]

for t in targets:
    desc = f"Audit contract {t['address']} on chain {t['chain']} ({t['name']})"
    task_id = q.add(
        description=desc,
        role="security_checker",
        contract_address=t['address']
    )
    print(f"[ENQUEUED] Task #{task_id} -> {desc} [Contract: {t['address']}]")
