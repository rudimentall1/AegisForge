import json
import os

# Примеры контрактов для проверки по разным сетям (включая Base, Optimism, Arbitrum, Arc, Robin)
targets = [
    {"chain": "42161", "address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "name": "WETH Arbitrum"},
    {"chain": "8453", "address": "0x4200000000000000000000000000000000000006", "name": "WETH Base"},
    {"chain": "10", "address": "0x4200000000000000000000000000000000000006", "name": "WETH Optimism"},
    {"chain": "1", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "name": "WETH Ethereum"}
]

os.makedirs("queue", exist_ok=True)
for t in targets:
    filename = f"queue/{t['chain']}_{t['address']}.json"
    with open(filename, "w") as f:
        json.dump(t, f, indent=2)
    print(f"[TARGET ADDED] {t['name']} ({t['chain']}) -> {filename}")

