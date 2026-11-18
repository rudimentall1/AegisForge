import os
from dotenv import load_dotenv

# Загружаем переменные из .env (включая OPENROUTER_API_KEY и TELEGRAM_TOKENS)
load_dotenv()

# Пример уязвимого контракта для боевой проверки Claude 3.5 Sonnet
mock_vulnerable_solidity = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Уязвимость: внешний вызов до обновления стейта баланса
        (bool success, ) = msg.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}
"""

if __name__ == "__main__":
    # Manual smoke script: keep runtime-only worker imports out of pytest collection.
    from agents.worker import analyze_contract_for_bounty
    print("[*] Инициализация боевого теста OpenRouter API (Claude 3.5 Sonnet)...")
    target_address = "0xLiveTestReentrancyBank999"
    
    result = analyze_contract_for_bounty(mock_vulnerable_solidity, target_address)
    
    print("\n[+] Статус выполнения:", result.get("status"))
    print("[+] Цель:", result.get("target"))
    print("\n[+] Отчет Red Team от Claude 3.5 Sonnet:\n")
    print(result.get("report", "Нет отчета"))
