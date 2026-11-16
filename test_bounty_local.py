from agents.worker import analyze_contract_for_bounty

# Пример простой уязвимости (Reentrancy / Внешний вызов до обновления баланса)
mock_vulnerable_solidity = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        
        // Уязвимость: пересылка эфира до списания баланса (Reentrancy)
        (bool sent, ) = msg.call{value: _amount}("");
        require(sent, "Failed to send Ether");
        
        balances[msg.sender] -= _amount;
    }
}
"""

if __name__ == "__main__":
    print("[*] Запуск локального теста Red Team агента...")
    token_addr = "0xMockVulnerableVault123456789"
    
    result = analyze_contract_for_bounty(mock_vulnerable_solidity, token_addr)
    
    print("\n[+] Результат анализа от воркера:")
    for key, value in result.items():
        print(f"  -> {key}: {value}")
