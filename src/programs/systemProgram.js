class SystemProgram {
  static createAccount(initialBalance) {
    return {
      publicKey: '0x' + Math.random().toString(36).substring(2, 12),
      balance: initialBalance,
    };
  }

  static transfer(fromAccount, toAccount, amount) {
    if (fromAccount.balance >= amount) {
      fromAccount.balance -= amount;
      toAccount.balance += amount;
      return true;
    }
    return false; // Insufficient balance
  }
}
