pragma circom 2.2.2;

include "transactions.circom";

component main {public [alpha]} = TransactionBatchedCompressed(50, 16);
