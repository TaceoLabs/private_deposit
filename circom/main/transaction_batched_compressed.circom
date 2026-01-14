pragma circom 2.2.2;

include "transactions.circom";

component main {public [alpha]} = TransactionBatchedCompressed(50,  16); // The second parameter is the state size for the sponge in the compression part
