// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../../src/priv_balance.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    address bob = address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC);

    uint256 amount = 1 ether;
    uint256 amount_commitment =
        15593109598059662780184338689081921601599342431766556349154126622647806139894;

    // For a transfer action
    // Sender Public Key
    PrivateBalance.BabyJubJubElement sender_key =
        PrivateBalance.BabyJubJubElement(
            14126526673002152226685028859637341993398518531603040589075929701947081008152,
            2262429687539372424558773003960644901192543279316913065087518967280725694787
        );

    // Ciphertext components
    uint256 amount0 =
        4905774193859250633367103010011164286351164406878957297441473790037983418652;
    uint256 r0 =
        21386148726158425328415803708635161530955724864871919339801760063789425854042;
    uint256 amount1 =
        20287032784938589294727054070772132499956033880369988115096570893732088478341;
    uint256 r1 =
        2517106720126313632299138440935051367221304808062364863107679786545605031704;
    uint256 amount2 =
        9318907414941246766382086462820299264561576095244169207256108475923746065863;
    uint256 r2 =
        19408893814710241131916645829673431006471358670475695934923536001569549968187;

    PrivateBalance.Ciphertext ciphertext =
        PrivateBalance.Ciphertext(
            [amount0, amount1, amount2],
            [r0, r1, r2],
            sender_key
        );

    function setUp() public {
        address priv_balance_address = vm.envAddress("PRIV_BALANCE_ADDRESS");
        priv_balance = PrivateBalance(priv_balance_address);
    }

    function run() public {
        vm.startBroadcast();
        uint256 index = priv_balance.transfer(
            bob,
            amount_commitment,
            ciphertext
        );
        vm.stopBroadcast();

        console.log("Transfer registered at index", index);
    }
}
