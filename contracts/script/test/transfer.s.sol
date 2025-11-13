// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;

    uint256 amount = 1 ether;
    uint256 amount_commitment = 6122001814780532967242228952635820560915594353320782112285831468616175141938;

    // For a transfer action
    // Sender Public Key
    ConfidentialToken.BabyJubJubElement sender_key = ConfidentialToken.BabyJubJubElement(
        14126526673002152226685028859637341993398518531603040589075929701947081008152,
        2262429687539372424558773003960644901192543279316913065087518967280725694787
    );

    // Ciphertext components
    uint256 amount0 = 4905774193859250633367103010011164286351164406878957297441473790037983418652;
    uint256 r0 = 21386148726158425328415803708635161530955724864871919339801760063789425854042;
    uint256 amount1 = 20287032784938589294727054070772132499956033880369988115096570893732088478341;
    uint256 r1 = 2517106720126313632299138440935051367221304808062364863107679786545605031704;
    uint256 amount2 = 9318907414941246766382086462820299264561576095244169207256108475923746065863;
    uint256 r2 = 19408893814710241131916645829673431006471358670475695934923536001569549968187;

    ConfidentialToken.Ciphertext ciphertext =
        ConfidentialToken.Ciphertext([amount0, amount1, amount2], [r0, r1, r2], sender_key);

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialToken(conf_token_address);
    }

    function run() public {
        address bob = vm.envAddress("BOB_ADDRESS");

        vm.startBroadcast();
        uint256 index = conf_token.transfer(bob, amount_commitment, ciphertext);
        vm.stopBroadcast();

        console.log("Transfer registered at index", index);
    }
}
