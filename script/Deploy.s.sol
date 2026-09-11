// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {ProbeMarket} from "../src/ProbeMarket.sol";

contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        // Demo-friendly windows; production would use e.g. 24h / 1h.
        uint256 revealWindow = vm.envOr("REVEAL_WINDOW", uint256(10 minutes));
        uint256 disputeWindow = vm.envOr("DISPUTE_WINDOW", uint256(3 minutes));
        vm.startBroadcast(pk);
        ProbeMarket m = new ProbeMarket(vm.addr(pk), revealWindow, disputeWindow);
        vm.stopBroadcast();
        console.log("ProbeMarket deployed at:", address(m));
        console.log("resolver:", vm.addr(pk));
    }
}
