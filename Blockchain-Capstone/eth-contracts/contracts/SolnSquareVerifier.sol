pragma solidity >=0.4.21 <0.6.0;

// TODO define a contract call to the zokrates generated solidity contract <Verifier> or <renamedVerifier>
import "./ERC721Mintable.sol";
import "./Verifier.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";

// TODO define another contract named SolnSquareVerifier that inherits from your ERC721Mintable class

// TODO define a solutions struct that can hold an index & an address

// TODO define an array of the above struct

// TODO define a mapping to store unique solutions submitted

// TODO Create an event to emit when a solution is added

// TODO Create a function to add the solutions to the array and emit the event

// TODO Create a function to mint new NFT only after the solution has been verified
//  - make sure the solution is unique (has not been used before)
//  - make sure you handle metadata as well as tokenSuplly

contract SolnSquareVerifier is ERC721Mintable, Verifier {

    struct Solution {
        bool isUsed;
        address verifierAddress;
    }
    uint256 solutionCount = 0;
    mapping(bytes32 => Solution) private uniqueSolutions;

    event SolutionAdded(bytes32 key, address verifierAddress);

    function addSolution(bytes32 solutionKey, address verifierAddress) internal {
        require(!uniqueSolutions[solutionKey].isUsed, "Solution is not unique");
        solutionCount = solutionCount.add(1);
        uniqueSolutions[solutionKey].isUsed = true;
        uniqueSolutions[solutionKey].verifierAddress = verifierAddress;
        emit SolutionAdded(solutionKey, verifierAddress);
    }

    function mintVerify
    (
        address to,
        uint256 tokenId,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory inputs
    ) public {
        bytes32 key = keccak256(abi.encodePacked(a, b, c, inputs));
        require(!uniqueSolutions[key].isUsed, "Solution is not unique");
        require(verifyTx(a, b, c, inputs), "Proof is not valid");
        addSolution(key, msg.sender);
        super.mint(to, tokenId);
    }
}