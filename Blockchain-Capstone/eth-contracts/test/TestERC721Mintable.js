var ERC721MintableComplete = artifacts.require('ERC721MintableComplete');

contract('TestERC721Mintable', accounts => {

    const account_one = accounts[0];
    const account_two = accounts[1];

    describe('match erc721 spec', function () {
        beforeEach(async function () {
            this.contract = await ERC721MintableComplete.new({ from: account_one });

            // TODO: mint multiple tokens
        })

        it('should return total supply', async function () {
            let totalSupply = await this.contract.totalSupply.call({ from: owner });
            assert.equal(numOriginalTokens, totalSupply, "Total supply does not match");

        })

        it('should get token balance', async function () {
            let tokenBalance = await this.contract.balanceOf.call(accountOne);
            assert.equal(numOriginalTokens, tokenBalance, "Token balance does not match");

        })

        // token uri should be complete i.e: https://s3-us-west-2.amazonaws.com/udacity-blockchain/capstone/1
        it('should return token uri', async function () {
            let tokenURI = await this.contract.tokenURI.call(1);
            assert.equal("https://s3-us-west-2.amazonaws.com/udacity-blockchain/capstone/1", tokenURI, "Token URI does not match");

        })

        it('should transfer token from one owner to another', async function () {
            await this.contract.transferFrom(accountOne, accounts[2], 1, { from: accountOne });
            let tokenOwner = await this.contract.ownerOf.call(1);
            assert.equal(accounts[2], tokenOwner, 'Token owner does not match');

        })
    });

    describe('have ownership properties', function () {
        beforeEach(async function () {
            this.contract = await ERC721MintableComplete.new({ from: account_one });
        })

        it('should fail when minting when address is not contract owner', async function () {
            let result = true;
            try {
                await this.contract.mint(accountOne, 1, { from: accountOne });
            } catch (e) {
                result = false;
            }
            assert.equal(result, false, "Non-owner able to mint coins");

        })

        it('should return contract owner', async function () {
            let contractOwner = await this.contract.getOwner.call();
            assert.equal(owner, contractOwner, "Owner does not match contract owner");
        })

    });
})