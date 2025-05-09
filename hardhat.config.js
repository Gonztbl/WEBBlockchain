require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks: {
    ganache: {
      url: "http://127.0.0.1:8545",
      chainId: 1337,
      accounts: ['0xa55320d8584fca72c0e91e4c2f7e739195003afe7c18458b3bf378e1849daf58']
      //accounts: ['0xe24d891a35b5df521622a679820f4bbc7d95f98181fc61ec5af04ca8bd70c379']
      //accounts: ['0x640966b17354e322d405854a22c472512d9fb2938abe518589318203a9123ec2']
    }
  },
  solidity: "0.8.28",
};
