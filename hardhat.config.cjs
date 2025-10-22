require("@nomicfoundation/hardhat-toolbox");

require('dotenv').config();
require("@nomiclabs/hardhat-ethers");

const { API_URL, PRIVATE_KEY } = process.env;

module.exports = {
   solidity: "0.8.28",
   defaultNetwork: "localhost",
   networks: {
      hardhat: {},
      // Local Ganache
    localhost: {
      url: API_URL,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : []
    }
   },
}