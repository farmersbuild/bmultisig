/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const walletUtils = require('./util/wallet');
const testUtils = require('./util/utils');
const {forEvent} = testUtils;
const CosignerCtx = require('./util/cosigner-context');
const Script = require('bcash/lib/script/script');
const KeyRing = require('bcash/lib/primitives/keyring');
const MTX = require('bcash/lib/primitives/mtx');
const Amount = require('bcash/lib/btc/amount');
const WalletDB = require('bcash/lib/wallet/walletdb');
const WalletNodeClient = require('../lib/walletclient');
const MultisigDB = require('../lib/multisigdb');
const Proposal = require('../lib/primitives/proposal');

const {CREATE, REJECT} = Proposal.payloadType;

const TEST_WALLET_ID = 'test1';
const TEST_WALLET_ID2 = 'test2';

describe(`MultisigProposals`, function () {
  // 2-of-2 will be used for tests
  let wdb, msdb;

  let mswallet;
  let wallet, pdb; // 2-of-2

  const cosignerCtx1 = new CosignerCtx({
    walletName: TEST_WALLET_ID,
    name: 'cosigner1'
  });
  const cosignerCtx2 = new CosignerCtx({
    walletName: TEST_WALLET_ID,
    name: 'cosigner2',
    joinPrivKey: cosignerCtx1.joinPrivKey
  });
  const cosignerCtx3 = new CosignerCtx({
    walletName: TEST_WALLET_ID,
    name: 'cosigner3',
    joinPrivKey: cosignerCtx1.joinPrivKey
  });

  const cosignerCtxs = [cosignerCtx1, cosignerCtx2, cosignerCtx3];

  const [priv1, priv2, priv3] = [
    cosignerCtx1.accountPrivKey,
    cosignerCtx2.accountPrivKey,
    cosignerCtx3.accountPrivKey
  ];

  const xpubs = [
    cosignerCtx1.accountKey,
    cosignerCtx2.accountKey,
    cosignerCtx3.accountKey
  ];

  const [xpub1, xpub2, xpub3] = xpubs;

  let cosigner1, cosigner2;

  beforeEach(async () => {
    wdb = new WalletDB({ });

    const wdbClient = new WalletNodeClient({ wdb });

    msdb = new MultisigDB({
      client: wdbClient
    });

    wdb.on('error', () => {});
    msdb.on('error', () => {});

    msdb.init();

    await wdb.open();
    await msdb.open();

    cosigner1 = cosignerCtx1.toCosigner();
    cosigner2 = cosignerCtx2.toCosigner();

    mswallet = await mkWallet(msdb, TEST_WALLET_ID, 2, 2,
      [
      cosignerCtx1,
      cosignerCtx2
      ]);

    wallet = mswallet.wallet;
    pdb = mswallet.pdb;
  });

  afterEach(async () => {
    await wdb.close();
    await msdb.close();
  });

  it('should create pdb with wallet', async () => {
    assert.strictEqual(mswallet.isInitialized(), true,
      'Wallet was not initalized');
    assert(mswallet, 'Multisig wallet not found');
    assert(pdb, 'ProposalsDB not found');
  });

  it('should create transaction', async () => {
    await walletUtils.fundWalletBlock(wdb, mswallet, 1);
    await walletUtils.fundWalletBlock(wdb, mswallet, 1);

    const account = await mswallet.getAccount();
    const address = account.receiveAddress();

    const txoptions = {
      subtractFee: true,
      outputs: [{
        address: address,
        value: Amount.fromBTC(2).toValue()
      }]
    };

    const tx = await mswallet.createTX(txoptions);

    assert.ok(tx instanceof MTX);
    assert.strictEqual(tx.isSane(), true);
  });

  describe('Approve proposal', function() {
    it('should approve proposal', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const pending = await mswallet.getPendingProposals();
      assert.strictEqual(pending.length, 0);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 2, 'proposal1');
      const sigs = await signProposal(
        mswallet,
        proposal,
        cosignerCtxs,
        cosignerCtx1
      );

      assert.strictEqual(sigs.length, 2, 'Wrong number of signatures.');

      let err;

      try {
        // bad sigs
        const sigs = [
          Buffer.alloc(32, 0),
          Buffer.alloc(32, 0)
        ];

        await mswallet.approveProposal(
          proposal.id,
          cosigner1,
          sigs
        );
      } catch (e) {
        err = e;
      }

      assert(err);
      assert.strictEqual(err.message, 'Signature(s) incorrect.');

      err = null;
      try {
        // bad cosigner
        await mswallet.approveProposal(
          proposal.id,
          cosigner2,
          sigs
        );
      } catch (e) {
        err = e;
      }

      assert(err);
      assert(err.message, 'Signature(s) incorrect.');

      const approved = await mswallet.approveProposal(
        proposal.id,
        cosigner1,
        sigs
      );

      assert.strictEqual(approved.approvals.size, 1);
      assert.strictEqual(approved.approvals.has(cosigner1.id), true);

      // approve by second cosigner
      const sigs2 = await signProposal(
        mswallet,
        proposal,
        cosignerCtxs,
        cosignerCtx2
      );

      const approved2 = await mswallet.approveProposal(
        proposal.id,
        cosigner2,
        sigs2
      );

      const pmtx = await mswallet.getProposalMTX(proposal.id);
      assert(pmtx.verify());

      assert.strictEqual(approved2.approvals.size, 2);
      assert.strictEqual(approved2.approvals.has(cosigner1.id), true);
      assert.strictEqual(approved2.approvals.has(cosigner2.id), true);
    });

    it('should approve proposal (2-of-3)', async () => {
      const mswallet2 = await mkWallet(msdb, TEST_WALLET_ID2, 2, 3,
        [
        cosignerCtx1,
        cosignerCtx2,
        cosignerCtx3
        ]);

      const cosigner2 = cosignerCtx2.toCosigner();
      const cosigner3 = cosignerCtx3.toCosigner();

      await walletUtils.fundWalletBlock(wdb, mswallet2, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet2, 1);

      const pending = await mswallet2.getPendingProposals();
      assert.strictEqual(pending.length, 0);

      const proposal = await mkProposal(
        mswallet2,
        cosignerCtx1,
        2,
        'proposal1'
      );

      const mtx = await mswallet2.getProposalMTX(proposal.id);
      const paths = await mswallet2.getInputPaths(mtx);

      const xpubs = [xpub1, xpub2, xpub3];

      { // cosigner2
        const rings = testUtils.getMTXRings(
          mtx, paths, priv2, xpubs, 2
        );

        const sigs = testUtils.getMTXSignatures(mtx, rings);

        assert.strictEqual(sigs.length, 2);

        const approved = await mswallet2.approveProposal(
          proposal.id,
          cosigner2,
          sigs
        );

        assert.strictEqual(approved.approvals.size, 1);
        assert.strictEqual(approved.approvals.has(cosigner2.id), true);
      }

      { // cosigner3
        const rings = testUtils.getMTXRings(
          mtx, paths, priv3, xpubs, 2
        );
        const sigs = testUtils.getMTXSignatures(mtx, rings);
        assert.strictEqual(sigs.length, 2);

        const approved = await mswallet2.approveProposal(
          proposal.id,
          cosigner3,
          sigs
        );

        const pmtx = await mswallet2.getProposalMTX(proposal.id);
        assert(pmtx.verify(), 'Transaction is not valid.');

        assert.strictEqual(approved.approvals.size, 2);
        assert.strictEqual(approved.approvals.has(cosigner3.id), true);
      }
    });

    it('should approve signed proposal', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const p1 = await mkProposal(mswallet, cosignerCtx1, 1);

      const pending = await mswallet.getPendingProposals();
      assert.strictEqual(pending.length, 1);

      const approve = async (priv, cosigner) => {
        const mtx = await mswallet.getProposalMTX(p1.id);
        const paths = await mswallet.getInputPaths(mtx);

        const rings = testUtils.getMTXRings(
          mtx, paths, priv, [xpub1, xpub2], 2
        );
        const signatures = testUtils.getMTXSignatures(mtx, rings);

        // approve proposal
        await mswallet.approveProposal(p1.id, cosigner, signatures);
      };

      await approve(priv1, cosigner1);
      await approve(priv2, cosigner2);

      const pmtx = await mswallet.getProposalMTX(p1.id);
      assert(pmtx.verify());
    });

    it('should fail approving proposal twice', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal1 = await mkProposal(mswallet, cosignerCtx1, 1);
      await mkProposal(mswallet, cosignerCtx1, 1);

      const pendingProposals = await mswallet.getPendingProposals();
      assert.strictEqual(pendingProposals.length, 2);

      const mtx = await mswallet.getProposalMTX(proposal1.id);
      const paths = await mswallet.getInputPaths(mtx);

      const rings = testUtils.getMTXRings(
        mtx, paths, priv1, [xpub1, xpub2], 2
      );
      const signatures = testUtils.getMTXSignatures(mtx, rings);

      await mswallet.approveProposal(
        proposal1.id,
        cosigner1,
        signatures
      );

      let err;

      try {
        await mswallet.approveProposal(proposal1.id, cosigner1, signatures);
      } catch (e) {
        err = e;
      }

      assert.ok(err instanceof Error);
      assert.strictEqual(err.message, 'Cosigner already approved.');
    });
  });

  describe('Reject proposal', function() {
    it('should reject proposal', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const p1 = await mkProposal(mswallet, cosignerCtx1, 1);

      await mkProposal(mswallet, cosignerCtx1, 1);
      await mkProposal(mswallet, cosignerCtx1, 1);

      const pendingProposals = await mswallet.getPendingProposals();

      assert.strictEqual(pendingProposals.length, 3);

      const signature = cosignerCtx1.signProposal(REJECT, p1.options);
      const proposal1 = await mswallet.rejectProposal(
        p1.id,
        cosigner1,
        signature
      );

      assert.strictEqual(proposal1.status, Proposal.status.REJECTED);

      const pendingProposals2 = await mswallet.getPendingProposals();
      assert.strictEqual(pendingProposals2.length, 2);

      const proposal2 = await mkProposal(mswallet, cosignerCtx1, 1);
      assert.ok(proposal2 instanceof Proposal);
    });

    it('should fail rejecting rejected proposal', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const p1 = await mkProposal(mswallet, cosignerCtx1, 1);

      const signature = cosignerCtx1.signProposal(REJECT, p1.options);
      await mswallet.rejectProposal(p1.id, cosigner1, signature);

      let err;
      try {
        const signature = cosignerCtx2.signProposal(REJECT, p1.options);

        await mswallet.rejectProposal(p1.id, cosigner2, signature);
      } catch (e) {
        err = e;
      }

      assert.ok(err instanceof Error);
      assert.strictEqual(err.message, 'Can not reject non pending proposal.');
    });
  });

  describe('Get proposal information', function() {
    it('should get proposal by coin', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const coins = await wallet.getCoins();

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);
      assert.ok(proposal instanceof Proposal);

      const pid = await mswallet.getPIDByOutpoint(coins[0]);
      const proposal2 = await mswallet.getProposalByOutpoint(coins[0]);

      assert.strictEqual(proposal.id, pid);
      assert(proposal.equals(proposal2));
    });

    it('should get proposal', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal1 = await mkProposal(mswallet, cosignerCtx1, 1);
      assert.ok(proposal1 instanceof Proposal);

      const proposal2 = await mswallet.getProposal(proposal1.id);
      assert.ok(proposal2 instanceof Proposal);
      assert.deepStrictEqual(proposal1, proposal2);
    });

    it('should fail getting non-existent proposal', async () => {
      const proposal = await mswallet.getProposal(999);
      assert.ok(proposal === null);
    });

    it('should get proposal mtx', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 2);

      const {id} = await mkProposal(mswallet, cosignerCtx1, 3);
      const proposal = await mswallet.getProposal(id);
      const mtx = await mswallet.getProposalMTX(id);

      assert.ok(proposal instanceof Proposal);
      assert.ok(mtx instanceof MTX);

      const inputPaths = await mswallet.getInputPaths(mtx);

      assert.strictEqual(inputPaths.length, 2);
    });
  });

  describe('Coin spends', function() {
    it('should reject proposal on mempool double spend', async () => {
      const amount = Amount.fromBTC(1).toValue();
      const account = await mswallet.getAccount();
      const mtx = walletUtils.createFundTX(account.receiveAddress(), amount);

      await wdb.addTX(mtx.toTX());

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      const dstx = walletUtils.getDoubleSpendTransaction(mtx);

      await wdb.addTX(dstx.toTX());

      const checkProposal = await mswallet.getProposal(proposal.id);

      assert.ok(checkProposal instanceof Proposal);
      assert.strictEqual(checkProposal.status, Proposal.status.DBLSPEND);
    });

    it('should reject proposal on coin spend', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      const mtx = await mswallet.getProposalMTX(proposal.id);
      const paths = await mswallet.getInputPaths(mtx);

      const sign = async (priv) => {
        mtx.inputs.forEach((_, i) => {
          const path = paths[i];

          // derive correct priv key
          const _priv = priv.derive(path.branch).derive(path.index);

          // derive pubkeys
          const p1 = xpub1.derive(path.branch).derive(path.index);
          const p2 = xpub2.derive(path.branch).derive(path.index);

          const ring = KeyRing.fromPrivate(_priv.privateKey);

          ring.script = Script.fromMultisig(
            proposal.m,
            proposal.n,
            [p1.publicKey, p2.publicKey]
          );

          const signed = mtx.sign(ring);

          assert.strictEqual(signed, 1);
        });
      };

      sign(priv1);
      sign(priv2);

      await wdb.addBlock(walletUtils.nextBlock(wdb), [mtx.toTX()]);

      const checkProposal = await mswallet.getProposal(proposal.id);

      assert.ok(checkProposal instanceof Proposal);
      assert.strictEqual(checkProposal.status, Proposal.status.DBLSPEND);
    });

    it('should reject proposal on reorg double spend', async () => {
      const mtx = await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);
      assert.ok(proposal instanceof Proposal);

      const rejectEvent = forEvent(mswallet, 'proposal rejected', 2000);

      await walletUtils.removeBlock(wdb);
      await walletUtils.doubleSpendTransaction(wdb, mtx.toTX());

      await rejectEvent;

      const checkProposal = await mswallet.getProposal(proposal.id);

      assert.ok(checkProposal instanceof Proposal);
      assert.strictEqual(checkProposal.status, Proposal.status.DBLSPEND);
    });
  });

  describe('Force reject proposal', function() {
    let proposal;

    beforeEach(async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      proposal = await mkProposal(mswallet, cosignerCtx1, 1);
    });

    it('should force reject proposal', async () => {
      const pid = proposal.id;
      const rejectedProposal = await mswallet.forceRejectProposal(pid);

      assert(rejectedProposal);
      assert(rejectedProposal.status === Proposal.status.FORCE);

      // we should be able to create new proposal
      const p2 = await mkProposal(mswallet, cosignerCtx1, 1);

      assert(p2);
    });

    it('should fail rejecting rejected proposal', async () => {
      const signature = cosignerCtx1.signProposal(REJECT, proposal.options);
      await mswallet.rejectProposal(proposal.id, cosigner1, signature);

      const pid = proposal.id;

      await assert.rejects(async () => {
        await mswallet.forceRejectProposal(pid);
      }, {
        message: 'Proposal is not pending.'
      });
    });
  });

  describe('Coin lock/unlock', function() {
    const checkLockedStatus = async (coin, options) => {
      const smartCoins = await mswallet.getSmartCoins();
      assert.strictEqual(smartCoins.length, options.smartCoins);

      const locked = await mswallet.getLocked(false);
      assert.strictEqual(locked.length, options.locked);

      const lockedProposal = await mswallet.getLocked(true);
      assert.strictEqual(lockedProposal.length, options.lockedProposal);

      const isLockedTXDB = mswallet.isLockedTXDB(coin);
      assert.strictEqual(isLockedTXDB, options.isLockedTXDB);

      const isLocked = await mswallet.isLocked(coin);
      assert.strictEqual(isLocked, options.isLocked);
    };

    beforeEach(async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
    });

    it('should lock the coins on proposal creation', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const coins = await wallet.getCoins();
      assert.strictEqual(coins.length, 3);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 3);
      assert.ok(proposal instanceof Proposal);

      let err;
      try {
        await mkProposal(mswallet, cosignerCtx2, 3);
      } catch (e) {
        err = e;
      }

      const message = 'Not enough funds. (available=0.0, required=3.0)';
      assert(err);
      assert.strictEqual(err.message, message);
    });

    it('should recover coins on rejection', async () => {
      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      assert.ok(proposal instanceof Proposal);

      const coins = await mswallet.getProposalOutpoints(proposal.id);

      const signature = cosignerCtx1.signProposal(REJECT, proposal.options);

      const rejected = await mswallet.rejectProposal(
        proposal.id,
        cosigner1,
        signature
      );

      const coin = coins[0];
      const pidByOutpoint = await mswallet.getPIDByOutpoint(coin);

      assert.strictEqual(rejected.status, Proposal.status.REJECTED);
      assert.strictEqual(pidByOutpoint, -1);
    });

    it('should unlock coins on approval', async () => {
      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      assert.ok(proposal instanceof Proposal);

      const coins = await mswallet.getProposalOutpoints(proposal.id);

      const sigs = await Promise.all([cosignerCtx1, cosignerCtx2].map((ctx) => {
        return signProposal(
          mswallet,
          proposal,
          cosignerCtxs,
          ctx
        );
      }));

      await mswallet.approveProposal(
        proposal.id,
        cosigner1,
        sigs[0]
      );

      const approved = await mswallet.approveProposal(
        proposal.id,
        cosigner2,
        sigs[1]
      );

      assert.strictEqual(approved.isApproved(), true);

      // WDB does not have tx yet.
      const coin = coins[0];

      {
        const pidByOutpoint = await mswallet.getPIDByOutpoint(coin);
        const locked = wallet.getLocked();

        assert(pidByOutpoint > -1);
        assert(locked.length > 0);
      }

      const tx = await mswallet.getProposalTX(proposal.id);
      await wdb.addTX(tx);

      await forEvent(mswallet, 'unlocked coin', 2000);
      await sleep(100);

      {
        const pidByOutpoint = await mswallet.getPIDByOutpoint(coin);
        const locked = wallet.getLocked();

        assert.strictEqual(locked.length, 0);
        assert.strictEqual(pidByOutpoint, -1);
      }
    });

    it('should lock the coins after server restart', async () => {
      const coins = await wallet.getCoins();
      assert.strictEqual(coins.length, 1);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      assert.ok(proposal instanceof Proposal);

      await msdb.close();
      await wdb.close();

      await wdb.open();
      await msdb.open();

      mswallet = await msdb.getWallet(TEST_WALLET_ID);

      let err;
      try {
        await mkProposal(mswallet, cosignerCtx2, 1);
      } catch (e) {
        err = e;
      }

      const message = 'Not enough funds. (available=0.0, required=1.0)';
      assert(err, 'Create proposal must throw an error.');
      assert.strictEqual(err.message, message, 'Incorrect error message.');
    });

    it('should lock the coins and recover locked coins', async () => {
      // this is mostly wallet test than proposal
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const coins = await wallet.getCoins();
      assert.strictEqual(coins.length, 3);

      const [txoptions] = getTXOptions(3);

      // create proposal
      const mtx = await mswallet.createTX(txoptions);
      assert.ok(mtx instanceof MTX);

      for (const coin of coins)
        await mswallet.lockCoinTXDB(coin);

      let err;
      try {
        await mswallet.createTX(txoptions);
      } catch (e) {
        err = e;
      }

      const message = 'Not enough funds. (available=0.0, required=3.0)';
      assert(err);
      assert.strictEqual(err.message, message);

      for (const coin of coins)
        await mswallet.unlockCoinTXDB(coin);

      const mtx2 = await mswallet.createTX(txoptions);
      assert(mtx2 instanceof MTX);
    });

    it('should lock/unlock coin in TXDB', async () => {
      const coins = await mswallet.getSmartCoins();
      assert.strictEqual(coins.length, 1);
      const coin = coins[0];

      await checkLockedStatus(coin, {
        smartCoins: 1,
        locked: 0,
        lockedProposal: 0,
        isLockedTXDB: false,
        isLocked: false
      });

      // TXDB lock
      mswallet.lockCoinTXDB(coin);

      await checkLockedStatus(coin, {
        smartCoins: 0,
        locked: 1,
        lockedProposal: 0,
        isLockedTXDB: true,
        isLocked: false
      });

      // recover TXBD Lock.
      mswallet.unlockCoinTXDB(coin);

      await checkLockedStatus(coin, {
        smartCoins: 1,
        locked: 0,
        lockedProposal: 0,
        isLockedTXDB: false,
        isLocked: false
      });

      // mswallet unlock.
      mswallet.lockCoinTXDB(coin);

      await mswallet.unlockCoin(coin);

      await checkLockedStatus(coin, {
        smartCoins: 1,
        locked: 0,
        lockedProposal: 0,
        isLockedTXDB: false,
        isLocked: false
      });
    });

    it('should not unlock coin proposal coin', async () => {
      const coins = await mswallet.getSmartCoins();
      const coin = coins[0];
      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      assert.strictEqual(coins.length, 1);
      assert(proposal);

      await checkLockedStatus(coin, {
        smartCoins: 0,
        locked: 1,
        lockedProposal: 1,
        isLockedTXDB: true,
        isLocked: true
      });

      await assert.rejects(async () => {
        await mswallet.unlockCoin(coin);
      }, {
        message: 'Can not unlock coin locked by proposal.'
      });

      await mswallet.forceRejectProposal(proposal.id);

      const pid = await mswallet.getPIDByOutpoint(coin);
      assert.strictEqual(pid, -1);

      await checkLockedStatus(coin, {
        smartCoins: 1,
        locked: 0,
        lockedProposal: 0,
        isLockedTXDB: false,
        isLocked: false
      });
    });

    it('should force unlock coins', async () => {
      const coins = await mswallet.getSmartCoins();
      const coin = coins[0];
      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      assert.strictEqual(coins.length, 1);
      assert(proposal);

      await checkLockedStatus(coin, {
        smartCoins: 0,
        locked: 1,
        lockedProposal: 1,
        isLockedTXDB: true,
        isLocked: true
      });

      await mswallet.forceUnlockCoin(coin);

      await checkLockedStatus(coin, {
        smartCoins: 1,
        locked: 0,
        lockedProposal: 0,
        isLockedTXDB: false,
        isLocked: false
      });

      const rejectedProposal = await mswallet.getProposal(proposal.id);
      assert.strictEqual(rejectedProposal.status, Proposal.status.UNLOCK);
    });
  });

  describe('Proposal stats', function() {
    it('should get pending proposals stats', async () => {
      // 2 coins for one pending proposal
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      await mkProposal(mswallet, cosignerCtx1, 2);
      const stats = await mswallet.getStats();

      assert.deepStrictEqual(stats.toJSON(), {
        lockedOwnCoins: 2,
        lockedOwnBalance: 200000000,
        proposals: 1,
        pending: 1,
        rejected: 0,
        approved: 0
      });
    });

    it('should get approved proposal stats', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 2);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 2,
          lockedOwnBalance: 200000000,
          proposals: 1,
          pending: 1,
          rejected: 0,
          approved: 0
        });
      }

      const sigs = await Promise.all([cosignerCtx1, cosignerCtx2].map((ctx) => {
        return signProposal(
          mswallet,
          proposal,
          cosignerCtxs,
          ctx
        );
      }));

      await mswallet.approveProposal(
        proposal.id,
        cosigner1,
        sigs[0]
      );

      await mswallet.approveProposal(
        proposal.id,
        cosigner2,
        sigs[1]
      );

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 2,
          lockedOwnBalance: 200000000,
          proposals: 1,
          pending: 0,
          rejected: 0,
          approved: 1
        });
      }

      // now we broadcast the transaction
      const tx = await mswallet.getProposalTX(proposal.id);
      await wdb.addTX(tx);
      await sleep(100);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 0,
          lockedOwnBalance: 0,
          proposals: 1,
          pending: 0,
          rejected: 0,
          approved: 1
        });
      }
    });

    it('should get rejected proposal stats', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      await walletUtils.fundWalletBlock(wdb, mswallet, 2);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 2.1);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 2,
          lockedOwnBalance: 300000000,
          proposals: 1,
          pending: 1,
          approved: 0,
          rejected: 0
        });
      }

      const signature = cosignerCtx1.signProposal(
        REJECT,
        proposal.options
      );

      await mswallet.rejectProposal(
        proposal.id,
        cosigner1,
        signature
      );

      const stats = await mswallet.getStats();

      assert.deepStrictEqual(stats.toJSON(), {
        lockedOwnCoins: 0,
        lockedOwnBalance: 0,
        proposals: 1,
        pending: 0,
        approved: 0,
        rejected: 1
      });
    });

    it('should get force rejected proposal stats', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);

      const proposal = await mkProposal(mswallet, cosignerCtx1, 1);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 1,
          lockedOwnBalance: 100000000,
          proposals: 1,
          pending: 1,
          approved: 0,
          rejected: 0
        });
      }

      await mswallet.forceRejectProposal(proposal.id);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 0,
          lockedOwnBalance: 0,
          proposals: 1,
          pending: 0,
          approved: 0,
          rejected: 1
        });
      }
    });

    it('should get double spent proposal stats', async () => {
      await walletUtils.fundWalletBlock(wdb, mswallet, 1);
      const mtx = await walletUtils.fundWalletBlock(wdb, mswallet, 2);

      await mkProposal(mswallet, cosignerCtx1, 3);

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 2,
          lockedOwnBalance: 300000000,
          proposals: 1,
          pending: 1,
          approved: 0,
          rejected: 0
        });
      }

      const rejectEvent = forEvent(mswallet, 'proposal rejected', 2000);
      await walletUtils.removeBlock(wdb);
      await walletUtils.doubleSpendTransaction(wdb, mtx.toTX());
      await rejectEvent;

      {
        const stats = await mswallet.getStats();

        assert.deepStrictEqual(stats.toJSON(), {
          lockedOwnCoins: 0,
          lockedOwnBalance: 0,
          proposals: 1,
          pending: 0,
          approved: 0,
          rejected: 1
        });
      }
    });
  });
});

/*
 * Helpers
 */

/**
 * @param {MultisigDB} msdb
 * @param {String} walletName
 * @param {Number} m
 * @param {Number} n
 * @param {CosignerCtx[]} cosigners
 * @returns {MultisigWallet}
 */

async function mkWallet(msdb, walletName, m, n, cosignerCtxs = []) {
  const cosigners = cosignerCtxs.map((c) => {
    c.walletName = walletName;
    c.refresh();
    return c.toCosigner();
  });

  const author = cosigners.shift();
  const mswallet = await msdb.create({
    id: walletName,
    m: m,
    n: n,
    joinPubKey: cosignerCtxs[0].joinPubKey
  }, author);

  assert(cosigners.length === n - 1);

  let last;
  for (const cosigner of cosigners) {
    last = await msdb.join(walletName, cosigner);
    assert.ok(last, 'Could not join wallet.');
  }

  assert.strictEqual(author, last.cosigners[0]);
  for (const [i, cosigner] of cosigners.entries()) {
    assert.strictEqual(cosigner, last.cosigners[i + 1]);
  }

  return mswallet;
}

/**
 * @ignore
 * @param {MultisigWallet} wallet
 * @param {CosignerCtx} cosignerCtx
 * @param {Number} btc
 * @param {String} [memo = 'proposal']
 * @returns {Promise<Proposal>}
 */

async function mkProposal(wallet, cosignerCtx, btc, memo = 'proposal') {
  const [txoptions, httpTXOptions] = getTXOptions(btc);
  const cosigner = cosignerCtx.toCosigner();

  const options = {
    memo: memo,
    timestamp: now(),
    txoptions: httpTXOptions
  };

  const signature = cosignerCtx.signProposal(CREATE, options);

  const [proposal] = await wallet.createProposal(
    options,
    cosigner,
    txoptions,
    signature
  );

  return proposal;
}

/**
 * @ignore
 * @param {MultisigClient.Wallet} mswallet
 * @param {CosignerCtx[]} cosignerCtxs
 * @param {Object} options
 * @param {Number} options.m
 * @param {Number} options.pid - proposal id
 * @param {CosignerCtx} options.cosignerCtx - signer
 * @returns {Promise<Buffer[]>} signatures
 */

async function signProposal(mswallet, proposal, cosignerCtxs, cosignerCtx) {
  const mtx = await mswallet.getProposalMTX(proposal.id);
  const paths = await mswallet.getInputPaths(mtx);

  // the signer.
  if (!cosignerCtx)
    cosignerCtx = cosignerCtxs[0];

  const m = proposal.m;

  const xpubs = cosignerCtxs.slice(0, m).map(c => c.accountKey);
  const privKey = cosignerCtx.accountPrivKey;

  const rings = testUtils.getMTXRings(
    mtx,
    paths,
    privKey,
    xpubs,
    m
  );

  const signatures = testUtils.getMTXSignatures(mtx, rings);

  return signatures;
};

function getTXOptions(btc) {
  const address = generateAddress();

  const txoptions = {
    subtractFee: true,
    outputs: [{
      address: address,
      value: Amount.fromBTC(btc).toValue()
    }]
  };

  const httpTXOptions = {
    subtractFee: true,
    outputs: [{
      address: address.toString(),
      value: Amount.fromBTC(btc).toValue()
    }]
  };

  return [txoptions, httpTXOptions];
}

function generateAddress() {
  return KeyRing.generate().getAddress();
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
