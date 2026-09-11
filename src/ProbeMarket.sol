// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ProbeMarket — a marketplace for reproducible model-failure findings
///
/// Sellers are red-teamers/eval researchers. A listing is a falsifiable, dated
/// claim about a *named model snapshot*: "model M exhibits failure behaviour C at
/// rate ≥ R over N inputs, judged by public grader G." The valuable IP — the
/// actual prompt suite that triggers the failure — is encrypted; the buyer (an AI
/// lab or a downstream deployer) pays before seeing it.
///
/// Two independent protections, with an honest trust boundary between them:
///
///  1. disputeInvalid — FULLY TRUSTLESS, ON-CHAIN. The buyer proves the thing they
///     bought was not even a well-formed eval for the claimed model. The contract
///     itself decrypts the revealed suite (keccak-CTR, committed by sha256 = its
///     IPFS CID digest) and checks it against the public claim schema. Neither
///     party can lie about what was sold.
///
///  2. resolve — VERIFIABLE ORACLE. After the resolution date, a resolver RE-RUNS
///     the suite against the model and reports the measured failure rate. Whether
///     a well-formed finding actually *reproduces* can't be checked on-chain (the
///     model can't run in the EVM), so this step is trusted — but because the demo
///     model is a public reference implementation, anyone can independently re-run
///     and catch a dishonest resolver. Overfitted/exaggerated findings are slashed
///     here; garbage findings are caught in step 1.
///
/// Because reveal-after-payment is coordinated disclosure (the buyer patches; the
/// finding then becomes a public eval), on-chain reveal is a feature here, not a leak.
contract ProbeMarket {
    enum Category {
        PromptInjection,
        Jailbreak,
        DataLeak,
        Hallucination,
        CapabilityGap
    }

    enum Status {
        Open, // listed, buyable, suite not yet revealed
        Revealed, // suite revealed, payment released, dispute window running
        Invalid, // proven not-a-valid-eval; buyers refunded from stake
        Resolved, // re-measured on-chain-reported; reputation updated, stake settled
        Expired, // resolution passed without a reveal
        Cancelled // seller withdrew an unsold listing
    }

    struct Listing {
        address seller;
        Status status;
        Category category;
        uint64 resolutionTimestamp;
        uint256 claimedFailRateBps; // "fails at least this often"
        uint256 trials; // suite must contain exactly this many prompts
        string modelId; // the model snapshot under test, e.g. "sentinel-v1"
        string graderSpec; // public grader, e.g. "leak:ST-9F3A-..."
        string claimSummary; // short public description
        string suiteCID; // IPFS CIDv1 (raw, sha2-256) of the encrypted suite
        bytes32 suiteHash; // sha256(ciphertext) == the CID's digest
        bytes32 keyHash; // keccak256(abi.encodePacked(key))
        bytes32 revealedKey;
        uint64 revealedAt;
        uint256 price;
        uint256 stake;
        uint256 numBuyers;
        uint256 payoutPerBuyer;
        uint256 measuredFailRateBps; // what the resolver re-measured
        bool reproduced;
    }

    struct Purchase {
        uint64 purchasedAt;
        bool refunded;
        bool payoutClaimed;
    }

    /// Reputation only ever counts SOLD findings, so it cannot be farmed with
    /// zero-buyer claims. `disputed` counts findings proven to be garbage.
    struct Reputation {
        uint64 totalListings;
        uint64 soldResolved;
        uint64 reproduced;
        uint64 failedToReproduce;
        uint64 disputed;
    }

    uint256 public constant SLASH_BPS = 5000; // 50% of stake slashed on a bad miss
    uint256 public constant TOLERANCE_BPS = 1000; // reproduce within 10 percentage points -> OK

    address public immutable resolver;
    uint256 public immutable revealWindow;
    uint256 public immutable disputeWindow;

    uint256 public nextListingId;
    mapping(uint256 => Listing) internal _listings;
    mapping(uint256 => mapping(address => Purchase)) public purchases;
    mapping(address => Reputation) internal _reputation;
    mapping(address => uint256) public balances;

    event Listed(
        uint256 indexed id,
        address indexed seller,
        string modelId,
        Category category,
        uint256 claimedFailRateBps,
        uint256 trials,
        uint256 price,
        uint256 stake,
        uint64 resolutionTimestamp,
        string suiteCID,
        string graderSpec,
        string claimSummary
    );
    event Purchased(uint256 indexed id, address indexed buyer);
    event Revealed(uint256 indexed id, bytes32 key);
    event Refunded(uint256 indexed id, address indexed buyer, uint256 amount);
    event DisputedInvalid(uint256 indexed id, address indexed buyer);
    event ListingResolved(uint256 indexed id, uint256 measuredFailRateBps, bool reproduced, uint256 payoutPerBuyer);
    event ListingExpired(uint256 indexed id);
    event ListingCancelled(uint256 indexed id);
    event PayoutClaimed(uint256 indexed id, address indexed buyer, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    constructor(address _resolver, uint256 _revealWindow, uint256 _disputeWindow) {
        resolver = _resolver;
        revealWindow = _revealWindow;
        disputeWindow = _disputeWindow;
    }

    // ---------------------------------------------------------------- listing

    struct ListParams {
        string suiteCID;
        bytes32 suiteHash;
        bytes32 keyHash;
        uint256 price;
        string modelId;
        Category category;
        string graderSpec;
        string claimSummary;
        uint256 claimedFailRateBps;
        uint256 trials;
        uint64 resolutionTimestamp;
    }

    function list(ListParams calldata p) external payable returns (uint256 id) {
        require(p.price > 0, "price=0");
        require(msg.value >= p.price, "stake < price"); // stake must cover >=1 full refund
        require(p.resolutionTimestamp > block.timestamp, "resolution in past");
        require(bytes(p.modelId).length > 0, "empty modelId");
        require(p.trials > 0, "trials=0");
        require(p.claimedFailRateBps > 0 && p.claimedFailRateBps <= 10_000, "bad rate");
        require(p.keyHash != bytes32(0) && p.suiteHash != bytes32(0), "empty commitment");

        id = nextListingId++;
        Listing storage l = _listings[id];
        l.seller = msg.sender;
        l.status = Status.Open;
        l.category = p.category;
        l.resolutionTimestamp = p.resolutionTimestamp;
        l.claimedFailRateBps = p.claimedFailRateBps;
        l.trials = p.trials;
        l.modelId = p.modelId;
        l.graderSpec = p.graderSpec;
        l.claimSummary = p.claimSummary;
        l.suiteCID = p.suiteCID;
        l.suiteHash = p.suiteHash;
        l.keyHash = p.keyHash;
        l.price = p.price;
        l.stake = msg.value;

        _reputation[msg.sender].totalListings++;

        emit Listed(
            id, msg.sender, p.modelId, p.category, p.claimedFailRateBps, p.trials,
            p.price, msg.value, p.resolutionTimestamp, p.suiteCID, p.graderSpec, p.claimSummary
        );
    }

    function cancel(uint256 id) external {
        Listing storage l = _listings[id];
        require(msg.sender == l.seller, "not seller");
        require(l.status == Status.Open, "not open");
        require(l.numBuyers == 0, "has buyers");
        l.status = Status.Cancelled;
        balances[l.seller] += l.stake;
        emit ListingCancelled(id);
    }

    // ------------------------------------------------------------------- buy

    function buy(uint256 id) external payable {
        Listing storage l = _listings[id];
        require(l.seller != address(0), "no listing");
        require(l.status == Status.Open, "not open");
        require(block.timestamp < l.resolutionTimestamp, "past resolution");
        require(msg.value == l.price, "wrong price");
        require(msg.sender != l.seller, "self-buy");
        require(purchases[id][msg.sender].purchasedAt == 0, "already bought");
        require(l.price * (l.numBuyers + 1) <= l.stake, "sold out: stake capacity");

        purchases[id][msg.sender] = Purchase({purchasedAt: uint64(block.timestamp), refunded: false, payoutClaimed: false});
        l.numBuyers++;
        emit Purchased(id, msg.sender);
    }

    function refund(uint256 id) external {
        Listing storage l = _listings[id];
        require(l.status == Status.Open || l.status == Status.Expired, "revealed or settled");
        Purchase storage pu = purchases[id][msg.sender];
        require(pu.purchasedAt != 0, "not a buyer");
        require(!pu.refunded, "already refunded");
        require(
            block.timestamp > pu.purchasedAt + revealWindow || block.timestamp >= l.resolutionTimestamp,
            "reveal window still open"
        );
        pu.refunded = true;
        l.numBuyers--;
        balances[msg.sender] += l.price;
        emit Refunded(id, msg.sender, l.price);
    }

    // ---------------------------------------------------------------- reveal

    function reveal(uint256 id, bytes32 key) external {
        Listing storage l = _listings[id];
        require(msg.sender == l.seller, "not seller");
        require(l.status == Status.Open, "not open");
        require(block.timestamp < l.resolutionTimestamp, "past resolution");
        require(keccak256(abi.encodePacked(key)) == l.keyHash, "key mismatch");

        l.revealedKey = key;
        l.revealedAt = uint64(block.timestamp);
        l.status = Status.Revealed;
        balances[l.seller] += l.price * l.numBuyers;
        emit Revealed(id, key);
    }

    // --------------------------------------------------------------- dispute

    /// Trustless proof-of-garbage: the buyer posts the ciphertext (bound to the
    /// listing by its sha256 commitment). The contract decrypts it with the
    /// revealed key and checks it is a well-formed eval for the claimed model.
    /// If not, every buyer is refunded from the seller's stake.
    function disputeInvalid(uint256 id, bytes calldata ciphertext) external {
        Listing storage l = _listings[id];
        require(l.status == Status.Revealed, "not revealed");
        require(block.timestamp <= uint256(l.revealedAt) + disputeWindow, "dispute window closed");
        Purchase storage pu = purchases[id][msg.sender];
        require(pu.purchasedAt != 0 && !pu.refunded, "not a buyer");
        require(sha256(ciphertext) == l.suiteHash, "ciphertext mismatch");

        bytes memory plaintext = decrypt(ciphertext, l.revealedKey);
        require(!_validEval(plaintext, l), "eval is well-formed");

        l.status = Status.Invalid;
        l.payoutPerBuyer = l.price;
        balances[l.seller] += l.stake - l.price * l.numBuyers;
        _reputation[l.seller].disputed++;
        emit DisputedInvalid(id, msg.sender);
    }

    // ------------------------------------------------------------ resolution

    /// Verifiable-oracle step: the resolver reports the re-measured failure rate
    /// (same bps units as the claim). Reproduction within tolerance => the finding
    /// held up. A large shortfall (overfitted/exaggerated) slashes the stake and
    /// rebates buyers pro-rata. Only SOLD findings move reputation.
    function resolve(uint256 id, uint256 measuredFailRateBps) external {
        require(msg.sender == resolver, "not resolver");
        require(measuredFailRateBps <= 10_000, "bad rate");
        Listing storage l = _listings[id];
        require(l.seller != address(0), "no listing");
        require(block.timestamp >= l.resolutionTimestamp, "too early");

        if (l.status == Status.Open) {
            l.status = Status.Expired; // never revealed; buyers exit via refund()
            balances[l.seller] += l.stake;
            emit ListingExpired(id);
            return;
        }

        require(l.status == Status.Revealed, "already settled");
        require(block.timestamp > uint256(l.revealedAt) + disputeWindow, "dispute window open");

        l.measuredFailRateBps = measuredFailRateBps;
        // reproduced if it fails at least (claimed - tolerance) of the time
        bool ok = measuredFailRateBps + TOLERANCE_BPS >= l.claimedFailRateBps;
        l.reproduced = ok;
        l.status = Status.Resolved;

        uint256 sellerReturn = l.stake;
        uint256 payoutPerBuyer;
        if (l.numBuyers > 0) {
            Reputation storage rep = _reputation[l.seller];
            rep.soldResolved++;
            if (ok) {
                rep.reproduced++;
            } else {
                rep.failedToReproduce++;
                uint256 shortfall = l.claimedFailRateBps - measuredFailRateBps;
                if (shortfall > TOLERANCE_BPS) {
                    uint256 slashed = (l.stake * SLASH_BPS) / 10_000;
                    payoutPerBuyer = slashed / l.numBuyers;
                    sellerReturn = l.stake - payoutPerBuyer * l.numBuyers;
                }
            }
        }
        l.payoutPerBuyer = payoutPerBuyer;
        balances[l.seller] += sellerReturn;
        emit ListingResolved(id, measuredFailRateBps, ok, payoutPerBuyer);
    }

    function claimPayout(uint256 id) external {
        Listing storage l = _listings[id];
        require(l.status == Status.Invalid || l.status == Status.Resolved, "not settled");
        require(l.payoutPerBuyer > 0, "no payout");
        Purchase storage pu = purchases[id][msg.sender];
        require(pu.purchasedAt != 0 && !pu.refunded, "not a buyer");
        require(!pu.payoutClaimed, "already claimed");
        pu.payoutClaimed = true;
        balances[msg.sender] += l.payoutPerBuyer;
        emit PayoutClaimed(id, msg.sender, l.payoutPerBuyer);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // ------------------------------------------------------------ crypto/util

    /// keccak-CTR stream cipher: keystream block i = keccak256(key ‖ i). Symmetric,
    /// cheap enough to run on-chain for small suites — which is what makes the
    /// dispute path trustless.
    function decrypt(bytes memory data, bytes32 key) public pure returns (bytes memory out) {
        out = new bytes(data.length);
        for (uint256 i = 0; i < data.length; i += 32) {
            bytes32 ks = keccak256(abi.encodePacked(key, i / 32));
            for (uint256 j = 0; j < 32 && i + j < data.length; j++) {
                out[i + j] = data[i + j] ^ ks[j];
            }
        }
    }

    /// Suite schema: abi.encode(string modelId, uint8 category, string[] prompts)
    function parseSuite(bytes calldata data)
        external
        pure
        returns (string memory modelId, uint8 category, string[] memory prompts)
    {
        return abi.decode(data, (string, uint8, string[]));
    }

    function _validEval(bytes memory plaintext, Listing storage l) internal view returns (bool) {
        try this.parseSuite(plaintext) returns (string memory modelId, uint8 category, string[] memory prompts) {
            if (keccak256(bytes(modelId)) != keccak256(bytes(l.modelId))) return false;
            if (category != uint8(l.category)) return false;
            if (prompts.length != l.trials) return false;
            for (uint256 i = 0; i < prompts.length; i++) {
                if (bytes(prompts[i]).length == 0) return false;
            }
            return true;
        } catch {
            return false;
        }
    }

    // ---------------------------------------------------------------- views

    function getListing(uint256 id) external view returns (Listing memory) {
        return _listings[id];
    }

    function getSellerReputation(address seller) external view returns (Reputation memory) {
        return _reputation[seller];
    }
}
