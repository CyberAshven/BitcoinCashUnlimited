<div class="cwikmeta">
{
"title": "Transaction Changes",
"related":["/transaction.md"]
} </div>

# Transaction Changes

This document assumes a familiarity with Bitcoin/Bitcoin Cash transaction semantics and structure.

## Transaction Hash Changes (Id and Idem)

### Summary
Transaction identity is split into two roles:
1. The **"transaction idem"**.  Latin for same, all transactions with the same idem cause the same UTXO state transformation.
2. The **transaction "id"**.  Similar to Bitcoin's transaction hash, the id is (probabilistically) unique for a transaction.

Using the Idem avoids most malleability attacks.  In practice, users only care about UTXO state transformation (who paid who) rather then the exact bytes in the transaction, so the Idem should be used by default in wallets.  Transactions spend other transactions by Idem, allowing children to be signed before parents and preventing malleability from orphaning chains of unspent transactions.  The bitcoind RPC operations generally return the Idem, but sometimes both.

The Id is used in the networking code, and in the block merkle tree.  Using the Id in the networking code is necessary so an attacker can't "spoof" a valid transaction with an invalid one.  Using the Id in the block merkle tree ensures participant consistency -- the blockchain converges to a specific transaction regardless of variants, and ensures that the chain-of-signatures must be retained by all full node participants.

### Background

Bitcoin uses a single identity for a transaction -- the SHA256 of the serialized transaction.  This allows transaction malleability attacks, because there are some bytes in the transaction that may be changed without changing the transaction signatures or the transaction's effect on the blockchain's UTXO state.  Although malleability has been "solved", the solution only covers typical script types, and consists of a variety of patches that enforce constraints on transactions that seems unnecessary and arbitrary for anyone not familiar with malleability.  

Recognizing that a transaction is fundamentally exactly and only a transformation of blockchain UTXO state allows for a clean input script malleability solution.  From the point of view of the blockchain, all valid transactions that effect the same UTXO state transformation are equivalent, since the UTXO state is the only data that subsequent transactions can access.

If a transaction consumes (and removes) the same coins, and produces the same outputs, the final UTXO will be exactly the same regardless of how the transaction accomplished this.  Therefore, for example, it does not matter how a transaction satisfies its input constraint scripts, only that it does so.

### Details

The transaction DAG (directed acyclic graph, or how transactions reference each other), uses the transaction's idem.

The block merkle tree and network subsystems use the transaction id.  This guarantees that the blockchain converges to a specific transaction, regardless of the existence of idems (malleated versions of the "same" transaction),  and that at the network layer, an invalid idem cannot be used to hide or block a valid transaction.

*Note that if a layered application uses transaction data that does not affect the UTXO (for example a data push within the satisfier script that is popped and ignored) it still might be vulnerable to transaction malleability.  These applications should either commit to that data within the UTXO (preventing malleability of that data), or wait for the particular idem to be confirmed on the blockchain.*

### Transaction Idem Calculation
Serialize the following transaction fields using standard bitcoin serialization algorithms:
* version
* inputs
	* prevout
	* sequence
	* amount
	* NOTE: the satisfier script (scriptSig) is not serialized
* outputs
* locktime


### Transaction Id Calculation

1. Create the "satisfiersHash" by double SHA256 hashing the following byte stream:
number of inputs as a little endian 4 byte number
for each input:
  satisfier script (script sig)
  0xFF
2. Calculate the transaction Idem
3. Concatenate the Idem with the satisfiersHash.
4. The transaction Id is the double SHA256 of the result of step 3.

## Transaction Spend Changes

### Inclusion of Amount field
*This change solves the simple-signer problem, prevents high-fee bugs, and prepares the system for a hybrid UTXO and account model*

An "amount" field was included in each input.  This field MUST match the amount (nValue) in the output that is spent.  The existence of this field helps stop wallets from making errors where they incorrectly track input amounts, resulting in accidentally giving extremely large fees to miners.  It also provides this information to signing-only wallets, which defuses a theoretical attack where a such a wallet is tricked into giving large fees to miners.

Note that Bitcoin Cash requires that the amount field be part of the sighash, solving the above without solving HOW wallets learn about the previous amount.  This change simply provides a convenient and default way to communicate this amount.

Note that this field is redundant information to the full node and so in theory does not need to be stored or passed over the network.  However, this implementation stores it, and until this space and bandwidth are at a premium, this optimization makes little sense.

### Outpoints (COutPoint)
*Saves 4 bytes per input and prepares the system for more sophisticated sources of UTXO entries*

"Outpoints" are references to UTXO entries, or "coins" from prior transactions.  There was no good name for this so the term "outpoint" was created.  The outpoint used to consist of a previous transaction hash and output index.  It has been modified to be a single hash which consists of:

*SHA256(tx.idem, output index)*

This saves 4 bytes, and is structurally more elegant.  Rather than tying a UTXO "coin" to a particular source (a particular transaction's output) it recognizes a UTXO as an independent entity.

With this change, the reverse lookup (determining where a UTXO came from) cannot use the transaction Idem lookup table.  A separate table must be created that maps outpoint hashes to source transactions.  This table is unnecessary for normal blockchain operations, but does effect blockchain explorers and analysis tools.


### Outputs (CTxOut)

#### Type

Outputs are versioned so that new output types can be deployed.  This allows the blockchain to create entirely new constraint scripts, potentially with non-backward-compatible script machine changes.  Currently 2 types are defined.

0. Legacy: This behaves like BTC/BCH.
1. General: See the Generalized TXO section below 

#### Generalized TXO

The generalized TXO format will be implemented in a subsequent merge request.

## Consensus Changes

### Coinbase
 * The coinbase transaction MUST have 0 inputs (vin array length must be 0).  All other transactions MUST have 1 or more inputs.
 * The last output (vout[vout.size()-1]) MUST be a 0 value OP_RETURN with the block height minimally encoded as the first data item, i.e.:  CScript() << OP_RETURN << _nHeight;  Additional data MAY be added after the height field by the miner.  The length of this data is constrained by standard OP_RETURN size rules.

These changes ensure that the coinbase Idem is unique for a blockchain transformation.
 

## Signatures

### Schnorr Signatures
ECDSA signatures are removed.

### Signature Hash

The signature hash field (sighash) is modified to allow multiple bytes.  Since Schnorr signatures are a well-known size, we can determine exactly how may bytes comprise the sighash.

#### Partial Transaction Sig Hash

##### N Outputs
The sighash includes outputs from 0 to N-1 (i.e. [0,N) ).  This allows multiple parties to engage in partial transaction interactions.
