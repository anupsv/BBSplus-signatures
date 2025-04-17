/*
Package bbs implements the BBS+ signature scheme, which allows for selective disclosure of signed messages.

BBS+ is a pairing-based cryptographic signature scheme that enables:
1. Creating signatures over multiple messages
2. Selectively disclosing a subset of signed messages without revealing the others
3. Proving that the disclosed messages were part of the original signed set

The implementation uses the BLS12-381 elliptic curve pairing, which provides 128 bits of security and is widely used in cryptographic applications, particularly in blockchain systems.

Key features:
- Generate key pairs for signing multiple messages
- Sign and verify signatures on sets of messages
- Create and verify selective disclosure proofs
- Convert messages to appropriate field elements

For the full specification of the algorithm, see:
https://github.com/mattrglobal/bbs-signatures/blob/master/docs/ALGORITHM.md

Usage example:
    // Generate a key pair for 5 messages
    keyPair, _ := bbs.GenerateKeyPair(5, nil)
    
    // Convert messages to field elements
    msgs := make([]*big.Int, 5)
    for i, msgStr := range messageStrings {
        msgs[i] = bbs.MessageToFieldElement(bbs.MessageToBytes(msgStr))
    }
    
    // Sign the messages
    signature, _ := bbs.Sign(keyPair.PrivateKey, keyPair.PublicKey, msgs)
    
    // Verify the signature
    err := bbs.Verify(keyPair.PublicKey, signature, msgs)
    
    // Create a selective disclosure proof for messages 0 and 2
    proof, disclosed, _ := bbs.CreateProof(keyPair.PublicKey, signature, msgs, []int{0, 2})
    
    // Verify the proof
    err = bbs.VerifyProof(keyPair.PublicKey, proof, disclosed)
*/
package bbs