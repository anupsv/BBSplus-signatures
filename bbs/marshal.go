package bbs

import (
	"bytes"
	"encoding/binary"
	"math/big"
	
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// MarshalBinary encodes a PrivateKey into a binary form
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	// Serialize the X value
	xBytes := sk.X.Bytes()
	
	// Format: [xLength(4)][xBytes]
	buf := new(bytes.Buffer)
	
	// Write the length of the X value
	err := binary.Write(buf, binary.BigEndian, uint32(len(xBytes)))
	if err != nil {
		return nil, err
	}
	
	// Write the X value
	_, err = buf.Write(xBytes)
	if err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a PrivateKey from a binary form
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	
	// Read length of X value
	var xLen uint32
	err := binary.Read(buf, binary.BigEndian, &xLen)
	if err != nil {
		return err
	}
	
	// Read X value
	xBytes := make([]byte, xLen)
	_, err = buf.Read(xBytes)
	if err != nil {
		return err
	}
	
	// Initialize X
	sk.X = new(big.Int).SetBytes(xBytes)
	
	return nil
}

// MarshalBinary encodes a PublicKey into a binary form
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write MessageCount
	err := binary.Write(buf, binary.BigEndian, uint32(pk.MessageCount))
	if err != nil {
		return nil, err
	}
	
	// Write W (G2 point) - serialize using gnark-crypto's built-in serialization
	wBytes := pk.W.Marshal()
	err = binary.Write(buf, binary.BigEndian, uint32(len(wBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(wBytes)
	if err != nil {
		return nil, err
	}
	
	// Write G1 (G1 point)
	g1Bytes := pk.G1.Marshal()
	err = binary.Write(buf, binary.BigEndian, uint32(len(g1Bytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(g1Bytes)
	if err != nil {
		return nil, err
	}
	
	// Write G2 (G2 point)
	g2Bytes := pk.G2.Marshal()
	err = binary.Write(buf, binary.BigEndian, uint32(len(g2Bytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(g2Bytes)
	if err != nil {
		return nil, err
	}
	
	// Write number of H points
	err = binary.Write(buf, binary.BigEndian, uint32(len(pk.H)))
	if err != nil {
		return nil, err
	}
	
	// Write each H point
	for _, h := range pk.H {
		hBytes := h.Marshal()
		err = binary.Write(buf, binary.BigEndian, uint32(len(hBytes)))
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(hBytes)
		if err != nil {
			return nil, err
		}
	}
	
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a PublicKey from a binary form
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	
	// Read MessageCount
	var messageCount uint32
	err := binary.Read(buf, binary.BigEndian, &messageCount)
	if err != nil {
		return err
	}
	pk.MessageCount = int(messageCount)
	
	// Read W (G2 point)
	var wLen uint32
	err = binary.Read(buf, binary.BigEndian, &wLen)
	if err != nil {
		return err
	}
	wBytes := make([]byte, wLen)
	_, err = buf.Read(wBytes)
	if err != nil {
		return err
	}
	err = pk.W.Unmarshal(wBytes)
	if err != nil {
		return err
	}
	
	// Read G1 (G1 point)
	var g1Len uint32
	err = binary.Read(buf, binary.BigEndian, &g1Len)
	if err != nil {
		return err
	}
	g1Bytes := make([]byte, g1Len)
	_, err = buf.Read(g1Bytes)
	if err != nil {
		return err
	}
	err = pk.G1.Unmarshal(g1Bytes)
	if err != nil {
		return err
	}
	
	// Read G2 (G2 point)
	var g2Len uint32
	err = binary.Read(buf, binary.BigEndian, &g2Len)
	if err != nil {
		return err
	}
	g2Bytes := make([]byte, g2Len)
	_, err = buf.Read(g2Bytes)
	if err != nil {
		return err
	}
	err = pk.G2.Unmarshal(g2Bytes)
	if err != nil {
		return err
	}
	
	// Read number of H points
	var numH uint32
	err = binary.Read(buf, binary.BigEndian, &numH)
	if err != nil {
		return err
	}
	
	// Read each H point
	pk.H = make([]bls12381.G1Affine, numH)
	for i := uint32(0); i < numH; i++ {
		var hLen uint32
		err = binary.Read(buf, binary.BigEndian, &hLen)
		if err != nil {
			return err
		}
		hBytes := make([]byte, hLen)
		_, err = buf.Read(hBytes)
		if err != nil {
			return err
		}
		err = pk.H[i].Unmarshal(hBytes)
		if err != nil {
			return err
		}
	}
	
	return nil
}

// MarshalBinary encodes a Signature into a binary form
func (sig *Signature) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write A (G1 point)
	aBytes := sig.A.Marshal()
	err := binary.Write(buf, binary.BigEndian, uint32(len(aBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(aBytes)
	if err != nil {
		return nil, err
	}
	
	// Write E (big.Int)
	eBytes := sig.E.Bytes()
	err = binary.Write(buf, binary.BigEndian, uint32(len(eBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(eBytes)
	if err != nil {
		return nil, err
	}
	
	// Write S (big.Int)
	sBytes := sig.S.Bytes()
	err = binary.Write(buf, binary.BigEndian, uint32(len(sBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(sBytes)
	if err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a Signature from a binary form
func (sig *Signature) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	
	// Read A (G1 point)
	var aLen uint32
	err := binary.Read(buf, binary.BigEndian, &aLen)
	if err != nil {
		return err
	}
	aBytes := make([]byte, aLen)
	_, err = buf.Read(aBytes)
	if err != nil {
		return err
	}
	err = sig.A.Unmarshal(aBytes)
	if err != nil {
		return err
	}
	
	// Read E (big.Int)
	var eLen uint32
	err = binary.Read(buf, binary.BigEndian, &eLen)
	if err != nil {
		return err
	}
	eBytes := make([]byte, eLen)
	_, err = buf.Read(eBytes)
	if err != nil {
		return err
	}
	sig.E = new(big.Int).SetBytes(eBytes)
	
	// Read S (big.Int)
	var sLen uint32
	err = binary.Read(buf, binary.BigEndian, &sLen)
	if err != nil {
		return err
	}
	sBytes := make([]byte, sLen)
	_, err = buf.Read(sBytes)
	if err != nil {
		return err
	}
	sig.S = new(big.Int).SetBytes(sBytes)
	
	return nil
}