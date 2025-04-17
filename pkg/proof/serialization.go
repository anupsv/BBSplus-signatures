package proof

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/asv/projects/bbs/pkg/core"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ProofSerializer handles serialization of proof structures to binary format
type ProofSerializer struct {
	// Any serialization options can go here
}

// NewProofSerializer creates a new proof serializer
func NewProofSerializer() *ProofSerializer {
	return &ProofSerializer{}
}

// Serialize converts a proof to binary format
func (ps *ProofSerializer) Serialize(proof *core.ProofOfKnowledge) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("cannot serialize nil proof")
	}

	var buf bytes.Buffer

	// Write APrime
	aprimeBytes := proof.APrime.Marshal()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(aprimeBytes))); err != nil {
		return nil, fmt.Errorf("failed to write APrime length: %w", err)
	}
	if _, err := buf.Write(aprimeBytes); err != nil {
		return nil, fmt.Errorf("failed to write APrime bytes: %w", err)
	}

	// Write ABar
	abarBytes := proof.ABar.Marshal()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(abarBytes))); err != nil {
		return nil, fmt.Errorf("failed to write ABar length: %w", err)
	}
	if _, err := buf.Write(abarBytes); err != nil {
		return nil, fmt.Errorf("failed to write ABar bytes: %w", err)
	}

	// Write D
	dBytes := proof.D.Marshal()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(dBytes))); err != nil {
		return nil, fmt.Errorf("failed to write D length: %w", err)
	}
	if _, err := buf.Write(dBytes); err != nil {
		return nil, fmt.Errorf("failed to write D bytes: %w", err)
	}

	// Write C
	cBytes := proof.C.Bytes()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(cBytes))); err != nil {
		return nil, fmt.Errorf("failed to write C length: %w", err)
	}
	if _, err := buf.Write(cBytes); err != nil {
		return nil, fmt.Errorf("failed to write C bytes: %w", err)
	}

	// Write EHat
	ehatBytes := proof.EHat.Bytes()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(ehatBytes))); err != nil {
		return nil, fmt.Errorf("failed to write EHat length: %w", err)
	}
	if _, err := buf.Write(ehatBytes); err != nil {
		return nil, fmt.Errorf("failed to write EHat bytes: %w", err)
	}

	// Write SHat
	shatBytes := proof.SHat.Bytes()
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(shatBytes))); err != nil {
		return nil, fmt.Errorf("failed to write SHat length: %w", err)
	}
	if _, err := buf.Write(shatBytes); err != nil {
		return nil, fmt.Errorf("failed to write SHat bytes: %w", err)
	}

	// Write number of MHat values
	mhatCount := uint32(len(proof.MHat))
	if err := binary.Write(&buf, binary.BigEndian, mhatCount); err != nil {
		return nil, fmt.Errorf("failed to write MHat count: %w", err)
	}

	// Write each MHat value
	for i, mhat := range proof.MHat {
		mhatBytes := mhat.Bytes()
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(mhatBytes))); err != nil {
			return nil, fmt.Errorf("failed to write MHat[%d] length: %w", i, err)
		}
		if _, err := buf.Write(mhatBytes); err != nil {
			return nil, fmt.Errorf("failed to write MHat[%d] bytes: %w", i, err)
		}
	}

	// Write number of RHat values (if available)
	rhatCount := uint32(len(proof.RHat))
	if err := binary.Write(&buf, binary.BigEndian, rhatCount); err != nil {
		return nil, fmt.Errorf("failed to write RHat count: %w", err)
	}

	// Write each RHat value (if available)
	for i, rhat := range proof.RHat {
		rhatBytes := rhat.Bytes()
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(rhatBytes))); err != nil {
			return nil, fmt.Errorf("failed to write RHat[%d] length: %w", i, err)
		}
		if _, err := buf.Write(rhatBytes); err != nil {
			return nil, fmt.Errorf("failed to write RHat[%d] bytes: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}

// Deserialize converts binary data back to a proof
func (ps *ProofSerializer) Deserialize(data []byte) (*core.ProofOfKnowledge, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data cannot be deserialized")
	}

	buf := bytes.NewReader(data)
	proof := &core.ProofOfKnowledge{}

	// Read APrime
	var aprimeLen uint32
	if err := binary.Read(buf, binary.BigEndian, &aprimeLen); err != nil {
		return nil, fmt.Errorf("failed to read APrime length: %w", err)
	}
	aprimeBytes := make([]byte, aprimeLen)
	if _, err := io.ReadFull(buf, aprimeBytes); err != nil {
		return nil, fmt.Errorf("failed to read APrime bytes: %w", err)
	}
	if err := proof.APrime.Unmarshal(aprimeBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal APrime: %w", err)
	}

	// Read ABar
	var abarLen uint32
	if err := binary.Read(buf, binary.BigEndian, &abarLen); err != nil {
		return nil, fmt.Errorf("failed to read ABar length: %w", err)
	}
	abarBytes := make([]byte, abarLen)
	if _, err := io.ReadFull(buf, abarBytes); err != nil {
		return nil, fmt.Errorf("failed to read ABar bytes: %w", err)
	}
	if err := proof.ABar.Unmarshal(abarBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ABar: %w", err)
	}

	// Read D
	var dLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dLen); err != nil {
		return nil, fmt.Errorf("failed to read D length: %w", err)
	}
	dBytes := make([]byte, dLen)
	if _, err := io.ReadFull(buf, dBytes); err != nil {
		return nil, fmt.Errorf("failed to read D bytes: %w", err)
	}
	if err := proof.D.Unmarshal(dBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal D: %w", err)
	}

	// Read C
	var cLen uint32
	if err := binary.Read(buf, binary.BigEndian, &cLen); err != nil {
		return nil, fmt.Errorf("failed to read C length: %w", err)
	}
	cBytes := make([]byte, cLen)
	if _, err := io.ReadFull(buf, cBytes); err != nil {
		return nil, fmt.Errorf("failed to read C bytes: %w", err)
	}
	proof.C = new(big.Int).SetBytes(cBytes)

	// Read EHat
	var ehatLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ehatLen); err != nil {
		return nil, fmt.Errorf("failed to read EHat length: %w", err)
	}
	ehatBytes := make([]byte, ehatLen)
	if _, err := io.ReadFull(buf, ehatBytes); err != nil {
		return nil, fmt.Errorf("failed to read EHat bytes: %w", err)
	}
	proof.EHat = new(big.Int).SetBytes(ehatBytes)

	// Read SHat
	var shatLen uint32
	if err := binary.Read(buf, binary.BigEndian, &shatLen); err != nil {
		return nil, fmt.Errorf("failed to read SHat length: %w", err)
	}
	shatBytes := make([]byte, shatLen)
	if _, err := io.ReadFull(buf, shatBytes); err != nil {
		return nil, fmt.Errorf("failed to read SHat bytes: %w", err)
	}
	proof.SHat = new(big.Int).SetBytes(shatBytes)

	// Read number of MHat values
	var mhatCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mhatCount); err != nil {
		return nil, fmt.Errorf("failed to read MHat count: %w", err)
	}

	// Read each MHat value
	proof.MHat = make([]*big.Int, mhatCount)
	for i := uint32(0); i < mhatCount; i++ {
		var mhatLen uint32
		if err := binary.Read(buf, binary.BigEndian, &mhatLen); err != nil {
			return nil, fmt.Errorf("failed to read MHat[%d] length: %w", i, err)
		}
		mhatBytes := make([]byte, mhatLen)
		if _, err := io.ReadFull(buf, mhatBytes); err != nil {
			return nil, fmt.Errorf("failed to read MHat[%d] bytes: %w", i, err)
		}
		proof.MHat[i] = new(big.Int).SetBytes(mhatBytes)
	}

	// Read number of RHat values
	var rhatCount uint32
	if err := binary.Read(buf, binary.BigEndian, &rhatCount); err != nil {
		return nil, fmt.Errorf("failed to read RHat count: %w", err)
	}

	// Read each RHat value (if available)
	if rhatCount > 0 {
		proof.RHat = make([]*big.Int, rhatCount)
		for i := uint32(0); i < rhatCount; i++ {
			var rhatLen uint32
			if err := binary.Read(buf, binary.BigEndian, &rhatLen); err != nil {
				return nil, fmt.Errorf("failed to read RHat[%d] length: %w", i, err)
			}
			rhatBytes := make([]byte, rhatLen)
			if _, err := io.ReadFull(buf, rhatBytes); err != nil {
				return nil, fmt.Errorf("failed to read RHat[%d] bytes: %w", i, err)
			}
			proof.RHat[i] = new(big.Int).SetBytes(rhatBytes)
		}
	}

	return proof, nil
}

// SerializeDisclosedMessages serializes a map of disclosed messages
func (ps *ProofSerializer) SerializeDisclosedMessages(messages map[int]*big.Int) ([]byte, error) {
	var buf bytes.Buffer

	// Write the number of messages
	messageCount := uint32(len(messages))
	if err := binary.Write(&buf, binary.BigEndian, messageCount); err != nil {
		return nil, fmt.Errorf("failed to write message count: %w", err)
	}

	// Write each index and message
	for idx, msg := range messages {
		// Write index
		if err := binary.Write(&buf, binary.BigEndian, int32(idx)); err != nil {
			return nil, fmt.Errorf("failed to write message index: %w", err)
		}

		// Write message value
		msgBytes := msg.Bytes()
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(msgBytes))); err != nil {
			return nil, fmt.Errorf("failed to write message length: %w", err)
		}
		if _, err := buf.Write(msgBytes); err != nil {
			return nil, fmt.Errorf("failed to write message bytes: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// DeserializeDisclosedMessages deserializes a map of disclosed messages
func (ps *ProofSerializer) DeserializeDisclosedMessages(data []byte) (map[int]*big.Int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data cannot be deserialized")
	}

	buf := bytes.NewReader(data)
	messages := make(map[int]*big.Int)

	// Read the number of messages
	var messageCount uint32
	if err := binary.Read(buf, binary.BigEndian, &messageCount); err != nil {
		return nil, fmt.Errorf("failed to read message count: %w", err)
	}

	// Read each index and message
	for i := uint32(0); i < messageCount; i++ {
		// Read index
		var idx int32
		if err := binary.Read(buf, binary.BigEndian, &idx); err != nil {
			return nil, fmt.Errorf("failed to read message index: %w", err)
		}

		// Read message value
		var msgLen uint32
		if err := binary.Read(buf, binary.BigEndian, &msgLen); err != nil {
			return nil, fmt.Errorf("failed to read message length: %w", err)
		}
		msgBytes := make([]byte, msgLen)
		if _, err := io.ReadFull(buf, msgBytes); err != nil {
			return nil, fmt.Errorf("failed to read message bytes: %w", err)
		}
		messages[int(idx)] = new(big.Int).SetBytes(msgBytes)
	}

	return messages, nil
}

// ProofToBase64 converts a proof to a base64 string
func (ps *ProofSerializer) ProofToBase64(proof *core.ProofOfKnowledge) (string, error) {
	data, err := ps.Serialize(proof)
	if err != nil {
		return "", err
	}
	return bls12381.EncodeToBase64(data), nil
}

// ProofFromBase64 converts a base64 string to a proof
func (ps *ProofSerializer) ProofFromBase64(b64 string) (*core.ProofOfKnowledge, error) {
	data, err := bls12381.DecodeFromBase64(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return ps.Deserialize(data)
}

// DisclosedMessagesToBase64 converts disclosed messages to a base64 string
func (ps *ProofSerializer) DisclosedMessagesToBase64(messages map[int]*big.Int) (string, error) {
	data, err := ps.SerializeDisclosedMessages(messages)
	if err != nil {
		return "", err
	}
	return bls12381.EncodeToBase64(data), nil
}

// DisclosedMessagesFromBase64 converts a base64 string to disclosed messages
func (ps *ProofSerializer) DisclosedMessagesFromBase64(b64 string) (map[int]*big.Int, error) {
	data, err := bls12381.DecodeFromBase64(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return ps.DeserializeDisclosedMessages(data)
}