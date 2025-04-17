package bbs

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

// MarshalBinary encodes a ProofOfKnowledge into a binary form
func (p *ProofOfKnowledge) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write APrime (G1 point)
	aPrimeBytes := p.APrime.Marshal()
	err := binary.Write(buf, binary.BigEndian, uint32(len(aPrimeBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(aPrimeBytes)
	if err != nil {
		return nil, err
	}
	
	// Write ABar (G1 point)
	aBarBytes := p.ABar.Marshal()
	err = binary.Write(buf, binary.BigEndian, uint32(len(aBarBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(aBarBytes)
	if err != nil {
		return nil, err
	}
	
	// Write D (G1 point)
	dBytes := p.D.Marshal()
	err = binary.Write(buf, binary.BigEndian, uint32(len(dBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(dBytes)
	if err != nil {
		return nil, err
	}
	
	// Write C (big.Int)
	cBytes := p.C.Bytes()
	err = binary.Write(buf, binary.BigEndian, uint32(len(cBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(cBytes)
	if err != nil {
		return nil, err
	}
	
	// Write EHat (big.Int)
	eHatBytes := p.EHat.Bytes()
	err = binary.Write(buf, binary.BigEndian, uint32(len(eHatBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(eHatBytes)
	if err != nil {
		return nil, err
	}
	
	// Write SHat (big.Int)
	sHatBytes := p.SHat.Bytes()
	err = binary.Write(buf, binary.BigEndian, uint32(len(sHatBytes)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(sHatBytes)
	if err != nil {
		return nil, err
	}
	
	// Write number of MHat entries
	err = binary.Write(buf, binary.BigEndian, uint32(len(p.MHat)))
	if err != nil {
		return nil, err
	}
	
	// Write each MHat entry
	for idx, mHat := range p.MHat {
		// Write index
		err = binary.Write(buf, binary.BigEndian, int32(idx))
		if err != nil {
			return nil, err
		}
		
		// Write value
		mHatBytes := mHat.Bytes()
		err = binary.Write(buf, binary.BigEndian, uint32(len(mHatBytes)))
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(mHatBytes)
		if err != nil {
			return nil, err
		}
	}
	
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a ProofOfKnowledge from a binary form
func (p *ProofOfKnowledge) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	
	// Read APrime (G1 point)
	var aPrimeLen uint32
	err := binary.Read(buf, binary.BigEndian, &aPrimeLen)
	if err != nil {
		return err
	}
	aPrimeBytes := make([]byte, aPrimeLen)
	_, err = buf.Read(aPrimeBytes)
	if err != nil {
		return err
	}
	err = p.APrime.Unmarshal(aPrimeBytes)
	if err != nil {
		return err
	}
	
	// Read ABar (G1 point)
	var aBarLen uint32
	err = binary.Read(buf, binary.BigEndian, &aBarLen)
	if err != nil {
		return err
	}
	aBarBytes := make([]byte, aBarLen)
	_, err = buf.Read(aBarBytes)
	if err != nil {
		return err
	}
	err = p.ABar.Unmarshal(aBarBytes)
	if err != nil {
		return err
	}
	
	// Read D (G1 point)
	var dLen uint32
	err = binary.Read(buf, binary.BigEndian, &dLen)
	if err != nil {
		return err
	}
	dBytes := make([]byte, dLen)
	_, err = buf.Read(dBytes)
	if err != nil {
		return err
	}
	err = p.D.Unmarshal(dBytes)
	if err != nil {
		return err
	}
	
	// Read C (big.Int)
	var cLen uint32
	err = binary.Read(buf, binary.BigEndian, &cLen)
	if err != nil {
		return err
	}
	cBytes := make([]byte, cLen)
	_, err = buf.Read(cBytes)
	if err != nil {
		return err
	}
	p.C = new(big.Int).SetBytes(cBytes)
	
	// Read EHat (big.Int)
	var eHatLen uint32
	err = binary.Read(buf, binary.BigEndian, &eHatLen)
	if err != nil {
		return err
	}
	eHatBytes := make([]byte, eHatLen)
	_, err = buf.Read(eHatBytes)
	if err != nil {
		return err
	}
	p.EHat = new(big.Int).SetBytes(eHatBytes)
	
	// Read SHat (big.Int)
	var sHatLen uint32
	err = binary.Read(buf, binary.BigEndian, &sHatLen)
	if err != nil {
		return err
	}
	sHatBytes := make([]byte, sHatLen)
	_, err = buf.Read(sHatBytes)
	if err != nil {
		return err
	}
	p.SHat = new(big.Int).SetBytes(sHatBytes)
	
	// Read number of MHat entries
	var mHatCount uint32
	err = binary.Read(buf, binary.BigEndian, &mHatCount)
	if err != nil {
		return err
	}
	
	// Initialize MHat map
	p.MHat = make(map[int]*big.Int)
	
	// Read each MHat entry
	for i := uint32(0); i < mHatCount; i++ {
		// Read index
		var idx int32
		err = binary.Read(buf, binary.BigEndian, &idx)
		if err != nil {
			return err
		}
		
		// Read value length
		var mHatLen uint32
		err = binary.Read(buf, binary.BigEndian, &mHatLen)
		if err != nil {
			return err
		}
		
		// Read value
		mHatBytes := make([]byte, mHatLen)
		_, err = buf.Read(mHatBytes)
		if err != nil {
			return err
		}
		p.MHat[int(idx)] = new(big.Int).SetBytes(mHatBytes)
	}
	
	return nil
}