package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDecryptWebMStreamWithProgressBar(t *testing.T) {
	// 1. Setup keys and metadata
	keyID, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	key, _ := hex.DecodeString("100f0e0d0c0b0a090807060504030201")
	rawIV, _ := hex.DecodeString("8765432112345678")

	keys := map[string][]byte{
		hex.EncodeToString(keyID): key,
	}

	// 2. Prepare Sample Structure
	clearSeg1 := []byte("CLEAR_SEG1")
	secretMsg := []byte("SECRET_MESSAGE!!!")
	clearSeg2 := []byte("CLEAR_TRAILING")

	// 3. Encrypt the secret segment using AES-CTR with Extended IV
	extendedIV := make([]byte, 16)
	copy(extendedIV[:8], rawIV)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	stream := cipher.NewCTR(block, extendedIV)

	cipherSeg := make([]byte, len(secretMsg))
	stream.XORKeyStream(cipherSeg, secretMsg)

	// 4. Assemble the Block Payload:
	signalByte := byte(WebMEncryptedSignal | WebMPartitionedSignal)

	header := make([]byte, 1+8+1+8)
	header[0] = signalByte
	copy(header[1:9], rawIV)
	header[9] = byte(2) // 2 partitions

	p0 := uint32(len(clearSeg1))
	p1 := p0 + uint32(len(secretMsg))

	binary.BigEndian.PutUint32(header[10:14], p0)
	binary.BigEndian.PutUint32(header[14:18], p1)

	mockPayload := append(header, clearSeg1...)
	mockPayload = append(mockPayload, cipherSeg...)
	mockPayload = append(mockPayload, clearSeg2...)

	// Create SimpleBlock payload
	var simpleBlockBuf bytes.Buffer
	// Track number (VINT) - let's say track 1
	simpleBlockBuf.Write(encodeVINT(1))
	// Timecode (int16)
	binary.Write(&simpleBlockBuf, binary.BigEndian, int16(100))
	// Flags (byte)
	simpleBlockBuf.WriteByte(0x80)
	// Frame data
	simpleBlockBuf.Write(mockPayload)

	simpleBlockBytes := encodeElement(0xA3, simpleBlockBuf.Bytes())

	// Create a Tracks element with TrackEntry containing ContentEncodings and TrackNum=1
	var trackEntryBuf bytes.Buffer
	// TrackNumber (0xD7)
	trackEntryBuf.Write(encodeUintElement(0xD7, 1))
	// ContentEncodings (0x6D80)
	var contentEncodingsBuf bytes.Buffer
	var contentEncodingBuf bytes.Buffer
	var contentEncryptionBuf bytes.Buffer
	// ContentEncKeyID (0x47E1)
	contentEncryptionBuf.Write(encodeElement(0x47E1, keyID))
	contentEncodingBuf.Write(encodeElement(0x5035, contentEncryptionBuf.Bytes()))
	contentEncodingsBuf.Write(encodeElement(0x6240, contentEncodingBuf.Bytes()))
	trackEntryBuf.Write(encodeElement(0x6D80, contentEncodingsBuf.Bytes()))

	tracksBytes := encodeElement(0x1654AE6B, encodeElement(0xAE, trackEntryBuf.Bytes()))

	// Create a Cluster (0x1F43B675) with a Timecode and our SimpleBlock
	var clusterBuf bytes.Buffer
	// Timecode (0xE7)
	clusterBuf.Write(encodeUintElement(0xE7, 0))
	// SimpleBlock (0xA3)
	clusterBuf.Write(simpleBlockBytes)

	clusterBytes := encodeElement(0x1F43B675, clusterBuf.Bytes())

	// Assemble Segment (0x18538067)
	var segmentPayload bytes.Buffer
	segmentPayload.Write(tracksBytes)
	segmentPayload.Write(clusterBytes)

	segmentBytes := encodeElement(0x18538067, segmentPayload.Bytes())

	// Entire EBML stream
	var ebmlStream bytes.Buffer
	// EBML Header (0x1A45DFA3) - just dummy content
	ebmlStream.Write(encodeElement(0x1A45DFA3, []byte{0x01}))
	ebmlStream.Write(segmentBytes)

	inputStreamBytes := ebmlStream.Bytes()
	totalBytes := int64(len(inputStreamBytes))

	var outputBuf bytes.Buffer

	// Run DecryptWebMStream with progress bar!
	err = DecryptWebMStream(bytes.NewReader(inputStreamBytes), &outputBuf, totalBytes, keys)
	if err != nil {
		t.Fatalf("DecryptWebMStream failed: %v", err)
	}

	// Verify decrypted output contains the clear strings
	decryptedBytes := outputBuf.Bytes()
	expectedDecryptedMsg := "CLEAR_SEG1SECRET_MESSAGE!!!CLEAR_TRAILING"
	if !bytes.Contains(decryptedBytes, []byte(expectedDecryptedMsg)) {
		t.Errorf("decrypted output does not contain the expected clear message!")
	}
}
