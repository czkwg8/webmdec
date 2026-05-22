package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// Constants matching WebM CENC (Common Encryption) specifications.
const (
	WebMEncryptedSignal   = 0x01 // Bit 0 of signal byte: 1 = Encrypted, 0 = Clear
	WebMPartitionedSignal = 0x02 // Bit 1 of signal byte: 1 = Subsample/Partitioned, 0 = Entire frame encrypted
	WebMIvSize            = 8    // WebM IV size is always 8 bytes
)

// Subsample represents a slice of media data containing clear and encrypted bytes.
type Subsample struct {
	ClearBytes  uint32 // Number of clear (unencrypted) bytes at the start of this subsample
	CipherBytes uint32 // Number of cipher (encrypted) bytes following the clear bytes
}

// DecryptConfig holds the parsed cryptographic parameters for a single WebM frame/block.
type DecryptConfig struct {
	KeyID      []byte      // 16-byte Key ID associated with the track
	IV         []byte      // Extended 16-byte IV used for AES-CTR
	Subsamples []Subsample // List of subsamples indicating clear and encrypted regions
}

// DecryptResult contains the decrypted frame data and the parsed decryption config.
type DecryptResult struct {
	DecryptedData []byte        // Output slice containing the fully decrypted frame
	Config        DecryptConfig // The configuration parsed from the block header
	IsEncrypted   bool          // Indicates whether the block was actually encrypted
}

// ParseAndDecryptWebMBlock replicates the C++ WebMCreateDecryptConfig & DecryptSampleBuffer logic.
// - blockPayload: The raw byte slice of the WebM block payload (starts with the Signal Byte).
// - keyID: The 16-byte key ID of the track.
// - key: The 16-byte decryption key.
func ParseAndDecryptWebMBlock(blockPayload []byte, keyID []byte, key []byte) (*DecryptResult, error) {
	if len(blockPayload) < 1 {
		return nil, fmt.Errorf("empty WebM block payload")
	}

	if len(keyID) != 16 {
		return nil, fmt.Errorf("invalid key ID length: expected 16 bytes, got %d", len(keyID))
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key length: expected 16 bytes, got %d", len(key))
	}

	signalByte := blockPayload[0]
	headerSize := 1

	// Case 1: The frame is not encrypted (Signal Byte does not have the 0x01 bit set)
	if signalByte&WebMEncryptedSignal == 0 {
		// The frame is clear, but the 1-byte Signal Byte is still prepended.
		// Return the remainder of the payload as clear data.
		clearData := make([]byte, len(blockPayload)-1)
		copy(clearData, blockPayload[1:])
		return &DecryptResult{
			DecryptedData: clearData,
			IsEncrypted:   false,
		}, nil
	}

	// Case 2: Frame is encrypted. Ensure the header can hold the 8-byte IV
	headerSize += WebMIvSize
	if len(blockPayload) < headerSize {
		return nil, fmt.Errorf("block payload too small to contain IV: expected at least %d bytes, got %d", headerSize, len(blockPayload))
	}

	// Extract the 8-byte raw IV
	rawIV := blockPayload[1 : 1+WebMIvSize]

	// Extend the 8-byte IV to 16 bytes (CTR Counter Block) by padding 8 trailing bytes of zero.
	extendedIV := make([]byte, 16)
	copy(extendedIV[:WebMIvSize], rawIV) // Remainder of slice [8:16] is zero-initialized

	var subsamples []Subsample
	var dataOffset int

	// Check if the frame uses Subsample Encryption (Partitioned)
	if signalByte&WebMPartitionedSignal != 0 {
		numPartitionsOffset := headerSize
		headerSize += 1 // 1 byte for num_partitions
		if len(blockPayload) < headerSize {
			return nil, fmt.Errorf("block payload too small to contain num_partitions")
		}

		numPartitions := int(blockPayload[numPartitionsOffset])
		partitionsStart := headerSize
		headerSize += numPartitions * 4 // 4 bytes for each partition offset

		if len(blockPayload) < headerSize {
			return nil, fmt.Errorf("block payload too small to contain partition offsets")
		}

		payloadSize := uint32(len(blockPayload) - headerSize)
		dataOffset = headerSize

		// Parse partition offsets (each is a big-endian uint32)
		offsets := make([]uint32, numPartitions)
		for i := 0; i < numPartitions; i++ {
			idx := partitionsStart + (i * 4)
			offsets[i] = binary.BigEndian.Uint32(blockPayload[idx : idx+4])
		}

		// Convert partition offsets into Clear/Cipher Subsamples
		var prevOffset uint32 = 0
		for i := 0; i < numPartitions; i += 2 {
			clearOffset := offsets[i]
			if clearOffset < prevOffset {
				return nil, fmt.Errorf("partition offsets out of order: offset %d < prev %d", clearOffset, prevOffset)
			}
			clearSize := clearOffset - prevOffset

			var cipherSize uint32 = 0
			if i+1 < numPartitions {
				cipherOffset := offsets[i+1]
				if cipherOffset < clearOffset {
					return nil, fmt.Errorf("partition offsets out of order: offset %d < clear %d", cipherOffset, clearOffset)
				}
				cipherSize = cipherOffset - clearOffset
				prevOffset = cipherOffset
			} else {
				// Last partition index is odd. Cipher size extends to the end of the payload.
				if payloadSize < clearOffset {
					return nil, fmt.Errorf("partition clear offset %d exceeds payload size %d", clearOffset, payloadSize)
				}
				cipherSize = payloadSize - clearOffset
				prevOffset = payloadSize
			}

			subsamples = append(subsamples, Subsample{
				ClearBytes:  clearSize,
				CipherBytes: cipherSize,
			})
		}

		// Even number of partitions: add one last all-clear subsample covering the remainder
		if numPartitions%2 == 0 && prevOffset < payloadSize {
			subsamples = append(subsamples, Subsample{
				ClearBytes:  payloadSize - prevOffset,
				CipherBytes: 0,
			})
		}
	} else {
		// No partitioning: the entire remainder of the frame is encrypted
		dataOffset = headerSize
		payloadSize := uint32(len(blockPayload) - headerSize)
		subsamples = append(subsamples, Subsample{
			ClearBytes:  0,
			CipherBytes: payloadSize,
		})
	}

	encryptedMediaData := blockPayload[dataOffset:]
	decryptedMediaData := make([]byte, len(encryptedMediaData))

	// Instantiate the AES-128 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Initialize the AES-CTR stream cryptor
	stream := cipher.NewCTR(block, extendedIV)

	// Execute decryption block by block according to the subsample scheme
	var srcOffset uint32 = 0
	for _, sub := range subsamples {
		// 1. Copy Clear Bytes (unencrypted segment)
		if sub.ClearBytes > 0 {
			if srcOffset+sub.ClearBytes > uint32(len(encryptedMediaData)) {
				return nil, fmt.Errorf("subsample clear bytes overflow frame buffer")
			}
			copy(decryptedMediaData[srcOffset:srcOffset+sub.ClearBytes], encryptedMediaData[srcOffset:srcOffset+sub.ClearBytes])
			srcOffset += sub.ClearBytes
		}

		// 2. Decrypt Cipher Bytes (encrypted segment)
		if sub.CipherBytes > 0 {
			if srcOffset+sub.CipherBytes > uint32(len(encryptedMediaData)) {
				return nil, fmt.Errorf("subsample cipher bytes overflow frame buffer")
			}
			srcSlice := encryptedMediaData[srcOffset : srcOffset+sub.CipherBytes]
			dstSlice := decryptedMediaData[srcOffset : srcOffset+sub.CipherBytes]
			stream.XORKeyStream(dstSlice, srcSlice)
			srcOffset += sub.CipherBytes
		}
	}

	return &DecryptResult{
		DecryptedData: decryptedMediaData,
		IsEncrypted:   true,
		Config: DecryptConfig{
			KeyID:      keyID,
			IV:         extendedIV,
			Subsamples: subsamples,
		},
	}, nil
}
