package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"webmdec/util"
)

// parseKeyPairs parses key parameter formatted as kid1:key1|kid2:key2|...
func parseKeyPairs(keyParam string) (map[string][]byte, error) {
	keys := make(map[string][]byte)
	parts := strings.Split(keyParam, "|")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		colonIdx := strings.Index(part, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("invalid format, missing ':' in pair: %q", part)
		}
		kidHex := strings.TrimSpace(part[:colonIdx])
		keyHex := strings.TrimSpace(part[colonIdx+1:])

		kid, err := hex.DecodeString(kidHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode kid hex %q: %w", kidHex, err)
		}
		if len(kid) != 16 {
			return nil, fmt.Errorf("invalid kid length, expected 16 bytes (32 hex characters), got %d bytes: %q", len(kid), kidHex)
		}

		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key hex %q: %w", keyHex, err)
		}
		if len(key) != 16 {
			return nil, fmt.Errorf("invalid key length, expected 16 bytes (32 hex characters), got %d bytes: %q", len(key), keyHex)
		}

		keys[strings.ToLower(kidHex)] = key
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid kid:key pairs provided")
	}
	return keys, nil
}

func main() {
	keyParam := flag.String("key", "0123456789abcdef0123456789abcdef:abcdef0123456789abcdef0123456789", "AES decryption keys (format kid1:key1|kid2:key2|...)")
	inputFile := flag.String("input", "encrypted_video.webm", "Path to the input encrypted WebM file")
	outputFile := flag.String("output", "decrypted_video.webm", "Path to write the decrypted WebM file")
	runSim := flag.Bool("simulate", false, "Force running self-contained simulation test")

	flag.Parse()

	// Run simulation if forced or if default file doesn't exist
	_, statErr := os.Stat(*inputFile)
	if *runSim || (os.IsNotExist(statErr) && *inputFile == "encrypted_video.webm") {
		fmt.Println("==================================================")
		fmt.Println("   WebM CENC Decryption - Self-Test Simulation")
		fmt.Println("==================================================")
		if err := runSimulation(); err != nil {
			log.Fatalf("Simulation failed: %v", err)
		}
		return
	}

	keys, err := parseKeyPairs(*keyParam)
	if err != nil {
		log.Fatalf("Failed to parse key parameter: %v", err)
	}

	fmt.Printf("==================================================\n")
	fmt.Printf("   WebM CENC Streaming Demux & Decrypt Engine\n")
	fmt.Printf("==================================================\n")
	fmt.Printf(" - Input file:    %s\n", *inputFile)
	fmt.Printf(" - Output file:   %s\n", *outputFile)
	fmt.Printf(" - Key Pairs Loaded:\n")
	for kid, key := range keys {
		fmt.Printf("   * Key ID: %s -> Key: %x\n", kid, key)
	}
	fmt.Println()

	fIn, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer fIn.Close()

	var fileSize int64 = 0
	if fi, err := fIn.Stat(); err == nil {
		fileSize = fi.Size()
	}

	fOut, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer fOut.Close()

	fmt.Println("[DECRYPT] Processing EBML stream frame by frame...")
	if err := util.DecryptWebMStream(fIn, fOut, fileSize, keys); err != nil {
		log.Fatalf("Decryption stream failed: %v", err)
	}

	fmt.Println("==================================================")
	fmt.Printf("SUCCESS! Playable clear output written to: %s\n", *outputFile)
	fmt.Println("==================================================")
}

// runSimulation builds a mock encrypted partitioned WebM frame, decrypts it, and verifies results.
func runSimulation() error {
	// 1. Core Secrets
	keyID, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	key, _ := hex.DecodeString("100f0e0d0c0b0a090807060504030201")
	rawIV, _ := hex.DecodeString("8765432112345678") // 8 bytes

	fmt.Printf("[SIM] Using Key ID: %x\n", keyID)
	fmt.Printf("[SIM] Using Key:    %x\n", key)
	fmt.Printf("[SIM] Using IV:     %x\n\n", rawIV)

	// 2. Prepare Sample Structure
	clearSeg1 := []byte("CLEAR_SEG1")        // 10 bytes
	secretMsg := []byte("SECRET_MESSAGE!!!") // 17 bytes
	clearSeg2 := []byte("CLEAR_TRAILING")    // 14 bytes

	// 3. Encrypt the secret segment using AES-CTR with Extended IV
	extendedIV := make([]byte, 16)
	copy(extendedIV[:8], rawIV)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	stream := cipher.NewCTR(block, extendedIV)

	cipherSeg := make([]byte, len(secretMsg))
	stream.XORKeyStream(cipherSeg, secretMsg)

	// 4. Assemble the Block Payload:
	signalByte := byte(util.WebMEncryptedSignal | util.WebMPartitionedSignal) // 0x03

	header := make([]byte, 1+8+1+8)
	header[0] = signalByte
	copy(header[1:9], rawIV)
	header[9] = byte(2) // 2 partitions

	p0 := uint32(len(clearSeg1))
	p1 := p0 + uint32(len(secretMsg))

	binary.BigEndian.PutUint32(header[10:14], p0) // P0
	binary.BigEndian.PutUint32(header[14:18], p1) // P1

	mockPayload := append(header, clearSeg1...)
	mockPayload = append(mockPayload, cipherSeg...)
	mockPayload = append(mockPayload, clearSeg2...)

	fmt.Printf("[SIM] Generated mock encrypted WebM block payload (%d bytes total)\n", len(mockPayload))
	fmt.Printf("[SIM] Frame Layout Schema:\n")
	fmt.Printf(" - Clear segment 1:  \"%s\" (10 bytes)\n", string(clearSeg1))
	fmt.Printf(" - Ciphertext segment: %x (17 bytes)\n", cipherSeg)
	fmt.Printf(" - Clear segment 2:  \"%s\" (14 bytes)\n\n", string(clearSeg2))

	// 5. Decrypt using our Go parsing engine
	fmt.Println("[SIM] Running ParseAndDecryptWebMBlock...")
	result, err := util.ParseAndDecryptWebMBlock(mockPayload, keyID, key)
	if err != nil {
		return fmt.Errorf("decryption engine returned error: %w", err)
	}

	fmt.Println("[SIM] Parse results:")
	fmt.Printf(" - Decryption extended IV: %x\n", result.Config.IV)
	fmt.Printf(" - Subsamples found:       %d\n", len(result.Config.Subsamples))
	for idx, s := range result.Config.Subsamples {
		fmt.Printf("    [%d] Clear bytes: %d, Cipher bytes: %d\n", idx, s.ClearBytes, s.CipherBytes)
	}

	// 6. Verify Correctness
	decryptedStr := string(result.DecryptedData)
	expectedStr := "CLEAR_SEG1SECRET_MESSAGE!!!CLEAR_TRAILING"

	fmt.Printf("\n[SIM] Expected result:  \"%s\"\n", expectedStr)
	fmt.Printf("[SIM] Decrypted result: \"%s\"\n\n", decryptedStr)

	if decryptedStr == expectedStr {
		fmt.Println("==================================================")
		fmt.Println("   SIMULATION SUCCESSFUL: All segments decrypted  ")
		fmt.Println("==================================================")
	} else {
		return fmt.Errorf("decrypted output mismatch! Expected: %s, Got: %s", expectedStr, decryptedStr)
	}

	return nil
}
