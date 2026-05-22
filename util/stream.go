package util

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// ANSI color escape codes for high-fidelity beautiful console display
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

// formatSize converts bytes into a human-readable size string
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := ""
	switch exp {
	case 0:
		suffix = "KB"
	case 1:
		suffix = "MB"
	case 2:
		suffix = "GB"
	default:
		suffix = "TB"
	}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), suffix)
}

// progressReader wraps an io.Reader and displays a beautiful CLI progress bar.
type progressReader struct {
	r          io.Reader
	totalBytes int64
	readBytes  int64
	startTime  time.Time
	lastUpdate time.Time
}

func newProgressReader(r io.Reader, totalBytes int64) *progressReader {
	return &progressReader{
		r:          r,
		totalBytes: totalBytes,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	if n > 0 {
		pr.readBytes += int64(n)
		// Limit updates to prevent screen flickering (max 20 updates per second)
		now := time.Now()
		if now.Sub(pr.lastUpdate) >= 50*time.Millisecond || pr.readBytes == pr.totalBytes {
			pr.lastUpdate = now
			pr.displayProgress()
		}
	}
	return n, err
}

func (pr *progressReader) displayProgress() {
	if pr.totalBytes <= 0 {
		return
	}

	percent := float64(pr.readBytes) / float64(pr.totalBytes) * 100
	if percent > 100 {
		percent = 100
	}

	// Progress bar builder
	const barWidth = 30
	filledLength := int(percent / 100 * barWidth)
	if filledLength > barWidth {
		filledLength = barWidth
	}

	var barBuilder strings.Builder
	for i := 0; i < barWidth; i++ {
		if i < filledLength {
			barBuilder.WriteString("█")
		} else {
			barBuilder.WriteString("░")
		}
	}
	bar := barBuilder.String()

	elapsed := time.Since(pr.startTime)
	seconds := elapsed.Seconds()

	// Speed calculation
	var speedStr string
	if seconds > 0 {
		speed := float64(pr.readBytes) / seconds
		if speed > 1024*1024 {
			speedStr = fmt.Sprintf("%.2f MB/s", speed/(1024*1024))
		} else if speed > 1024 {
			speedStr = fmt.Sprintf("%.2f KB/s", speed/1024)
		} else {
			speedStr = fmt.Sprintf("%.0f B/s", speed)
		}
	} else {
		speedStr = "--"
	}

	// ETA calculation
	var etaStr string
	if percent >= 100 {
		etaStr = "0s"
	} else if seconds > 0 && pr.readBytes > 0 {
		speed := float64(pr.readBytes) / seconds
		remainingBytes := pr.totalBytes - pr.readBytes
		etaSeconds := float64(remainingBytes) / speed
		if etaSeconds > 3600 {
			etaStr = fmt.Sprintf("%dh %dm", int(etaSeconds)/3600, (int(etaSeconds)%3600)/60)
		} else if etaSeconds > 60 {
			etaStr = fmt.Sprintf("%dm %ds", int(etaSeconds)/60, int(etaSeconds)%60)
		} else {
			etaStr = fmt.Sprintf("%.1fs", etaSeconds)
		}
	} else {
		etaStr = "--"
	}

	// Format elapsed time
	var elapsedStr string
	if seconds > 60 {
		elapsedStr = fmt.Sprintf("%dm %ds", int(seconds)/60, int(seconds)%60)
	} else {
		elapsedStr = fmt.Sprintf("%.1fs", seconds)
	}

	// Render the premium CLI progress bar
	fmt.Printf("\r%s[%s] %s%.1f%% %s(%s/%s) | Speed: %s%s%s | Elapsed: %s%s%s | ETA: %s%s%s",
		colorCyan, bar,
		colorBold, percent, colorReset,
		formatSize(pr.readBytes), formatSize(pr.totalBytes),
		colorYellow, speedStr, colorReset,
		colorGreen, elapsedStr, colorReset,
		colorPurple, etaStr, colorReset,
	)
}

func (pr *progressReader) finalize() {
	pr.readBytes = pr.totalBytes
	pr.displayProgress()
	fmt.Println()
}

// Master element IDs in WebM/Matroska CENC
var masterElements = map[uint32]bool{
	0x1A45DFA3: true, // EBML
	0x18538067: true, // Segment
	0x114D9B74: true, // SeekHead
	0x1254C367: true, // Tags
	0x1941A469: true, // Attachments
	0x1549A966: true, // Info
	0x1654AE6B: true, // Tracks
	0xAE:       true, // TrackEntry
	0x6D80:     true, // ContentEncodings
	0x6240:     true, // ContentEncoding
	0x5035:     true, // ContentEncryption
	0x1F43B675: true, // Cluster
	0xA0:       true, // BlockGroup
}

// Valid children of Cluster
var clusterChildren = map[uint32]bool{
	0xE7:   true, // Timecode
	0xAB:   true, // PrevSize
	0xA3:   true, // SimpleBlock
	0xA0:   true, // BlockGroup
	0x58D7: true, // SilentTracks
	0xA7:   true, // Position
}

// CountingWriter wraps an io.Writer and tracks the total bytes written
type CountingWriter struct {
	W io.Writer
	N int64
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.W.Write(p)
	cw.N += int64(n)
	return n, err
}

// CueRecord represents a cue point entry
type CueRecord struct {
	Timecode uint64
	Offset   uint64 // Offset relative to the start of Segment's payload
}

// buildCuesElement builds a valid Matroska Cues (0x1C53BB6B) element
func buildCuesElement(cues []CueRecord, videoTrackNum uint64) []byte {
	var cuesBuf bytes.Buffer

	for _, c := range cues {
		var cuePointBuf bytes.Buffer

		// CueTime (0xB3)
		cuePointBuf.Write(encodeUintElement(0xB3, c.Timecode))

		// CueTrackPositions (0xB7)
		var trackPosBuf bytes.Buffer
		// CueTrack (0xF7)
		trackPosBuf.Write(encodeUintElement(0xF7, videoTrackNum))
		// CueClusterPosition (0xF1)
		trackPosBuf.Write(encodeUintElement(0xF1, c.Offset))

		cuePointBuf.Write(encodeElement(0xB7, trackPosBuf.Bytes()))

		cuesBuf.Write(encodeElement(0xBB, cuePointBuf.Bytes()))
	}

	return encodeElement(0x1C53BB6B, cuesBuf.Bytes())
}

// encodeElement wraps a payload with ID and size VINT
func encodeElement(id uint32, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write(encodeID(id))
	buf.Write(encodeVINT(uint64(len(payload))))
	buf.Write(payload)
	return buf.Bytes()
}

// encodeUintElement encodes a uint64 value as a Matroska big-endian uint element
func encodeUintElement(id uint32, val uint64) []byte {
	var payload []byte
	if val == 0 {
		payload = []byte{0}
	} else {
		temp := val
		for temp > 0 {
			payload = append([]byte{byte(temp & 0xFF)}, payload...)
			temp >>= 8
		}
	}
	return encodeElement(id, payload)
}

// encodeVINT8Bytes encodes a uint64 value as an exact 8-byte EBML VINT size
func encodeVINT8Bytes(val uint64) []byte {
	raw := make([]byte, 8)
	raw[0] = 0x01 | byte((val>>56)&0xFF)
	raw[1] = byte((val >> 48) & 0xFF)
	raw[2] = byte((val >> 40) & 0xFF)
	raw[3] = byte((val >> 32) & 0xFF)
	raw[4] = byte((val >> 24) & 0xFF)
	raw[5] = byte((val >> 16) & 0xFF)
	raw[6] = byte((val >> 8) & 0xFF)
	raw[7] = byte(val & 0xFF)
	return raw
}

// buildVoidElement compiles a perfectly sized EBML Void (0xEC) padding block
func buildVoidElement(totalSize int) []byte {
	if totalSize < 2 {
		panic("Void element must be at least 2 bytes")
	}
	payloadSize := totalSize - 2
	if payloadSize < 0x7F {
		res := make([]byte, totalSize)
		res[0] = 0xEC
		res[1] = byte(payloadSize) | 0x80
		return res
	}
	payloadSize = totalSize - 3
	res := make([]byte, totalSize)
	res[0] = 0xEC
	res[1] = byte(payloadSize>>8) | 0x40
	res[2] = byte(payloadSize & 0xFF)
	return res
}

// buildSeekHeadElement compiles a standard Matroska SeekHead (0x114D9B74) element
func buildSeekHeadElement(infoOffset, tracksOffset, cuesOffset uint64) []byte {
	var seekHeadBuf bytes.Buffer

	// 1. Seek entry for Info (0x1549A966)
	if infoOffset > 0 {
		var seekBuf bytes.Buffer
		seekBuf.Write(encodeElement(0x53AB, encodeID(0x1549A966)))
		seekBuf.Write(encodeUintElement(0x53AC, infoOffset))
		seekHeadBuf.Write(encodeElement(0x4DBB, seekBuf.Bytes()))
	}

	// 2. Seek entry for Tracks (0x1654AE6B)
	if tracksOffset > 0 {
		var seekBuf bytes.Buffer
		seekBuf.Write(encodeElement(0x53AB, encodeID(0x1654AE6B)))
		seekBuf.Write(encodeUintElement(0x53AC, tracksOffset))
		seekHeadBuf.Write(encodeElement(0x4DBB, seekBuf.Bytes()))
	}

	// 3. Seek entry for Cues (0x1C53BB6B)
	if cuesOffset > 0 {
		var seekBuf bytes.Buffer
		seekBuf.Write(encodeElement(0x53AB, encodeID(0x1C53BB6B)))
		seekBuf.Write(encodeUintElement(0x53AC, cuesOffset))
		seekHeadBuf.Write(encodeElement(0x4DBB, seekBuf.Bytes()))
	}

	return encodeElement(0x114D9B74, seekHeadBuf.Bytes())
}

// readVINTID reads an EBML ID (which is a VINT preserving its marker bits)
func readVINTID(r io.Reader) (uint32, []byte, error) {
	var firstByte [1]byte
	if _, err := io.ReadFull(r, firstByte[:]); err != nil {
		return 0, nil, err
	}
	b := firstByte[0]
	if b == 0 {
		return 0, nil, fmt.Errorf("invalid EBML ID prefix zero")
	}

	var leadingZeros int
	for i := 7; i >= 0; i-- {
		if (b & (1 << i)) != 0 {
			leadingZeros = 7 - i
			break
		}
	}

	length := leadingZeros + 1
	raw := make([]byte, length)
	raw[0] = b
	if length > 1 {
		if _, err := io.ReadFull(r, raw[1:]); err != nil {
			return 0, nil, err
		}
	}

	var id uint32
	for _, x := range raw {
		id = (id << 8) | uint32(x)
	}
	return id, raw, nil
}

// peekVINTID peeks at the next VINT ID without advancing the bufio.Reader
func peekVINTID(br *bufio.Reader) (uint32, []byte, error) {
	peeked, err := br.Peek(1)
	if err != nil {
		return 0, nil, err
	}
	b := peeked[0]
	if b == 0 {
		return 0, nil, fmt.Errorf("invalid VINT prefix zero in peek")
	}

	var leadingZeros int
	for i := 7; i >= 0; i-- {
		if (b & (1 << i)) != 0 {
			leadingZeros = 7 - i
			break
		}
	}

	length := leadingZeros + 1
	peeked, err = br.Peek(length)
	if err != nil {
		return 0, nil, err
	}

	var id uint32
	for _, x := range peeked {
		id = (id << 8) | uint32(x)
	}

	raw := make([]byte, length)
	copy(raw, peeked)
	return id, raw, nil
}

// readVINTSize reads an EBML size (VINT clearing its marker bit)
func readVINTSize(r io.Reader) (uint64, []byte, error) {
	var firstByte [1]byte
	if _, err := io.ReadFull(r, firstByte[:]); err != nil {
		return 0, nil, err
	}
	b := firstByte[0]
	if b == 0 {
		return 0, nil, fmt.Errorf("invalid EBML Size prefix zero")
	}

	var leadingZeros int
	for i := 7; i >= 0; i-- {
		if (b & (1 << i)) != 0 {
			leadingZeros = 7 - i
			break
		}
	}

	length := leadingZeros + 1
	raw := make([]byte, length)
	raw[0] = b
	if length > 1 {
		if _, err := io.ReadFull(r, raw[1:]); err != nil {
			return 0, nil, err
		}
	}

	val := uint64(b & ^(1 << (7 - leadingZeros)))
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(raw[i])
	}

	return val, raw, nil
}

// isUnknownSizeVal checks if the VINT size represents an unknown size (all value bits 1)
func isUnknownSizeVal(val uint64, length int) bool {
	return val == (uint64(1)<<(uint(length)*7))-1
}

// encodeVINT encodes a uint64 value as an EBML VINT
func encodeVINT(val uint64) []byte {
	var length int
	if val < 0x7F {
		length = 1
	} else if val < 0x3FFF {
		length = 2
	} else if val < 0x1FFFFF {
		length = 3
	} else if val < 0x0FFFFFFF {
		length = 4
	} else if val < 0x07FFFFFFFF {
		length = 5
	} else if val < 0x03FFFFFFFFFF {
		length = 6
	} else if val < 0x01FFFFFFFFFFFF {
		length = 7
	} else {
		length = 8
	}

	raw := make([]byte, length)
	v := val
	for i := length - 1; i >= 0; i-- {
		raw[i] = byte(v & 0xFF)
		v >>= 8
	}
	raw[0] |= (1 << (8 - length))
	return raw
}

// encodeID encodes a uint32 ID to bytes
func encodeID(id uint32) []byte {
	if id == 0 {
		return []byte{}
	}
	var buf []byte
	temp := id
	for temp > 0 {
		buf = append([]byte{byte(temp & 0xFF)}, buf...)
		temp >>= 8
	}
	return buf
}

// parseBlockHeader extracts track number, timecode, and flags from SimpleBlock/Block payload
func parseBlockHeader(payload []byte) (trackNum uint64, timecode int16, flags byte, headerSize int, err error) {
	r := bytes.NewReader(payload)
	tn, rawTN, err := readVINT(r)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	var tcBuf [2]byte
	if _, err := io.ReadFull(r, tcBuf[:]); err != nil {
		return 0, 0, 0, 0, err
	}
	tc := int16(binary.BigEndian.Uint16(tcBuf[:]))

	var fBuf [1]byte
	if _, err := io.ReadFull(r, fBuf[:]); err != nil {
		return 0, 0, 0, 0, err
	}
	f := fBuf[0]

	headerSize = len(rawTN) + 2 + 1
	return tn, tc, f, headerSize, nil
}

// readVINT is a convenience helper matching readVINTID/readVINTSize logic for inner block parsing
func readVINT(r io.Reader) (uint64, []byte, error) {
	var firstByte [1]byte
	if _, err := io.ReadFull(r, firstByte[:]); err != nil {
		return 0, nil, err
	}
	b := firstByte[0]
	if b == 0 {
		return 0, nil, fmt.Errorf("invalid VINT prefix zero")
	}

	var leadingZeros int
	for i := 7; i >= 0; i-- {
		if (b & (1 << i)) != 0 {
			leadingZeros = 7 - i
			break
		}
	}

	length := leadingZeros + 1
	raw := make([]byte, length)
	raw[0] = b
	if length > 1 {
		if _, err := io.ReadFull(r, raw[1:]); err != nil {
			return 0, nil, err
		}
	}

	val := uint64(b & ^(1 << (7 - leadingZeros)))
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(raw[i])
	}

	return val, raw, nil
}

// TrackEncryption holds the track encryption properties parsed from EBML
type TrackEncryption struct {
	IsEncrypted bool
	KeyID       []byte
}

// findContentEncKeyID recursively searches for the ContentEncKeyID inside ContentEncodings structure
func findContentEncKeyID(payload []byte) []byte {
	r := bytes.NewReader(payload)
	var possibleKeyID []byte
	for r.Len() > 0 {
		id, _, err := readVINTID(r)
		if err != nil {
			return nil
		}
		size, _, err := readVINTSize(r)
		if err != nil {
			return nil
		}
		childPayload := make([]byte, size)
		if _, err := io.ReadFull(r, childPayload); err != nil {
			return nil
		}

		// In some quirkily muxed WebM files, ContentEncKeyID (0x47E1) and ContentEncAlgo (0x47E2)
		// might be swapped, or the 16-byte Key ID might be stored under 0x47E2.
		// A valid CENC Key ID is always exactly 16 bytes.
		if (id == 0x47E1 || id == 0x47E2) && len(childPayload) == 16 {
			return childPayload
		}
		// Fallback: if we find 0x47E1 but it's not 16 bytes, keep it as a backup
		if id == 0x47E1 && len(childPayload) > 0 && possibleKeyID == nil {
			possibleKeyID = childPayload
		}

		if id == 0x6D80 || id == 0x6240 || id == 0x5035 {
			if res := findContentEncKeyID(childPayload); res != nil {
				return res
			}
		}
	}
	return possibleKeyID
}

// parseEncryptedTracks scans a Tracks element's children to identify encrypted tracks and their Key IDs
func parseEncryptedTracks(payload []byte) (map[uint64]*TrackEncryption, error) {
	tracks := make(map[uint64]*TrackEncryption)
	r := bytes.NewReader(payload)
	for r.Len() > 0 {
		childID, _, err := readVINTID(r)
		if err != nil {
			return nil, err
		}
		childSize, _, err := readVINTSize(r)
		if err != nil {
			return nil, err
		}
		childPayload := make([]byte, childSize)
		if _, err := io.ReadFull(r, childPayload); err != nil {
			return nil, err
		}

		if childID == 0xAE { // TrackEntry
			trackNum, isEnc, keyID, err := parseTrackEntryInfo(childPayload)
			if err != nil {
				return nil, err
			}
			if isEnc {
				tracks[trackNum] = &TrackEncryption{
					IsEncrypted: true,
					KeyID:       keyID,
				}
			}
		}
	}
	return tracks, nil
}

// parseTrackEntryInfo parses inside a TrackEntry element and returns track attributes
func parseTrackEntryInfo(payload []byte) (uint64, bool, []byte, error) {
	r := bytes.NewReader(payload)
	var trackNum uint64
	var isEncrypted bool
	var keyID []byte

	for r.Len() > 0 {
		childID, _, err := readVINTID(r)
		if err != nil {
			return 0, false, nil, err
		}
		childSize, _, err := readVINTSize(r)
		if err != nil {
			return 0, false, nil, err
		}
		childPayload := make([]byte, childSize)
		if _, err := io.ReadFull(r, childPayload); err != nil {
			return 0, false, nil, err
		}

		switch childID {
		case 0xD7: // TrackNumber
			var val uint64
			for _, x := range childPayload {
				val = (val << 8) | uint64(x)
			}
			trackNum = val
		case 0x6D80: // ContentEncodings
			isEncrypted = true
			if kid := findContentEncKeyID(childPayload); kid != nil {
				keyID = kid
			}
		}
	}
	return trackNum, isEncrypted, keyID, nil
}

// filterMasterElement recursively filters out ContentEncodings (0x6D80) elements from Tracks structure
func filterMasterElement(payload []byte) ([]byte, error) {
	r := bytes.NewReader(payload)
	var outBuf bytes.Buffer

	for r.Len() > 0 {
		childID, childIDRaw, err := readVINTID(r)
		if err != nil {
			return nil, err
		}
		childSize, _, err := readVINTSize(r)
		if err != nil {
			return nil, err
		}

		childPayload := make([]byte, childSize)
		if _, err := io.ReadFull(r, childPayload); err != nil {
			return nil, err
		}

		if childID == 0x6D80 { // Skip ContentEncodings completely
			continue
		}

		if masterElements[childID] {
			filteredPayload, err := filterMasterElement(childPayload)
			if err != nil {
				return nil, err
			}
			outBuf.Write(encodeID(childID))
			outBuf.Write(encodeVINT(uint64(len(filteredPayload))))
			outBuf.Write(filteredPayload)
		} else {
			outBuf.Write(childIDRaw)
			outBuf.Write(encodeVINT(uint64(len(childPayload))))
			outBuf.Write(childPayload)
		}
	}

	return outBuf.Bytes(), nil
}

// decryptAndRebuildBlock decrypts block payload and outputs the new rebuilt block EBML element
func decryptAndRebuildBlock(elementID uint32, payload []byte, keys map[string][]byte, encryptedTracks map[uint64]*TrackEncryption) ([]byte, error) {
	trackNum, timecode, flags, headerSize, err := parseBlockHeader(payload)
	if err != nil {
		return nil, err
	}

	trackEnc := encryptedTracks[trackNum]
	if trackEnc == nil || !trackEnc.IsEncrypted {
		// Not an encrypted track, rebuild as is
		var elemBuf bytes.Buffer
		elemBuf.Write(encodeID(elementID))
		elemBuf.Write(encodeVINT(uint64(len(payload))))
		elemBuf.Write(payload)
		return elemBuf.Bytes(), nil
	}

	if len(trackEnc.KeyID) == 0 {
		return nil, fmt.Errorf("track %d is encrypted but has no Key ID in headers", trackNum)
	}

	keyIDStr := hex.EncodeToString(trackEnc.KeyID)
	key, ok := keys[keyIDStr]
	if !ok {
		return nil, fmt.Errorf("no decryption key provided for Track %d's Key ID: %s", trackNum, keyIDStr)
	}

	frameData := payload[headerSize:]
	res, err := ParseAndDecryptWebMBlock(frameData, trackEnc.KeyID, key)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(encodeVINT(trackNum))
	var tcBuf [2]byte
	binary.BigEndian.PutUint16(tcBuf[:], uint16(timecode))
	buf.Write(tcBuf[:])
	buf.WriteByte(flags)
	buf.Write(res.DecryptedData)

	var elemBuf bytes.Buffer
	elemBuf.Write(encodeID(elementID))
	elemBuf.Write(encodeVINT(uint64(buf.Len())))
	elemBuf.Write(buf.Bytes())

	return elemBuf.Bytes(), nil
}

// decryptBlockGroup parses a BlockGroup master and decrypts the Block (0xA1) inside
func decryptBlockGroup(payload []byte, keys map[string][]byte, encryptedTracks map[uint64]*TrackEncryption) ([]byte, error) {
	r := bytes.NewReader(payload)
	var outBuf bytes.Buffer

	for r.Len() > 0 {
		childID, childIDRaw, err := readVINTID(r)
		if err != nil {
			return nil, err
		}
		childSize, childSizeRaw, err := readVINTSize(r)
		if err != nil {
			return nil, err
		}

		childPayload := make([]byte, childSize)
		if _, err := io.ReadFull(r, childPayload); err != nil {
			return nil, err
		}

		if childID == 0xA1 { // Block element
			decryptedBlock, err := decryptAndRebuildBlock(0xA1, childPayload, keys, encryptedTracks)
			if err != nil {
				return nil, err
			}
			outBuf.Write(decryptedBlock)
		} else {
			outBuf.Write(childIDRaw)
			outBuf.Write(childSizeRaw)
			outBuf.Write(childPayload)
		}
	}

	return outBuf.Bytes(), nil
}

// DecryptWebMStream reads from r and streams decrypted/clear WebM data to w
func DecryptWebMStream(r io.Reader, w io.Writer, totalBytes int64, keys map[string][]byte) error {
	var pr *progressReader
	if totalBytes > 0 {
		pr = newProgressReader(r, totalBytes)
		r = pr
	}

	cw := &CountingWriter{W: w}
	br := bufio.NewReaderSize(r, 1024*1024) // 1MB buffer
	encryptedTracks := make(map[uint64]*TrackEncryption)

	var cues []CueRecord
	var segmentPayloadStart int64 = 0
	var seekHeadPlaceholderOffset int64 = 0
	var infoOffset uint64 = 0
	var tracksOffset uint64 = 0

	totalBlocks := 0
	decryptedBlocks := 0
	clearBlocks := 0

	for {
		id, idRaw, err := peekVINTID(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to peek ID: %w", err)
		}

		// Consume the ID
		if _, err := io.ReadFull(br, idRaw); err != nil {
			return err
		}

		size, sizeRaw, err := readVINTSize(br)
		if err != nil {
			return fmt.Errorf("failed to read size for ID %x: %w", id, err)
		}

		elementOffset := uint64(cw.N - segmentPayloadStart)
		switch id {
		case 0x1549A966:
			infoOffset = elementOffset
		case 0x1654AE6B:
			tracksOffset = elementOffset
		}

		// Segment (0x18538067) -> Stream with unknown size
		if id == 0x18538067 {
			cw.Write(idRaw)
			cw.Write([]byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // 8-byte unknown size
			segmentPayloadStart = cw.N

			// Pre-allocate 256 bytes for SeekHead using a Void element
			seekHeadPlaceholderOffset = cw.N
			cw.Write(buildVoidElement(256))
			continue
		}

		// Skip SeekHead (0x114D9B74) and Cues (0x1C53BB6B) from the input to prevent invalid byte-seeking offsets
		if id == 0x114D9B74 || id == 0x1C53BB6B {
			if _, err := io.CopyN(io.Discard, br, int64(size)); err != nil {
				return fmt.Errorf("failed to skip element %x: %w", id, err)
			}
			continue
		}

		// Tracks (0x1654AE6B) -> Parse, identify encrypted track numbers, strip encodings, and write
		if id == 0x1654AE6B {
			payload := make([]byte, size)
			if _, err := io.ReadFull(br, payload); err != nil {
				return fmt.Errorf("failed to read Tracks payload: %w", err)
			}

			// Extract encrypted track numbers
			parsedTracks, err := parseEncryptedTracks(payload)
			if err != nil {
				return fmt.Errorf("failed to parse Tracks: %w", err)
			}
			encryptedTracks = parsedTracks
			fmt.Printf("\n[DEMUX] Identified encrypted track IDs:\n")
			for tid, trackEnc := range encryptedTracks {
				fmt.Printf("  * Track #%d [ENCRYPTED] with Key ID: %x\n", tid, trackEnc.KeyID)
			}

			// Filter ContentEncodings out of Tracks element
			filtered, err := filterMasterElement(payload)
			if err != nil {
				return fmt.Errorf("failed to filter ContentEncodings: %w", err)
			}

			cw.Write(idRaw)
			cw.Write(encodeVINT(uint64(len(filtered))))
			cw.Write(filtered)
			continue
		}

		// Cluster (0x1F43B675) -> Parse and decrypt child elements sequentially
		if id == 0x1F43B675 {
			clusterOffset := uint64(cw.N - segmentPayloadStart)
			var clusterTimecode uint64 = 0
			hasClusterTimecode := false

			cw.Write(idRaw)
			cw.Write([]byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // 8-byte unknown size

			var bytesRead uint64 = 0
			hasLimit := !isUnknownSizeVal(size, len(sizeRaw))

			for {
				if hasLimit && bytesRead >= size {
					break
				}

				nextID, nextIDRaw, err := peekVINTID(br)
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("failed to peek inside cluster: %w", err)
				}

				// If the element is not a Cluster child, terminate this cluster's parsing
				if !clusterChildren[nextID] {
					break
				}

				// Consume next ID
				if _, err := io.ReadFull(br, nextIDRaw); err != nil {
					return err
				}
				bytesRead += uint64(len(nextIDRaw))

				childSize, childSizeRaw, err := readVINTSize(br)
				if err != nil {
					return fmt.Errorf("failed to read child size for ID %x: %w", nextID, err)
				}
				bytesRead += uint64(len(childSizeRaw))
				bytesRead += childSize

				childPayload := make([]byte, childSize)
				if _, err := io.ReadFull(br, childPayload); err != nil {
					return fmt.Errorf("failed to read child %x payload: %w", nextID, err)
				}

				if nextID == 0xE7 { // Timecode
					var val uint64
					for _, x := range childPayload {
						val = (val << 8) | uint64(x)
					}
					clusterTimecode = val
					hasClusterTimecode = true
				}

				switch nextID {
				case 0xA3: // SimpleBlock
					totalBlocks++
					decryptedBlock, err := decryptAndRebuildBlock(0xA3, childPayload, keys, encryptedTracks)
					if err != nil {
						log.Printf("Warning: Failed to decrypt SimpleBlock: %v. Copying as clear fallback.", err)
						cw.Write(nextIDRaw)
						cw.Write(childSizeRaw)
						cw.Write(childPayload)
						clearBlocks++
					} else {
						cw.Write(decryptedBlock)
						decryptedBlocks++
					}
				case 0xA0: // BlockGroup
					totalBlocks++
					decryptedBlockGroup, err := decryptBlockGroup(childPayload, keys, encryptedTracks)
					if err != nil {
						log.Printf("Warning: Failed to decrypt BlockGroup: %v. Copying as clear fallback.", err)
						cw.Write(nextIDRaw)
						cw.Write(childSizeRaw)
						cw.Write(childPayload)
						clearBlocks++
					} else {
						cw.Write(encodeID(0xA0))
						cw.Write(encodeVINT(uint64(len(decryptedBlockGroup))))
						cw.Write(decryptedBlockGroup)
						decryptedBlocks++
					}
				default:
					// Other elements (e.g. cluster timecode)
					cw.Write(nextIDRaw)
					cw.Write(childSizeRaw)
					cw.Write(childPayload)
				}
			}

			// Add a CuePoint entry for this Cluster
			if hasClusterTimecode {
				cues = append(cues, CueRecord{
					Timecode: clusterTimecode,
					Offset:   clusterOffset,
				})
			}
			continue
		}

		// Copy any other top-level EBML elements as-is
		cw.Write(idRaw)
		cw.Write(sizeRaw)
		if size > 0 {
			if _, err := io.CopyN(cw, br, int64(size)); err != nil {
				return fmt.Errorf("failed to copy element payload %x: %w", id, err)
			}
		}
	}

	// Dynamically rebuild and append Cues (index) at the end of the WebM Segment
	var cuesOffset uint64 = 0
	if len(cues) > 0 {
		var videoTrackNum uint64 = 1
		for tid := range encryptedTracks {
			videoTrackNum = tid
			break
		}

		cuesOffset = uint64(cw.N - segmentPayloadStart)
		cuesElement := buildCuesElement(cues, videoTrackNum)
		cw.Write(cuesElement)
		fmt.Printf("\n[MUX] Rebuilt index and appended %d CuePoints to the end of the file.\n", len(cues))
	}

	// Overwrite SeekHead placeholder and Segment size if seeker
	if ws, isSeeker := w.(io.WriteSeeker); isSeeker {
		currentOffset, err := ws.Seek(0, io.SeekCurrent)
		if err == nil {
			// 1. Overwrite Segment size (8 bytes before segmentPayloadStart)
			if segmentPayloadStart > 0 {
				_, err = ws.Seek(segmentPayloadStart-8, io.SeekStart)
				if err == nil {
					finalSize := uint64(currentOffset - segmentPayloadStart)
					ws.Write(encodeVINT8Bytes(finalSize))
					fmt.Printf("[MUX] Updated Segment size to %d bytes.\n", finalSize)
				}
			}

			// 2. Overwrite SeekHead placeholder
			if seekHeadPlaceholderOffset > 0 {
				_, err = ws.Seek(seekHeadPlaceholderOffset, io.SeekStart)
				if err == nil {
					seekHeadBytes := buildSeekHeadElement(infoOffset, tracksOffset, cuesOffset)
					paddingSize := 256 - len(seekHeadBytes)
					ws.Write(seekHeadBytes)
					if paddingSize >= 2 {
						ws.Write(buildVoidElement(paddingSize))
					}
					fmt.Printf("[MUX] Successfully wrote SeekHead pointing to Info (%d), Tracks (%d), Cues (%d)\n", infoOffset, tracksOffset, cuesOffset)
				}
			}

			// 3. Restore seek offset
			ws.Seek(currentOffset, io.SeekStart)
		}
	}

	if pr != nil {
		pr.finalize()
	}

	fmt.Printf("\n[DECRYPT] Processing complete:\n")
	fmt.Printf("  - Total Media Blocks Scanned: %d\n", totalBlocks)
	fmt.Printf("  - Decrypted blocks successfully: %d\n", decryptedBlocks)
	fmt.Printf("  - Clear blocks/skipped:        %d\n", clearBlocks)

	return nil
}
