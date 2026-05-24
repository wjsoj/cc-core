// Package eventstream implements AWS event-stream binary frame codec.
//
// Wire format per frame (big-endian):
//
//	+----------------+----------------+----------------+---------+---------+----------+
//	| Total Length   | Header Length  | Prelude CRC32  | Headers | Payload | Msg CRC  |
//	|   (4 bytes)    |   (4 bytes)    |   (4 bytes)    | (var)   | (var)   | (4 bytes)|
//	+----------------+----------------+----------------+---------+---------+----------+
//
// CRC32 is the ISO-HDLC polynomial (also used by ZIP / Ethernet).
package eventstream

import "hash/crc32"

var crcTable = crc32.IEEETable

// CRC32 returns the ISO-HDLC CRC32 checksum of data.
func CRC32(data []byte) uint32 {
	return crc32.Checksum(data, crcTable)
}
