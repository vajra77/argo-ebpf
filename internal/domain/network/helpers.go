/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package network

const hexDigits = "0123456789abcdef"

// FormatMAC converte un array di 6 byte in una stringa MAC formattata a 12 caratteri esadecimali
// senza usare reflection o fmt.Sprintf per massimizzare le prestazioni nel throughput eBPF.
func FormatMAC(mac [6]byte) string {
	var buf [12]byte
	buf[0] = hexDigits[mac[0]>>4]
	buf[1] = hexDigits[mac[0]&0x0f]
	buf[2] = hexDigits[mac[1]>>4]
	buf[3] = hexDigits[mac[1]&0x0f]
	buf[4] = hexDigits[mac[2]>>4]
	buf[5] = hexDigits[mac[2]&0x0f]
	buf[6] = hexDigits[mac[3]>>4]
	buf[7] = hexDigits[mac[3]&0x0f]
	buf[8] = hexDigits[mac[4]>>4]
	buf[9] = hexDigits[mac[4]&0x0f]
	buf[10] = hexDigits[mac[5]>>4]
	buf[11] = hexDigits[mac[5]&0x0f]
	return string(buf[:])
}

func FormatMACWithColons(mac [6]byte) string {
	var buf [17]byte
	buf[0] = hexDigits[mac[0]>>4]
	buf[1] = hexDigits[mac[0]&0x0f]
	buf[2] = ':'
	buf[3] = hexDigits[mac[1]>>4]
	buf[4] = hexDigits[mac[1]&0x0f]
	buf[5] = ':'
	buf[6] = hexDigits[mac[2]>>4]
	buf[7] = hexDigits[mac[2]&0x0f]
	buf[8] = ':'
	buf[9] = hexDigits[mac[3]>>4]
	buf[10] = hexDigits[mac[3]&0x0f]
	buf[11] = ':'
	buf[12] = hexDigits[mac[4]>>4]
	buf[13] = hexDigits[mac[4]&0x0f]
	buf[14] = ':'
	buf[15] = hexDigits[mac[5]>>4]
	buf[16] = hexDigits[mac[5]&0x0f]
	return string(buf[:])
}
