package com.arcansecurity.vpn.l2tpipsec.core.net

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException

/**
 * Minimal IPv4 header view (RFC 791 section 3.1), used to inspect the packets the TUN interface
 * hands us and to build the ones we inject back into it.
 *
 * Only the fixed 20-byte part is modelled. Options are parsed over but not retained, and [encode]
 * always emits `ihl = 5`; the tunnel never needs to forward options, and dropping them keeps the
 * encoded header a fixed 20 bytes.
 *
 * The ECN bits of the traffic-class byte are likewise not modelled: [dscp] is the upper 6 bits and
 * [encode] writes the ECN bits back as zero.
 */
data class Ipv4Header(
    val version: Int,
    val ihl: Int,
    val dscp: Int,
    val totalLength: Int,
    val identification: Int,
    val flags: Int,
    val fragmentOffset: Int,
    val ttl: Int,
    val protocol: Int,
    val headerChecksum: Int,
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
) {

    /** Length in bytes of the header as it appeared on the wire, options included. */
    val headerLength: Int get() = ihl * 4

    /** Length in bytes of the payload that follows the header. */
    val payloadLength: Int get() = totalLength - headerLength

    val sourceIp: String get() = Bytes.ipv4ToString(sourceAddress)
    val destinationIp: String get() = Bytes.ipv4ToString(destinationAddress)

    /** True for a packet that is a fragment, i.e. one we cannot interpret on its own. */
    val isFragment: Boolean get() = fragmentOffset != 0 || (flags and FLAG_MORE_FRAGMENTS) != 0

    /**
     * Serialises a fresh 20-byte header for a payload of [payloadLength] bytes, recomputing
     * `totalLength` and the header checksum. [headerChecksum] and [ihl] of this instance are
     * ignored, so a header parsed from the wire can be re-emitted after any field was changed.
     */
    fun encode(payloadLength: Int): ByteArray {
        require(payloadLength >= 0) { "negative payload length $payloadLength" }
        val total = MIN_HEADER_SIZE + payloadLength
        require(total <= 0xFFFF) { "IPv4 total length $total does not fit in 16 bits" }
        val w = ByteWriter(MIN_HEADER_SIZE)
        w.u8((4 shl 4) or 5)
        w.u8((dscp and 0x3F) shl 2)
        w.u16(total)
        w.u16(identification and 0xFFFF)
        w.u16(((flags and 0x7) shl 13) or (fragmentOffset and 0x1FFF))
        w.u8(ttl and 0xFF)
        w.u8(protocol and 0xFF)
        val checksumAt = w.reserve(2)
        w.bytes(sourceAddress, 0, 4)
        w.bytes(destinationAddress, 0, 4)
        val out = w.toByteArray()
        // The checksum covers the header only, with its own field taken as zero (RFC 791 s. 3.1).
        val sum = InternetChecksum.compute(out, 0, MIN_HEADER_SIZE)
        out[checksumAt] = (sum ushr 8).toByte()
        out[checksumAt + 1] = sum.toByte()
        return out
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Ipv4Header) return false
        return version == other.version && ihl == other.ihl && dscp == other.dscp &&
            totalLength == other.totalLength && identification == other.identification &&
            flags == other.flags && fragmentOffset == other.fragmentOffset && ttl == other.ttl &&
            protocol == other.protocol && headerChecksum == other.headerChecksum &&
            sourceAddress.contentEquals(other.sourceAddress) &&
            destinationAddress.contentEquals(other.destinationAddress)
    }

    override fun hashCode(): Int {
        var h = version
        h = 31 * h + ihl
        h = 31 * h + dscp
        h = 31 * h + totalLength
        h = 31 * h + identification
        h = 31 * h + flags
        h = 31 * h + fragmentOffset
        h = 31 * h + ttl
        h = 31 * h + protocol
        h = 31 * h + headerChecksum
        h = 31 * h + sourceAddress.contentHashCode()
        h = 31 * h + destinationAddress.contentHashCode()
        return h
    }

    override fun toString(): String =
        "Ipv4Header($sourceIp -> $destinationIp proto=$protocol len=$totalLength ttl=$ttl)"

    companion object {
        const val MIN_HEADER_SIZE = 20

        const val PROTO_UDP = 17
        const val PROTO_TCP = 6
        const val PROTO_ICMP = 1
        /** ESP, only ever seen here in the RFC 3948 transport-mode reference diagrams. */
        const val PROTO_ESP = 50

        const val FLAG_DONT_FRAGMENT = 0x2
        const val FLAG_MORE_FRAGMENTS = 0x1

        fun parse(data: ByteArray, offset: Int = 0): Ipv4Header {
            val r = ByteReader(data, offset)
            val versionIhl = r.u8()
            val version = versionIhl ushr 4
            val ihl = versionIhl and 0x0F
            if (version != 4) throw ProtocolException("not an IPv4 packet: version $version")
            if (ihl < 5) throw ProtocolException("IPv4 IHL $ihl is below the 5-word minimum")
            // ihl is 4 bits, so ihl * 4 is at most 60 and the comparison cannot overflow.
            if (data.size - offset < ihl * 4) {
                throw ProtocolException("truncated IPv4 header: ${data.size - offset} < ${ihl * 4}")
            }
            val tos = r.u8()
            val totalLength = r.u16()
            if (totalLength < ihl * 4) {
                throw ProtocolException("IPv4 total length $totalLength is below the header size ${ihl * 4}")
            }
            val identification = r.u16()
            val flagsFragment = r.u16()
            val ttl = r.u8()
            val protocol = r.u8()
            val checksum = r.u16()
            val src = r.bytes(4)
            val dst = r.bytes(4)
            return Ipv4Header(
                version = version,
                ihl = ihl,
                dscp = tos ushr 2,
                totalLength = totalLength,
                identification = identification,
                flags = flagsFragment ushr 13,
                fragmentOffset = flagsFragment and 0x1FFF,
                ttl = ttl,
                protocol = protocol,
                headerChecksum = checksum,
                sourceAddress = src,
                destinationAddress = dst,
            )
        }

        /**
         * Cheap version probe for packets read from the TUN file descriptor, which carry no link
         * layer and therefore no EtherType to dispatch on. Returns 4, 6, or -1 when the buffer is
         * too short to be a header of the version its first nibble claims.
         */
        fun ipVersion(data: ByteArray, offset: Int, length: Int): Int {
            // A subtraction, not a sum: `offset + length` can overflow and wrap the check into a
            // pass, which would report a version for bytes that are not in the buffer.
            if (offset < 0 || length <= 0 || length > data.size - offset) return -1
            return when ((data[offset].toInt() ushr 4) and 0x0F) {
                4 -> if (length >= MIN_HEADER_SIZE) 4 else -1
                6 -> if (length >= IPV6_HEADER_SIZE) 6 else -1
                else -> -1
            }
        }

        private const val IPV6_HEADER_SIZE = 40
    }
}
