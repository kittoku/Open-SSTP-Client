package com.arcansecurity.vpn.l2tpipsec.core.l2tp

/**
 * Decoding of the Result Code AVP (RFC 2661 section 4.4.2).
 *
 * ```
 * |      Result Code      |  Error Code (opt) |  Error Message (opt) ...
 * ```
 *
 * The result code namespace differs between StopCCN and CDN, the error code namespace is shared.
 * Turning these numbers into a sentence is the difference between "the VPN failed" and "the
 * router rejected the account", so the tables are reproduced in full.
 */
object L2tpResultCodes {

    /** StopCCN result codes: why the control connection is going away. */
    private val stopCcn = mapOf(
        1 to "general request to clear the control connection",
        2 to "general error",
        3 to "control channel already exists",
        4 to "requester is not authorized to establish a control channel",
        5 to "the protocol version of the requester is not supported",
        6 to "requester is being shut down",
        7 to "finite state machine error",
    )

    /** CDN result codes: why the call is going away. */
    private val cdn = mapOf(
        1 to "call disconnected due to loss of carrier",
        2 to "call disconnected for the reason given by the error code",
        3 to "call disconnected for administrative reasons",
        4 to "call failed, facilities temporarily unavailable",
        5 to "call failed, facilities permanently unavailable",
        6 to "invalid destination",
        7 to "call failed, no carrier detected",
        8 to "call failed, busy signal detected",
        9 to "call failed, no dial tone",
        10 to "call was not established within the time allotted by the LAC",
        11 to "call connected but no appropriate framing was detected",
    )

    /** General error codes, shared by every message that can carry a Result Code AVP. */
    private val errors = mapOf(
        0 to "no general error",
        1 to "no control connection exists yet for this LAC-LNS pair",
        2 to "length is wrong",
        3 to "a field value was out of range or a reserved field was non-zero",
        4 to "insufficient resources to handle this operation now",
        5 to "the session id is invalid in this context",
        6 to "a generic vendor-specific error occurred",
        7 to "try another LNS",
        8 to "shut down because of an unknown AVP with the mandatory bit set",
    )

    /**
     * Renders the Result Code AVP of a StopCCN or CDN as a sentence suitable for the UI, falling
     * back to the raw numbers for codes the RFC does not define.
     */
    fun describe(messageType: L2tpMessageType, avps: List<L2tpAvp>): String {
        val avp = avps.find(L2tpAvpType.ResultCode)
            ?: return "${messageType.name} without a Result Code AVP"
        val value = avp.value
        if (value.size < 2) return "${messageType.name} with a malformed Result Code AVP"

        val result = ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
        val table = if (messageType == L2tpMessageType.CDN) cdn else stopCcn
        val sb = StringBuilder()
        sb.append(messageType.name).append(": ")
        sb.append(table[result] ?: "result code $result")
        if (table.containsKey(result)) sb.append(" (result ").append(result).append(')')

        if (value.size >= 4) {
            val error = ((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)
            // Error code 0 carries no information beyond "the result code says it all".
            if (error != 0 || value.size > 4) {
                sb.append("; ").append(errors[error] ?: "error code $error")
                if (errors.containsKey(error)) sb.append(" (error ").append(error).append(')')
            }
        }
        if (value.size > 4) {
            val message = String(value, 4, value.size - 4, Charsets.UTF_8).trimEnd(Char.MIN_VALUE)
            if (message.isNotEmpty()) sb.append("; \"").append(message).append('"')
        }
        return sb.toString()
    }
}
