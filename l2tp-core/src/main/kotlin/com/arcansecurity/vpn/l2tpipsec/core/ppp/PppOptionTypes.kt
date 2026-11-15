package com.arcansecurity.vpn.l2tpipsec.core.ppp

/** LCP configuration option types (RFC 1661 section 6). */
object LcpOption {
    const val MRU = 1
    const val AUTH_PROTOCOL = 3
    const val QUALITY_PROTOCOL = 4
    const val MAGIC_NUMBER = 5

    /** Protocol-Field-Compression; never requested and always rejected by this client. */
    const val PFC = 7

    /** Address-and-Control-Field-Compression; never requested and always rejected by this client. */
    const val ACFC = 8
}

/** IPCP configuration option types (RFC 1332 section 3 and RFC 1877 section 1). */
object IpcpOption {
    const val IP_COMPRESSION_PROTOCOL = 2
    const val IP_ADDRESS = 3
    const val PRIMARY_DNS = 129
    const val PRIMARY_NBNS = 130
    const val SECONDARY_DNS = 131
    const val SECONDARY_NBNS = 132
}
