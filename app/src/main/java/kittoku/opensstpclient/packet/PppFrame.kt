package kittoku.opensstpclient.packet

import kittoku.opensstpclient.misc.PppCredential
import kittoku.opensstpclient.misc.PppParsingError
import java.net.InetAddress
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.charset.Charset


internal const val PPP_HEADER = 0xFF03.toShort()

internal enum class PppProtocol(val value: Short) {
    LCP(0xC021.toShort()),
    PAP(0xC023.toShort()),
    IPCP(0x8021.toShort()),
    IP(0x0021.toShort())
}

internal class PppLcpFrame : ControlFrame() {
    internal enum class Code(val value: Byte) {
        CONFIGURE_REQUEST(0x01),
        CONFIGURE_ACK(0x02),
        CONFIGURE_NAK(0x03),
        CONFIGURE_REJECT(0x04),
        TERMINATE_REQUEST(0x05),
        TERMINATE_ACK(0x06),
        ECHO_REQUEST(0x09),
        ECHO_REPLY(0x0A)
    }

    internal enum class Option(val value: Byte) {
        MRU(0x01),
        AUTH(0x03)
    }

    internal enum class AuthProtocol(val value: Short) {
        PAP(0xC023.toShort()),
        OTHER(0)
    }

    internal var code: Code? = null
    internal var id: Byte = 0
    internal var lengthMessage: Short = 0
    internal var mru: Short? = null
    internal var auth: AuthProtocol? = null
    internal var unknownOption: MutableList<Byte> = mutableListOf()
    internal var magicNumber: Int = 0

    override fun read(bytes: ByteBuffer) {
        // reading starts with Code
        code = when(bytes.get()) {
            Code.CONFIGURE_REQUEST.value -> Code.CONFIGURE_REQUEST
            Code.CONFIGURE_ACK.value -> Code.CONFIGURE_ACK
            Code.CONFIGURE_NAK.value -> Code.CONFIGURE_NAK
            Code.CONFIGURE_REJECT.value -> Code.CONFIGURE_REJECT
            Code.TERMINATE_REQUEST.value -> Code.TERMINATE_REQUEST
            Code.TERMINATE_ACK.value -> Code.TERMINATE_ACK
            Code.ECHO_REQUEST.value -> Code.ECHO_REQUEST
            Code.ECHO_REPLY.value -> Code.ECHO_REPLY
            else -> null
        }

        id = bytes.get()
        lengthMessage = bytes.short

        when (code) {
            Code.CONFIGURE_REQUEST, Code.CONFIGURE_ACK, Code.CONFIGURE_NAK, Code.CONFIGURE_REJECT -> {
                var remaining: Int = lengthMessage - 4
                while (remaining > 0) {
                    val option: Byte = bytes.get()
                    val optLength: Byte = bytes.get()

                    when (option) {
                        Option.MRU.value -> mru = bytes.short
                        Option.AUTH.value -> {
                            auth = if (bytes.short == AuthProtocol.PAP.value) AuthProtocol.PAP else AuthProtocol.OTHER
                            repeat(optLength - 4) { bytes.get() } // discard
                        }
                        else -> {
                            unknownOption.add(option)
                            unknownOption.add(optLength)
                            repeat(optLength - 2) { unknownOption.add(bytes.get()) }
                        }
                    }
                    remaining -= optLength
                }
            }
            Code.TERMINATE_REQUEST, Code.TERMINATE_ACK, null -> {
                val tmpBytes = ByteArray(lengthMessage - 4)
                bytes.get(tmpBytes)
            }
            Code.ECHO_REQUEST, Code.ECHO_REPLY -> {
                magicNumber = bytes.int
                val tmpBytes = ByteArray(lengthMessage - 8)
                bytes.get(tmpBytes)
            }
        }
    }

    override fun write(bytes: ByteBuffer) {
        // writing starts with Address Field
        bytes.putShort(PPP_HEADER)
        bytes.putShort(PppProtocol.LCP.value)
        bytes.put(code!!.value)
        bytes.put(id)

        when (code) {
            Code.CONFIGURE_REQUEST, Code.CONFIGURE_ACK, Code.CONFIGURE_NAK, Code.CONFIGURE_REJECT -> {
                lengthMessage = (4 + unknownOption.size).toShort()
                if (mru != null) lengthMessage = (4 + lengthMessage).toShort()
                if (auth != null) lengthMessage = (4 + lengthMessage).toShort()

                bytes.putShort(lengthMessage)
                mru?.apply { bytes.put(Option.MRU.value).put(4).putShort(this) }
                auth?.apply { bytes.put(Option.AUTH.value).put(4).putShort(value) }

                unknownOption.forEach { bytes.put(it) }
            }
            Code.TERMINATE_REQUEST -> {
                lengthMessage = 0x0D
                bytes.putShort(lengthMessage)
                bytes.put("I'm done.".toByteArray(Charset.forName("US-ASCII")))
            }
            Code.TERMINATE_ACK -> {
                lengthMessage = 4
                bytes.putShort(lengthMessage)
            }
            Code.ECHO_REQUEST, Code.ECHO_REPLY -> {
                lengthMessage = 24
                bytes.putShort(lengthMessage)
                bytes.putInt(magicNumber)
                bytes.put("Ijime Zettai No.".toByteArray(Charset.forName("US-ASCII")))
            }
        }
    }
}

internal class PppParFrame : ControlFrame() {
    internal enum class Code(val value: Byte) {
        AUTHENTICATE_REQUEST(0x01),
        AUTHENTICATE_ACK(0x02),
        AUTHENTICATE_NAK(0x03)
    }

    internal var code: Code? = null
    internal var id: Byte = 0
    internal var lengthMessage: Short = 0
    internal lateinit var credential: PppCredential

    override fun read(bytes: ByteBuffer) {
        // reading starts with Code
        code = when (bytes.get()) {
            Code.AUTHENTICATE_REQUEST.value -> Code.AUTHENTICATE_REQUEST
            Code.AUTHENTICATE_ACK.value -> Code.AUTHENTICATE_ACK
            Code.AUTHENTICATE_NAK.value -> Code.AUTHENTICATE_NAK
            else -> throw PppParsingError("Invalid PPP PAP code")
        }

        id = bytes.get()
        lengthMessage = bytes.short

        when (code) {
            Code.AUTHENTICATE_REQUEST -> {
                val uLength = bytes.get().toInt()
                val uBytes = ByteArray(uLength)
                bytes.get(uBytes)

                val pLength = bytes.get().toInt()
                val pBytes = ByteArray(pLength)
                bytes.get(pBytes)

                credential = PppCredential(
                    uBytes.toString(Charset.forName("US-ASCII")),
                    pBytes.toString(Charset.forName("US-ASCII"))
                )
            }
            Code.AUTHENTICATE_ACK, Code.AUTHENTICATE_NAK -> {
                try {
                    val tmpLength = bytes.get().toInt()
                    val tmpBytes = ByteArray(tmpLength)
                    bytes.get(tmpBytes)
                } catch (e: BufferUnderflowException) {}
            }
        }
    }

    override fun write(bytes: ByteBuffer) {
        // writing starts with Address Field
        bytes.putShort(PPP_HEADER)
        bytes.putShort(PppProtocol.PAP.value)
        bytes.put(code!!.value)
        bytes.put(id)

        when (code) {
            Code.AUTHENTICATE_REQUEST -> {
                val uBytes = credential.username.toByteArray(Charset.forName("US-ASCII"))
                val uLength = uBytes.size

                val pBytes = credential.password.toByteArray(Charset.forName("US-ASCII"))
                val pLength = pBytes.size

                lengthMessage = (uLength + pLength + 6).toShort()

                bytes.putShort(lengthMessage)
                bytes.put(uLength.toByte()).put(uBytes)
                bytes.put(pLength.toByte()).put(pBytes)
            }
            Code.AUTHENTICATE_ACK -> {
                lengthMessage = 5
                bytes.putShort(lengthMessage)
                bytes.put(0)
            }
            Code.AUTHENTICATE_NAK -> {
                lengthMessage = 0x21
                bytes.putShort(lengthMessage)
                bytes.put(0x1C)
                bytes.put("Unknown peer-ID or password.".toByteArray(Charset.forName("US-ASCII")))
            }
        }
    }
}

internal class PppIpcpFrame : ControlFrame() {
    internal enum class Code(val value: Byte) {
        CONFIGURE_REQUEST(0x01),
        CONFIGURE_ACK(0x02),
        CONFIGURE_NAK(0x03),
        CONFIGURE_REJECT(0x04),
        TERMINATE_REQUEST(0x05),
        TERMINATE_ACK(0x06),
    }

    internal enum class Option(val value: Byte) {
        IP_ADDRESS(0x03),
        PRIMARY_DNS(0x81.toByte())
    }

    internal var code: Code? = null
    internal var id: Byte = 0
    internal var lengthMessage: Short = 0
    internal var ipAddress: InetAddress? = null
    internal var primaryDns: InetAddress? = null
    internal var unknownOption: MutableList<Byte> = mutableListOf()

    override fun read(bytes: ByteBuffer) {
        // reading starts with Code
        code = when(bytes.get()) {
            Code.CONFIGURE_REQUEST.value -> Code.CONFIGURE_REQUEST
            Code.CONFIGURE_ACK.value -> Code.CONFIGURE_ACK
            Code.CONFIGURE_NAK.value -> Code.CONFIGURE_NAK
            Code.CONFIGURE_REJECT.value -> Code.CONFIGURE_REJECT
            Code.TERMINATE_REQUEST.value -> Code.TERMINATE_REQUEST
            Code.TERMINATE_ACK.value -> Code.TERMINATE_ACK
            else -> null
        }

        id = bytes.get()
        lengthMessage = bytes.short

        when (code) {
            Code.CONFIGURE_REQUEST, Code.CONFIGURE_ACK, Code.CONFIGURE_NAK, Code.CONFIGURE_REJECT -> {
                var remaining: Int = lengthMessage - 4
                while (remaining > 0) {
                    val option: Byte = bytes.get()
                    val optLength: Byte = bytes.get()

                    when (option) {
                        Option.IP_ADDRESS.value -> ipAddress = InetAddress.getByAddress(ByteArray(4) { bytes.get() })
                        Option.PRIMARY_DNS.value -> primaryDns = InetAddress.getByAddress(ByteArray(4) { bytes.get() })
                        else -> {
                            unknownOption.add(option)
                            unknownOption.add(optLength)
                            repeat(optLength - 2) { unknownOption.add(bytes.get()) }
                        }
                    }
                    remaining -= optLength
                }
            }
            Code.TERMINATE_REQUEST, Code.TERMINATE_ACK, null -> {
                val tmpBytes = ByteArray(lengthMessage - 4)
                bytes.get(tmpBytes)
            }
        }
    }

    override fun write(bytes: ByteBuffer) {
        // writing starts with Address Field
        bytes.putShort(PPP_HEADER)
        bytes.putShort(PppProtocol.IPCP.value)
        bytes.put(code!!.value)
        bytes.put(id)

        when (code) {
            Code.CONFIGURE_REQUEST, Code.CONFIGURE_ACK, Code.CONFIGURE_NAK, Code.CONFIGURE_REJECT -> {
                lengthMessage = (4 + unknownOption.size).toShort()
                if (ipAddress != null) { lengthMessage = (lengthMessage + 6).toShort() }
                if (primaryDns != null) { lengthMessage = (lengthMessage + 6).toShort() }

                bytes.putShort(lengthMessage)
                ipAddress?.apply {
                    bytes.put(Option.IP_ADDRESS.value)
                    bytes.put(6)
                    address.forEach { bytes.put(it) }
                }
                primaryDns?.apply {
                    bytes.put(Option.PRIMARY_DNS.value)
                    bytes.put(6)
                    address.forEach { bytes.put(it) }
                }

                unknownOption.forEach { bytes.put(it) }
            }
            Code.TERMINATE_REQUEST -> {
                lengthMessage = 0x0D
                bytes.putShort(lengthMessage)
                bytes.put("I'm done.".toByteArray(Charset.forName("US-ASCII")))
            }
            Code.TERMINATE_ACK -> {
                lengthMessage = 4
                bytes.putShort(lengthMessage)
            }
        }
    }
}

internal abstract class ControlFrame {
    internal abstract fun read(bytes: ByteBuffer)
    internal abstract fun write(bytes: ByteBuffer)
}