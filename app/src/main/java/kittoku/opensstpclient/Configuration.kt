package kittoku.opensstpclient


internal const val INCOMING_BUFFER_SIZE = 16384
internal const val OUTGOING_BUFFER_SIZE = 2048
internal const val MAX_MRU = INCOMING_BUFFER_SIZE - 8
internal const val MAX_MTU = OUTGOING_BUFFER_SIZE - 8
internal const val MIN_MRU = 68
internal const val MIN_MTU = 68
internal const val DEFAULT_MRU = 1500
internal const val DEFAULT_MTU = 1500
internal const val MAX_INTERVAL = 100
internal const val INTERVAL_STEP = 10
