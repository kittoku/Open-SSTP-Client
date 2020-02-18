package kittoku.opensstpclient


internal const val MAX_MRU = 16384
internal const val MAX_MTU = 2048
internal const val MIN_MRU = 68
internal const val MIN_MTU = 68
internal const val INCOMING_BUFFER_SIZE = MAX_MRU + 8
internal const val OUTGOING_BUFFER_SIZE = MAX_MTU + 8
internal const val DEFAULT_MRU = 1500
internal const val DEFAULT_MTU = 1500
internal const val MAX_INTERVAL = 100L
internal const val INTERVAL_STEP = 10L
