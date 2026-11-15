package kittoku.osc

import java.util.Locale

internal fun flagEmoji(code: String): String {
    val c = code.trim().uppercase(Locale.US)
    if (c.length != 2 || c.any { it !in 'A'..'Z' }) return ""
    return String(Character.toChars(0x1F1E6 + (c[0] - 'A'))) + String(Character.toChars(0x1F1E6 + (c[1] - 'A')))
}
