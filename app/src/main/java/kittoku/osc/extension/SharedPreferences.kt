package kittoku.osc.extension

import android.content.SharedPreferences
import androidx.core.content.edit
import kittoku.osc.preference.TEMP_KEY_HEADER


internal fun SharedPreferences.removeTemporaryPreferences() {
    edit {
        all.keys.filter { it.startsWith(TEMP_KEY_HEADER) }.forEach { remove(it) }
    }
}
