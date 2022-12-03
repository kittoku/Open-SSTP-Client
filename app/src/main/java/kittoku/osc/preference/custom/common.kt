package kittoku.osc.preference.custom

import androidx.preference.Preference
import kittoku.osc.preference.OscPrefKey


internal interface OscPreference {
    val oscPrefKey: OscPrefKey
    val parentKey: OscPrefKey?
    val preferenceTitle: String
    fun updateView()
}

internal fun Preference.initialize(oscPreference: OscPreference) {
    title = oscPreference.preferenceTitle
    isSingleLineTitle = false

    oscPreference.parentKey?.also { dependency = it.name }

    oscPreference.updateView()
}
