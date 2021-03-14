package kittoku.opensstpclient.fragment

import android.text.TextUtils
import androidx.preference.EditTextPreference
import androidx.preference.Preference


internal val normalSummaryProvider = Preference.SummaryProvider<EditTextPreference> {
    if (TextUtils.isEmpty(it.text)) {
        "[No Value Entered]"
    } else {
        it.text
    }
}

internal val passwordSummaryProvider = Preference.SummaryProvider<EditTextPreference> {
    if (TextUtils.isEmpty(it.text)) {
        "[No Value Entered]"
    } else {
        "[Password Entered]"
    }
}

internal val numSummaryProvider = Preference.SummaryProvider<EditTextPreference> {
    if (TextUtils.isEmpty(it.text)) {
        "DEFAULT"
    } else {
        it.text
    }
}

internal val zeroDefaultSummaryProvider = Preference.SummaryProvider<EditTextPreference> {
    if (TextUtils.isEmpty(it.text) || it.text == "0") {
        "DEFAULT"
    } else {
        it.text
    }
}
