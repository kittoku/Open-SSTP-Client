package kittoku.osc.extension

import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.core.view.children


internal fun View.firstEditText(): EditText {
    if (this is EditText) {
        return this
    }

    val viewGroups = mutableListOf<ViewGroup>()
    if (this is ViewGroup) {
        viewGroups.add(this)
    }

    while (true) {
        viewGroups.removeAt(0).children.forEach {
            if (it is EditText) {
                return it
            }

            if (it is ViewGroup) {
                viewGroups.add(it)
            }
        }

        if (viewGroups.isEmpty()) {
            throw NotImplementedError()
        }
    }
}
