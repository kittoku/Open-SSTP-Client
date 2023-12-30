package kittoku.osc.io.incoming

internal class EchoTimer(private val interval: Long, private val echoFunction: suspend () -> Unit) {
    private var lastTicked = 0L
    private var deadline = 0L

    private var isEchoWaited = false

    private val isOutOfTime: Boolean
        get() = System.currentTimeMillis() - lastTicked > interval

    private val isDead: Boolean
        get() = System.currentTimeMillis() > deadline

    internal suspend fun checkAlive(): Boolean {
        if (isOutOfTime) {
            if (isEchoWaited) {
                if (isDead) {
                    return false
                }
            } else {
                echoFunction.invoke()
                isEchoWaited = true
                deadline = System.currentTimeMillis() + interval
            }
        }

        return true
    }

    internal fun tick() {
        lastTicked = System.currentTimeMillis()
        isEchoWaited = false
    }
}
