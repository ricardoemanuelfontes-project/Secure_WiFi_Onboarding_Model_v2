package app.reczi.pgp

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock

/**
 * Limpa a área de transferência depois de copiar texto desencriptado. Usa um alarme do
 * sistema para funcionar mesmo que a app seja fechada ou o telemóvel adormeça.
 */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = clear(context)

    companion object {
        const val DELAY_MS = 45_000L

        fun schedule(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + DELAY_MS, pending(context))
        }

        fun clear(context: Context) {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
            (context.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(pending(context))
        }

        private fun pending(context: Context): PendingIntent = PendingIntent.getBroadcast(
            context, 0, Intent(context, ClipboardClearReceiver::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
