package ru.myfinance

import android.app.Notification
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

enum class IngestResult { ADDED, DUPLICATE, IGNORED, UNKNOWN }

/** Превращает текст сообщения банка в операцию и сохраняет её. */
object Ingest {
    fun isBankSender(address: String) = address.contains("vtb", true) || address.contains("втб", true)
    fun isBankApp(pkg: String) = pkg.contains("vtb", true)

    fun handle(ctx: Context, text: String, source: String, ts: Long, origin: String): IngestResult {
        val db = Db.get(ctx)
        val clean = text.trim()
        return when (val r = VtbParser.parse(clean)) {
            ParseResult.Ignored -> IngestResult.IGNORED
            ParseResult.Unknown -> {
                db.addUnparsed(ts, origin, clean)
                IngestResult.UNKNOWN
            }
            is ParseResult.Ok -> {
                val p = r.parsed
                val tx = Tx(
                    kind = p.kind, amount = p.amount,
                    category = Categories.guess(p.kind, p.merchant, clean, db::rule),
                    merchant = p.merchant, ts = ts, source = source, raw = clean,
                )
                if (db.isDuplicate(tx)) IngestResult.DUPLICATE else {
                    db.insert(tx); IngestResult.ADDED
                }
            }
        }
    }

    /** Разбирает уже лежащие в телефоне SMS от ВТБ. Возвращает число новых операций. */
    fun importSms(ctx: Context): Int {
        var added = 0
        ctx.contentResolver.query(
            Uri.parse("content://sms/inbox"), arrayOf("address", "body", "date"), null, null, "date ASC",
        )?.use { c ->
            while (c.moveToNext()) {
                val address = c.getString(0) ?: continue
                if (!isBankSender(address)) continue
                val body = c.getString(1) ?: continue
                if (handle(ctx, body, Source.SMS, c.getLong(2), address) == IngestResult.ADDED) added++
            }
        }
        return added
    }
}

/** Новые SMS от VTB. */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        parts.groupBy { it.originatingAddress.orEmpty() }.forEach { (address, msgs) ->
            if (!Ingest.isBankSender(address)) return@forEach
            val body = msgs.joinToString("") { it.messageBody.orEmpty() }
            Ingest.handle(ctx, body, Source.SMS, msgs.first().timestampMillis, address)
        }
    }
}

/** Push-уведомления приложения ВТБ Онлайн. */
class BankNotificationListener : NotificationListenerService() {

    override fun onListenerConnected() {
        // подхватить уведомления, которые уже висят в шторке
        runCatching { activeNotifications?.forEach(::process) }
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) = process(sbn)

    private fun process(sbn: StatusBarNotification) {
        if (!Ingest.isBankApp(sbn.packageName)) return
        val n = sbn.notification ?: return
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        val e = n.extras ?: return
        val title = e.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val body = (e.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: e.getCharSequence(Notification.EXTRA_TEXT))
            ?.toString().orEmpty()
        if (body.isBlank() && title.isBlank()) return
        Ingest.handle(this, "$title\n$body", Source.PUSH, sbn.postTime, sbn.packageName)
    }
}
