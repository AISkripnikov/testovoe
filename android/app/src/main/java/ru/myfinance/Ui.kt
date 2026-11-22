package ru.myfinance

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.FileProvider
import java.io.File
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.math.abs

// ---------- тема ----------

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(primary = Color(0xFF748FFC))
        else -> lightColorScheme(primary = Color(0xFF3B5BDB))
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

val incomeColor: Color @Composable get() = if (isSystemInDarkTheme()) Color(0xFF69DB7C) else Color(0xFF2B8A3E)
val expenseColor: Color @Composable get() = if (isSystemInDarkTheme()) Color(0xFFFF8787) else Color(0xFFC92A2A)

val palette = listOf(
    Color(0xFF4C6EF5), Color(0xFFF08C00), Color(0xFF37B24D), Color(0xFFAE3EC9),
    Color(0xFF1098AD), Color(0xFFE8590C), Color(0xFF74B816), Color(0xFF868E96),
)

// ---------- деньги и даты ----------

private val NBSP = ' '

fun formatRub(kopecks: Long, sign: String = ""): String {
    val a = abs(kopecks)
    val rub = (a / 100).toString().reversed().chunked(3).joinToString(NBSP.toString()).reversed()
    val kop = a % 100
    val body = if (kop == 0L) rub else "$rub,${"%02d".format(kop)}"
    val prefix = if (kopecks < 0) "−" else sign
    return "$prefix$body$NBSP₽"
}

fun amountForInput(kopecks: Long): String =
    BigDecimal(kopecks).movePointLeft(2).stripTrailingZeros().toPlainString().replace('.', ',')

fun parseAmountInput(s: String): Long? = s.filter { !it.isWhitespace() }.replace(',', '.')
    .toBigDecimalOrNull()?.movePointRight(2)?.setScale(0, RoundingMode.HALF_UP)?.toLong()?.takeIf { it > 0 }

val zone: ZoneId get() = ZoneId.systemDefault()
fun Long.toLocalDate(): LocalDate = Instant.ofEpochMilli(this).atZone(zone).toLocalDate()

private val ru = Locale.forLanguageTag("ru")
val dayFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("d MMMM, EEEE", ru)
val dateFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("d MMMM yyyy", ru)
val dateTimeFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("d MMM, HH:mm", ru)
val monthFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("LLLL yyyy", ru)

// ---------- разрешения ----------

fun hasNotificationAccess(ctx: Context) =
    NotificationManagerCompat.getEnabledListenerPackages(ctx).contains(ctx.packageName)

// ---------- экспорт ----------

fun shareCsv(ctx: Context) {
    val rows = Db.get(ctx).all()
    val sb = StringBuilder("﻿Дата;Тип;Категория;Сумма;Где / от кого;Комментарий;Источник\n")
    val f = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
    fun esc(s: String) = "\"" + s.replace("\"", "\"\"").replace("\n", " ") + "\""
    for (t in rows) {
        sb.append(Instant.ofEpochMilli(t.ts).atZone(zone).format(f)).append(';')
            .append(if (t.kind == Kind.INCOME) "Доход" else "Расход").append(';')
            .append(esc(t.category)).append(';')
            .append(amountForInput(t.amount)).append(';')
            .append(esc(t.merchant)).append(';')
            .append(esc(t.note)).append(';')
            .append(when (t.source) { Source.SMS -> "SMS"; Source.PUSH -> "Уведомление"; else -> "Вручную" })
            .append('\n')
    }
    val dir = File(ctx.cacheDir, "export").apply { mkdirs() }
    val file = File(dir, "finance.csv").apply { writeText(sb.toString()) }
    val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/csv"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    ctx.startActivity(Intent.createChooser(send, "Экспорт операций").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}
