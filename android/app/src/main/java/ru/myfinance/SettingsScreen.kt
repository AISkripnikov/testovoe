package ru.myfinance

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

private fun granted(ctx: Context, p: String) = ContextCompat.checkSelfPermission(ctx, p) == PackageManager.PERMISSION_GRANTED

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(resumeTick: Int, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val db = remember { Db.get(ctx) }
    val scope = rememberCoroutineScope()
    val version by Db.version.collectAsState()
    var permTick by remember { mutableIntStateOf(0) }

    val notifOk = remember(resumeTick) { hasNotificationAccess(ctx) }
    val smsOk = remember(resumeTick, permTick) {
        granted(ctx, Manifest.permission.RECEIVE_SMS) && granted(ctx, Manifest.permission.READ_SMS)
    }
    val unparsed = remember(version) { db.unparsed() }
    var importing by remember { mutableStateOf(false) }
    var probe by remember { mutableStateOf("") }

    fun runImport() {
        importing = true
        scope.launch {
            val n = withContext(Dispatchers.IO) { runCatching { Ingest.importSms(ctx) }.getOrDefault(-1) }
            importing = false
            Toast.makeText(ctx, if (n < 0) "Не удалось прочитать SMS" else "Добавлено операций: $n", Toast.LENGTH_LONG).show()
        }
    }

    val smsLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { res ->
        permTick++
        if (res.values.all { it }) runImport()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Подключение ВТБ") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад") }
                },
            )
        },
    ) { pad ->
        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = pad.calculateTopPadding(),
                bottom = pad.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Step(
                    ok = notifOk,
                    title = "Уведомления ВТБ Онлайн",
                    text = "Главный способ: приложение читает push-уведомления ВТБ о покупках и переводах. " +
                        "В списке включите «Мои финансы».",
                    button = "Открыть настройки",
                ) {
                    ctx.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                }
            }
            if (!notifOk && Build.VERSION.SDK_INT >= 33) item {
                Card {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Переключатель серый и пишет «Ограниченная настройка»?", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "Android так защищает приложения, установленные не из магазина. Откройте «О приложении», " +
                                "нажмите ⋮ в правом верхнем углу → «Разрешить ограниченные настройки», затем вернитесь сюда.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        OutlinedButton(onClick = {
                            ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${ctx.packageName}")))
                        }) { Text("О приложении") }
                    }
                }
            }
            item {
                Step(
                    ok = smsOk,
                    title = "SMS от VTB",
                    text = "Если банк присылает SMS — они тоже будут учитываться. Заодно можно загрузить старые SMS " +
                        "и сразу увидеть траты за прошлые месяцы. Дубли push + SMS отбрасываются.",
                    button = "Разрешить SMS",
                ) {
                    smsLauncher.launch(arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS))
                }
            }
            if (smsOk) item {
                OutlinedButton(onClick = ::runImport, enabled = !importing, modifier = Modifier.fillMaxWidth()) {
                    Text(if (importing) "Загружаю…" else "Загрузить старые SMS от VTB")
                }
            }
            item {
                OutlinedButton(onClick = { shareCsv(ctx) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Экспорт всех операций в CSV (Excel)")
                }
            }

            item { HorizontalDivider(Modifier.padding(vertical = 4.dp)) }
            item {
                Text("Проверка распознавания", style = MaterialTheme.typography.titleMedium)
                Text("Вставьте текст SMS или уведомления ВТБ — покажу, как приложение его поймёт.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(value = probe, onValueChange = { probe = it }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    minLines = 2, label = { Text("Текст сообщения") })
                if (probe.isNotBlank()) Text(describe(probe, db), modifier = Modifier.padding(top = 8.dp))
            }

            item { HorizontalDivider(Modifier.padding(vertical = 4.dp)) }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Нераспознанные сообщения", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (unparsed.isEmpty()) "Пока всё распознаётся."
                            else "Сообщения банка, в которых не нашлась сумма или тип операции. " +
                                "Нажмите на сообщение, чтобы скопировать его — пришлите мне, и я научу приложение его понимать.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (unparsed.isNotEmpty()) TextButton(onClick = { db.clearUnparsed() }) { Text("Очистить") }
                }
            }
            items(unparsed, key = { it.id }) { u ->
                Card(onClick = {
                    val cm = ctx.getSystemService(ClipboardManager::class.java)
                    cm.setPrimaryClip(ClipData.newPlainText("ВТБ", u.text))
                    Toast.makeText(ctx, "Скопировано", Toast.LENGTH_SHORT).show()
                }) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${Instant.ofEpochMilli(u.ts).atZone(zone).format(dateTimeFormat)} · ${u.origin}",
                            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(u.text, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun Step(ok: Boolean, title: String, text: String, button: String, onClick: () -> Unit) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (ok) Icons.Default.CheckCircle else Icons.Default.Warning, contentDescription = null,
                    tint = if (ok) incomeColor else MaterialTheme.colorScheme.error,
                )
                Text("  $title", style = MaterialTheme.typography.titleMedium)
            }
            Text(if (ok) "Подключено." else text, style = MaterialTheme.typography.bodyMedium)
            if (!ok) Button(onClick = onClick) { Text(button) }
        }
    }
}

private fun describe(text: String, db: Db): String = when (val r = VtbParser.parse(text.trim())) {
    ParseResult.Ignored -> "Служебное или рекламное сообщение — будет пропущено."
    ParseResult.Unknown -> "Не распознано: не нашлась сумма в рублях или тип операции."
    is ParseResult.Ok -> with(r.parsed) {
        buildString {
            append(if (kind == Kind.INCOME) "Доход " else "Расход ").append(formatRub(amount))
            append("\nКатегория: ").append(Categories.guess(kind, merchant, text, db::rule))
            if (merchant.isNotBlank()) append("\nГде / кто: ").append(merchant)
            if (card != null) append("\nКарта/счёт: *").append(card)
            if (balance != null) append("\nОстаток: ").append(formatRub(balance))
        }
    }
}
