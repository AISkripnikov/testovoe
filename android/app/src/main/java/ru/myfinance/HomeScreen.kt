package ru.myfinance

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowLeft
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.time.YearMonth

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(resumeTick: Int, onAdd: () -> Unit, onOpen: (Long) -> Unit, onSettings: () -> Unit) {
    val ctx = LocalContext.current
    val db = remember { Db.get(ctx) }
    val version by Db.version.collectAsState()
    var monthKey by rememberSaveable { mutableStateOf(YearMonth.now().toString()) }
    val month = YearMonth.parse(monthKey)

    val txs = remember(version, monthKey) {
        val from = month.atDay(1).atStartOfDay(zone).toInstant().toEpochMilli()
        val to = month.plusMonths(1).atDay(1).atStartOfDay(zone).toInstant().toEpochMilli()
        db.between(from, to)
    }
    val unparsedCount = remember(version) { db.unparsed().size }
    val connected = remember(resumeTick) { hasNotificationAccess(ctx) }

    val income = txs.filter { it.kind == Kind.INCOME }.sumOf { it.amount }
    val expense = txs.filter { it.kind == Kind.EXPENSE }.sumOf { it.amount }
    val byCategory = txs.filter { it.kind == Kind.EXPENSE }
        .groupBy { it.category }.mapValues { (_, l) -> l.sumOf { it.amount } }
        .entries.sortedByDescending { it.value }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Мои финансы") },
                actions = {
                    IconButton(onClick = onSettings) {
                        BadgedBox(badge = { if (unparsedCount > 0 || !connected) Badge() }) {
                            Icon(Icons.Default.Settings, contentDescription = "Настройки")
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd) { Icon(Icons.Default.Add, contentDescription = "Добавить") }
        },
    ) { pad ->
        LazyColumn(
            contentPadding = PaddingValues(
                start = 16.dp, end = 16.dp,
                top = pad.calculateTopPadding() + 4.dp, bottom = pad.calculateBottomPadding() + 96.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!connected) item { ConnectCard(onSettings) }

            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { monthKey = month.minusMonths(1).toString() }) {
                        Icon(Icons.Default.KeyboardArrowLeft, contentDescription = "Предыдущий месяц")
                    }
                    Text(
                        month.format(monthFormat).replaceFirstChar { it.uppercase() },
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.weight(1f),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    )
                    IconButton(onClick = { monthKey = month.plusMonths(1).toString() }) {
                        Icon(Icons.Default.KeyboardArrowRight, contentDescription = "Следующий месяц")
                    }
                }
            }

            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Stat("Доходы", formatRub(income), incomeColor, Modifier.weight(1f))
                    Stat("Расходы", formatRub(expense), expenseColor, Modifier.weight(1f))
                }
                Spacer(Modifier.height(8.dp))
                Stat(
                    "Итог за месяц", formatRub(income - expense, if (income > expense) "+" else ""),
                    if (income >= expense) incomeColor else expenseColor, Modifier.fillMaxWidth(),
                )
            }

            if (byCategory.isNotEmpty()) item { CategoryCard(byCategory, expense) }

            if (txs.isEmpty()) item {
                Text(
                    "За этот месяц операций нет.\n" +
                        if (connected) "Новые покупки по карте ВТБ появятся здесь сами." else "",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 24.dp),
                )
            }

            txs.groupBy { it.ts.toLocalDate() }.forEach { (day, list) ->
                item(key = "d$day") {
                    val dayTotal = list.sumOf { if (it.kind == Kind.INCOME) it.amount else -it.amount }
                    Row(Modifier.padding(top = 8.dp)) {
                        Text(day.format(dayFormat), style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
                        Text(formatRub(dayTotal, "+"), style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                items(list, key = { it.id }) { TxRow(it, onClick = { onOpen(it.id) }) }
            }
        }
    }
}

@Composable
private fun ConnectCard(onSettings: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Подключите ВТБ", style = MaterialTheme.typography.titleMedium)
            Text("Разрешите читать уведомления и SMS банка — и покупки будут записываться сами.")
            Button(onClick = onSettings) { Text("Настроить") }
        }
    }
}

@Composable
private fun Stat(label: String, value: String, color: Color, modifier: Modifier) {
    Card(modifier) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, color = color, fontWeight = FontWeight.SemiBold,
                maxLines = 1)
        }
    }
}

@Composable
private fun CategoryCard(items: List<Map.Entry<String, Long>>, total: Long) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Расходы по категориям", style = MaterialTheme.typography.titleMedium)
            items.forEachIndexed { i, (category, sum) ->
                val share = sum.toFloat() / total
                Column {
                    Row {
                        Text(category, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(formatRub(sum), fontWeight = FontWeight.Medium)
                        Text("${(share * 100).toInt()}%", modifier = Modifier.width(44.dp),
                            textAlign = androidx.compose.ui.text.style.TextAlign.End,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Box(
                        Modifier.padding(top = 4.dp).fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                    ) {
                        Box(Modifier.fillMaxWidth(share.coerceIn(0.01f, 1f)).height(6.dp)
                            .background(palette[i % palette.size]))
                    }
                }
            }
        }
    }
}

@Composable
private fun TxRow(t: Tx, onClick: () -> Unit) {
    val color = if (t.kind == Kind.INCOME) incomeColor else expenseColor
    val all = Categories.forKind(t.kind)
    val dot = palette[(all.indexOf(t.category).takeIf { it >= 0 } ?: (t.category.hashCode() and 7)) % palette.size]
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(40.dp).clip(CircleShape).background(dot.copy(alpha = 0.18f)), contentAlignment = Alignment.Center) {
            Text(t.category.take(1), color = dot, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(t.merchant.ifBlank { t.category }, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val sub = buildList {
                if (t.merchant.isNotBlank()) add(t.category)
                if (t.note.isNotBlank()) add(t.note)
                if (t.source != Source.MANUAL) add("ВТБ")
            }.joinToString(" · ")
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Text(formatRub(if (t.kind == Kind.INCOME) t.amount else -t.amount, "+"), color = color, fontWeight = FontWeight.Medium)
    }
}
