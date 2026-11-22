package ru.myfinance

import android.app.DatePickerDialog
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.time.LocalDate
import java.time.LocalTime

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun EditScreen(id: Long?, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val db = remember { Db.get(ctx) }
    val tx = remember(id) { id?.let { db.tx(it) } }

    var kind by remember { mutableStateOf(tx?.kind ?: Kind.EXPENSE) }
    var amount by remember { mutableStateOf(tx?.let { amountForInput(it.amount) } ?: "") }
    var category by remember { mutableStateOf(tx?.category ?: "") }
    var merchant by remember { mutableStateOf(tx?.merchant ?: "") }
    var note by remember { mutableStateOf(tx?.note ?: "") }
    var date by remember { mutableStateOf(tx?.ts?.toLocalDate() ?: LocalDate.now()) }
    var learnRule by remember { mutableStateOf(true) }
    var confirmDelete by remember { mutableStateOf(false) }

    val canLearn = merchant.isNotBlank() && category.isNotBlank() && tx != null && tx.source != Source.MANUAL &&
        category != tx.category

    fun save() {
        val sum = parseAmountInput(amount)
        if (sum == null) { Toast.makeText(ctx, "Введите сумму больше нуля", Toast.LENGTH_SHORT).show(); return }
        if (category.isBlank()) { Toast.makeText(ctx, "Выберите категорию", Toast.LENGTH_SHORT).show(); return }
        val time = tx?.ts?.let { Instant.ofEpochMilli(it).atZone(zone).toLocalTime() } ?: LocalTime.now()
        val ts = date.atTime(time).atZone(zone).toInstant().toEpochMilli()
        val t = (tx ?: Tx(kind = kind, amount = sum, category = category, ts = ts)).copy(
            kind = kind, amount = sum, category = category.trim(), merchant = merchant.trim(), note = note.trim(), ts = ts,
        )
        if (tx == null) db.insert(t) else db.update(t)
        if (canLearn && learnRule) db.setRule(t.merchant, t.category)
        onDone()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (tx == null) "Новая операция" else "Операция") },
                navigationIcon = {
                    IconButton(onClick = onDone) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад") }
                },
                actions = {
                    if (tx != null) IconButton(onClick = { confirmDelete = true }) {
                        Icon(Icons.Default.Delete, contentDescription = "Удалить")
                    }
                },
            )
        },
    ) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(Kind.EXPENSE to "Расход", Kind.INCOME to "Доход").forEachIndexed { i, (k, label) ->
                    SegmentedButton(
                        selected = kind == k,
                        onClick = {
                            if (kind != k && category !in Categories.forKind(k)) category = ""
                            kind = k
                        },
                        shape = SegmentedButtonDefaults.itemShape(i, 2),
                    ) { Text(label) }
                }
            }

            OutlinedTextField(
                value = amount, onValueChange = { amount = it }, label = { Text("Сумма, ₽") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )

            Text("Категория", style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val options = (Categories.forKind(kind) + listOfNotNull(category.takeIf { it.isNotBlank() })).distinct()
                options.forEach { c ->
                    FilterChip(selected = category == c, onClick = { category = c }, label = { Text(c) })
                }
            }
            OutlinedTextField(
                value = category, onValueChange = { category = it }, label = { Text("или своя категория") },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = merchant, onValueChange = { merchant = it },
                label = { Text(if (kind == Kind.INCOME) "От кого" else "Где / кому") },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = note, onValueChange = { note = it }, label = { Text("Комментарий") },
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedButton(onClick = {
                DatePickerDialog(ctx, { _, y, m, d -> date = LocalDate.of(y, m + 1, d) },
                    date.year, date.monthValue - 1, date.dayOfMonth).show()
            }) {
                Icon(Icons.Default.DateRange, contentDescription = null)
                Text("  " + date.format(dateFormat))
            }

            if (canLearn) Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = learnRule, onCheckedChange = { learnRule = it })
                Text("Всегда относить «${merchant.trim()}» к «${category.trim()}» (и прошлые операции тоже)")
            }

            Button(onClick = ::save, modifier = Modifier.fillMaxWidth()) { Text("Сохранить") }

            if (tx != null && tx.raw.isNotBlank()) Card {
                Column(Modifier.padding(12.dp)) {
                    Text(
                        if (tx.source == Source.SMS) "SMS банка" else "Уведомление банка",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(tx.raw, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    if (confirmDelete) AlertDialog(
        onDismissRequest = { confirmDelete = false },
        title = { Text("Удалить операцию?") },
        confirmButton = {
            TextButton(onClick = { tx?.let { db.delete(it.id) }; confirmDelete = false; onDone() }) { Text("Удалить") }
        },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Отмена") } },
    )
}
