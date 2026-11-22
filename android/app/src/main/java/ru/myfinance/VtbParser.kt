package ru.myfinance

import kotlin.math.max
import kotlin.math.min

enum class Kind { INCOME, EXPENSE }

data class Parsed(
    val kind: Kind,
    val amount: Long,        // копейки
    val merchant: String,    // магазин / получатель / отправитель, может быть пустым
    val balance: Long?,      // остаток после операции, если банк его прислал
    val card: String?,       // последние 4 цифры карты/счёта
)

sealed interface ParseResult {
    data class Ok(val parsed: Parsed) : ParseResult
    /** Служебное сообщение (код, отказ, реклама) — не операция, сохранять не нужно. */
    data object Ignored : ParseResult
    /** Похоже на сообщение банка, но разобрать не удалось — попадёт в журнал. */
    data object Unknown : ParseResult
}

/**
 * Разбор SMS и push-уведомлений ВТБ. Форматы у банка меняются, поэтому разбор
 * не привязан к одному шаблону: ищем сумму с валютой, тип операции по ключевым
 * словам и считаем «магазином» то, что останется после вычистки служебных слов.
 */
object VtbParser {

    private val IGNORE = listOf(
        "код", "пароль", "никому не сообщайте", "отказ", "недостаточно средств", "отклонен",
        "не выполнен", "не прошл", "вход в", "заблокирован", "предодобрен", "кредит одобрен",
    )
    private val MARKETING = Regex(
        "получите|оформите|подключите|успейте|акци[яиюй]|выгодн|предложени|скидк|розыгрыш|до\\s+\\d"
    )

    private val INCOME = listOf(
        "возврат", "зачислен", "поступлен", "входящий", "перевод от", "получен перевод",
        "вам перевел", "кэшбэк", "кешбэк", "cashback", "зарплат", "аванс", "проценты", "пополнен",
    )
    private val EXPENSE = listOf(
        "списан", "оплат", "покупк", "снятие", "выдача", "исходящий", "перевод",
        "отправлен", "платеж", "комисси",
    )
    private val BALANCE = listOf("баланс", "остаток", "доступно")

    // Ищется по тексту в нижнем регистре. Lookbehind не даёт «склеить» сумму
    // с цифрами карты (*1234 500р) или времени (12:34 500р).
    private val MONEY = Regex(
        "(?iu)([+\\-−]?)\\s?(?<![\\d.,*:])(\\d{1,3}(?:[ \\u00A0\\u202F]\\d{3})+|\\d+)(?:[.,](\\d{1,2}))?" +
            "\\s?(?:₽|руб|rub|rur|р(?![а-яa-z]))"
    )
    private val CARD = Regex("\\*\\s?(\\d{4})")

    fun parse(input: String): ParseResult {
        // неразрывные пробелы (1\u00A0000\u00A0₽) — частое дело в push-уведомлениях
        val text = input.replace('\u00A0', ' ').replace('\u202F', ' ').replace('\u2009', ' ')
        val t = text.lowercase().replace('ё', 'е')
        if (IGNORE.any { it in t } || MARKETING.containsMatchIn(t)) return ParseResult.Ignored

        var amountMatch: MatchResult? = null
        var balance: Long? = null
        var prevEnd = 0
        for (m in MONEY.findAll(t)) {
            val before = t.substring(max(prevEnd, m.range.first - 30), m.range.first)
            if (BALANCE.any { it in before }) {
                if (balance == null) balance = toKopecks(m)
            } else if (amountMatch == null) {
                amountMatch = m
            }
            prevEnd = m.range.last + 1
        }
        val am = amountMatch ?: return ParseResult.Unknown
        val amount = toKopecks(am)
        if (amount <= 0) return ParseResult.Unknown

        val sign = am.groupValues[1]
        val kind = when {
            sign == "+" -> Kind.INCOME
            else -> kindByKeywords(t) ?: if (sign.isNotEmpty()) Kind.EXPENSE else null
        } ?: return ParseResult.Unknown

        return ParseResult.Ok(
            Parsed(
                kind = kind,
                amount = amount,
                merchant = extractMerchant(text, am),
                balance = balance,
                card = CARD.find(t)?.groupValues?.get(1),
            )
        )
    }

    /** Побеждает ключевое слово, которое встретилось раньше («Возврат покупки» — доход). */
    private fun kindByKeywords(t: String): Kind? {
        val hits = INCOME.map { it to Kind.INCOME } + EXPENSE.map { it to Kind.EXPENSE }
        return hits.mapNotNull { (word, kind) ->
            val i = t.indexOf(word)
            if (i >= 0) Triple(i, -word.length, kind) else null
        }.minWithOrNull(compareBy({ it.first }, { it.second }))?.third
    }

    private fun toKopecks(m: MatchResult): Long {
        val rub = m.groupValues[2].filter { it.isDigit() }.toLongOrNull() ?: return 0
        val kop = m.groupValues[3].padEnd(2, '0').ifEmpty { "00" }.toLong()
        return rub * 100 + kop
    }

    // ---------- извлечение названия магазина / контрагента ----------

    private val CARD_TOKEN = Regex(
        "(?iU)(?:\\b(?:по|с|со|на)\\s+)?(?:\\b(?:карт\\w*|сч[её]т\\w*|сч\\.?|мир|visa|mastercard|maestro))?\\s*\\*+\\s?\\d{2,4}"
    )
    private val NOISE = listOf(
        Regex("(?iU)\\b(?:по|через)?\\s*сбп\\b"),
        Regex("(?iU)\\b(?:втб|vtb)(?:\\s*(?:онлайн|online|банк))?\\b"),
        Regex("(?iU)\\b(?:вам\\s+)?(?:списан|оплат|покупк|снятие|выдач|исходящ|входящ|перевод|перевел|" +
            "отправлен|платеж|платёж|комисси|возврат|зачислен|поступлен|получен|кэшбэк|кешбэк|cashback|" +
            "зарплат|аванс|процент|пополнен|наличн|операци|успешно|уведомлени)\\w*"),
        Regex("\\b\\d{1,2}\\.\\d{1,2}(?:\\.\\d{2,4})?\\b"),  // даты
        Regex("\\b\\d{1,2}:\\d{2}(?::\\d{2})?\\b"),          // время
    )
    private val LEADING_PREP = Regex("(?iU)^(?:в|во|на|от|у|для|через|по|с|со|из)\\s+")
    private const val TRIM_CHARS = " .,:;-–—\n\t()"

    private fun extractMerchant(text: String, am: MatchResult): String {
        val lower = text.lowercase()
        // всё, что после слова «Баланс/Остаток», — не про магазин
        val cut = BALANCE.map { lower.indexOf(it, am.range.last + 1) }.filter { it >= 0 }.minOrNull()
        val body = if (cut != null) text.substring(0, cut) else text
        val after = body.substring(min(am.range.last + 1, body.length))
        val before = body.substring(0, min(am.range.first, body.length))
        return clean(after).ifEmpty { clean(before) }
    }

    private fun clean(s: String): String {
        var x = MONEY.replace(s, " ") // суммы (комиссия 0р и т.п.)
        x = CARD_TOKEN.replace(x, " ")
        for (r in NOISE) x = r.replace(x, " ")
        x = x.replace(Regex("\\s+"), " ")
        // по кругу: обрезать знаки препинания и предлоги по краям
        while (true) {
            val y = LEADING_PREP.replace(x.trim(*TRIM_CHARS.toCharArray()), "")
            if (y == x) break
            x = y
        }
        return x.take(40).trim()
    }
}
