package ru.myfinance

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VtbParserTest {

    private fun ok(text: String): Parsed {
        val r = VtbParser.parse(text)
        assertTrue("ожидали операцию, получили $r для: $text", r is ParseResult.Ok)
        return (r as ParseResult.Ok).parsed
    }

    private fun category(text: String): String {
        val p = ok(text)
        return Categories.guess(p.kind, p.merchant, text) { null }
    }

    @Test fun smsPurchase() {
        val text = "Оплата 1234.56р Карта*1234 PYATEROCHKA 6542 Баланс 9876.54р 12:34"
        val p = ok(text)
        assertEquals(Kind.EXPENSE, p.kind)
        assertEquals(123456L, p.amount)
        assertEquals(987654L, p.balance)
        assertEquals("1234", p.card)
        assertEquals("PYATEROCHKA 6542", p.merchant)
        assertEquals("Продукты", category(text))
    }

    @Test fun pushIncomeWithSpaces() {
        val text = "Поступление 50 000 ₽ на счёт *5678. Зарплата. Баланс 75 000,50 ₽"
        val p = ok(text)
        assertEquals(Kind.INCOME, p.kind)
        assertEquals(5_000_000L, p.amount)
        assertEquals(7_500_050L, p.balance)
        assertEquals("Зарплата", category(text))
    }

    @Test fun pushWithTitleAndNbsp() {
        val p = ok("Списание 349 ₽\nKOFEMANIYA, карта *1234. Доступно 12 345,67 ₽")
        assertEquals(Kind.EXPENSE, p.kind)
        assertEquals(34900L, p.amount)
        assertEquals(1_234_567L, p.balance)
        assertEquals("KOFEMANIYA", p.merchant)
    }

    @Test fun merchantInTitle() {
        val text = "YANDEX.TAXI\nОплата 412 ₽ по карте *1234"
        val p = ok(text)
        assertEquals(41200L, p.amount)
        assertEquals("YANDEX.TAXI", p.merchant)
        assertEquals("Транспорт", category(text))
    }

    @Test fun outgoingTransfer() {
        val text = "Перевод 1 500 ₽ по СБП Иван И. Баланс 3 000 ₽"
        val p = ok(text)
        assertEquals(Kind.EXPENSE, p.kind)
        assertEquals(150_000L, p.amount)
        assertEquals("Иван И", p.merchant)
        assertEquals("Переводы", category(text))
    }

    @Test fun incomingTransfer() {
        val p = ok("Вам перевели 2 000 ₽ от Петр П.")
        assertEquals(Kind.INCOME, p.kind)
        assertEquals(200_000L, p.amount)
        assertEquals("Петр П", p.merchant)
    }

    @Test fun plusSignMeansIncome() {
        assertEquals(Kind.INCOME, ok("+15 000 ₽ Перевод от Анна С.").kind)
    }

    @Test fun refundIsIncome() {
        val text = "Возврат покупки 999р Карта*1234 WILDBERRIES"
        assertEquals(Kind.INCOME, ok(text).kind)
        assertEquals("Возврат", category(text))
    }

    @Test fun cashWithdrawal() {
        val text = "Снятие наличных 5000р Карта*1234 ATM 123456 Баланс 100р"
        assertEquals(500_000L, ok(text).amount)
        assertEquals("Наличные", category(text))
    }

    @Test fun timeBeforeAmountIsNotGlued() {
        assertEquals(25_000L, ok("Карта*1234 15:42 Покупка 250р YANDEX.TAXI").amount)
    }

    @Test fun rubAbbreviation() {
        assertEquals(10_050L, ok("Списание 100,50 RUB, MTS").amount)
    }

    @Test fun ignoredMessages() {
        assertEquals(ParseResult.Ignored, VtbParser.parse("Код подтверждения 123456. Никому не сообщайте его"))
        assertEquals(ParseResult.Ignored, VtbParser.parse("Отказ в операции 500р Карта*1234"))
        assertEquals(ParseResult.Ignored, VtbParser.parse("Получите кэшбэк до 5 000 ₽ за покупки!"))
    }

    @Test fun unknownWithoutAmount() {
        assertEquals(ParseResult.Unknown, VtbParser.parse("Ваша карта готова, заберите её в офисе"))
    }

    @Test fun userRuleWins() {
        val text = "Оплата 300р Карта*1234 IP IVANOV"
        val p = ok(text)
        assertEquals("Подарки", Categories.guess(p.kind, p.merchant, text) { if (it == "ip ivanov") "Подарки" else null })
    }
}
