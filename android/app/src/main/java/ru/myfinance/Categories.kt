package ru.myfinance

object Categories {
    val EXPENSE = listOf(
        "Продукты", "Кафе и рестораны", "Транспорт", "Маркетплейсы", "Жильё и ЖКХ",
        "Связь и интернет", "Здоровье", "Одежда", "Развлечения", "Подписки",
        "Переводы", "Наличные", "Подарки", "Другое",
    )
    val INCOME = listOf("Зарплата", "Переводы", "Проценты и кэшбэк", "Возврат", "Подработка", "Другое")

    fun forKind(kind: Kind) = if (kind == Kind.INCOME) INCOME else EXPENSE

    private val KEYWORDS: List<Pair<String, List<String>>> = listOf(
        "Продукты" to listOf(
            "pyaterochka", "пятерочка", "magnit", "магнит", "perekrestok", "перекресток", "vkusvill",
            "вкусвилл", "lenta", "лента", "auchan", "ашан", "dixy", "дикси", "spar", "okey", "окей",
            "verny", "верный", "azbuka", "азбука вкуса", "globus", "глобус", "samokat", "самокат",
            "lavka", "лавка", "krasnoe", "красное&белое", "bristol", "бристоль", "chizhik", "чижик",
            "svetofor", "светофор", "monetka", "монетка", "produkty", "продукт",
        ),
        "Кафе и рестораны" to listOf(
            "cafe", "кафе", "coffee", "кофе", "kofe", "restoran", "ресторан", "rest ", "mcdonalds",
            "vkusno", "вкусно", "kfc", "rostics", "burger", "бургер", "shokoladnitsa", "шоколадница",
            "starbucks", "pizza", "пицц", "sushi", "суши", "yandex*eda", "yandex.eda", "яндекс еда",
            "delivery club", "dodo", "додо", "teremok", "теремок", "stolovaya", "столовая", "bar ",
        ),
        "Транспорт" to listOf(
            "taxi", "такси", "metro", "метро", "mosgortrans", "мосгортранс", "troika", "тройка",
            "transport", "транспорт", "azs", "азс", "lukoil", "лукойл", "gazpromneft", "газпромнефть",
            "rosneft", "роснефть", "tatneft", "parking", "парков", "rzd", "ржд", "aeroflot",
            "аэрофлот", "pobeda", "whoosh", "urent", "citydrive", "delimobil", "belkacar", "tutu",
        ),
        "Маркетплейсы" to listOf(
            "wildberries", "вайлдберриз", "ozon", "озон", "yandex market", "market.yandex",
            "яндекс маркет", "aliexpress", "megamarket", "мегамаркет", "avito", "авито",
        ),
        "Связь и интернет" to listOf(
            "mts", "мтс", "beeline", "билайн", "megafon", "мегафон", "tele2", "rostelecom",
            "ростелеком", "yota", "internet", "интернет", "domru", "дом.ру",
        ),
        "Подписки" to listOf(
            "yandex plus", "яндекс плюс", "plus.yandex", "apple.com", "itunes", "google", "netflix",
            "spotify", "ivi", "okko", "kinopoisk", "кинопоиск", "boosty", "wink", "start.ru",
        ),
        "Здоровье" to listOf(
            "apteka", "аптека", "pharm", "фарм", "klinik", "клиник", "clinic", "stomat", "стомат",
            "invitro", "инвитро", "gemotest", "гемотест", "doctor", "доктор", "rigla", "ригла",
        ),
        "Жильё и ЖКХ" to listOf(
            "жкх", "zhkh", "gku", "квартплат", "mosenergo", "мосэнерго", "энергосбыт", "energosbyt",
            "водоканал", "vodokanal", "управляющ", "kvartplata",
        ),
        "Одежда" to listOf(
            "gloria jeans", "befree", "ostin", "остин", "sportmaster", "спортмастер", "lamoda",
            "ламода", "zolla", "love republic", "obuv", "обувь", "familia", "melon",
        ),
        "Развлечения" to listOf(
            "kino", "кино", "cinema", "театр", "teatr", "steam", "playstation", "концерт", "kassir",
            "afisha", "афиша", "bowling", "боулинг", "museum", "музей",
        ),
    )

    /** [userRule] — категория, которую пользователь сам закрепил за этим магазином. */
    fun guess(kind: Kind, merchant: String, text: String, userRule: (String) -> String?): String {
        if (merchant.isNotBlank()) userRule(merchant.lowercase())?.let { return it }
        val t = text.lowercase().replace('ё', 'е')
        val m = merchant.lowercase().replace('ё', 'е')

        if (kind == Kind.INCOME) return when {
            "зарплат" in t || "аванс" in t -> "Зарплата"
            "кэшбэк" in t || "кешбэк" in t || "cashback" in t || "процент" in t -> "Проценты и кэшбэк"
            "возврат" in t -> "Возврат"
            "перевод" in t || "перевел" in t || "сбп" in t -> "Переводы"
            else -> "Другое"
        }

        if ("снятие" in t || "выдача" in t || "банкомат" in t || " atm" in " $t") return "Наличные"
        if ("перевод" in t || "сбп" in t) return "Переводы"
        val hay = "$m $t"
        for ((category, words) in KEYWORDS) {
            if (words.any { it in hay }) return category
        }
        return "Другое"
    }
}
