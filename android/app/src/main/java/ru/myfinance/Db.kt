package ru.myfinance

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

object Source {
    const val MANUAL = "manual"
    const val SMS = "sms"
    const val PUSH = "push"
}

data class Tx(
    val id: Long = 0,
    val kind: Kind,
    val amount: Long,          // копейки, всегда > 0
    val category: String,
    val merchant: String = "",
    val note: String = "",
    val ts: Long,              // время операции, мс
    val source: String = Source.MANUAL,
    val raw: String = "",      // исходный текст сообщения банка
)

data class Unparsed(val id: Long, val ts: Long, val origin: String, val text: String)

class Db private constructor(ctx: Context) : SQLiteOpenHelper(ctx, "finance.db", null, 1) {

    companion object {
        @Volatile private var instance: Db? = null
        fun get(ctx: Context): Db = instance ?: synchronized(this) {
            instance ?: Db(ctx.applicationContext).also { instance = it }
        }

        private val _version = MutableStateFlow(0)
        /** Меняется при любой записи — экраны перечитывают данные. */
        val version: StateFlow<Int> = _version
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE tx (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL, amount INTEGER NOT NULL, category TEXT NOT NULL,
                merchant TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                ts INTEGER NOT NULL, source TEXT NOT NULL, raw TEXT NOT NULL DEFAULT '')"""
        )
        db.execSQL("CREATE INDEX tx_ts ON tx(ts)")
        db.execSQL("CREATE TABLE rules (merchant TEXT PRIMARY KEY, category TEXT NOT NULL)")
        db.execSQL(
            "CREATE TABLE unparsed (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, " +
                "origin TEXT NOT NULL, text TEXT NOT NULL)"
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    private fun changed() = _version.update { it + 1 }

    // ---------- операции ----------

    private fun Tx.values() = ContentValues().apply {
        put("kind", kind.name); put("amount", amount); put("category", category)
        put("merchant", merchant); put("note", note); put("ts", ts); put("source", source); put("raw", raw)
    }

    private fun Cursor.tx() = Tx(
        id = getLong(0), kind = Kind.valueOf(getString(1)), amount = getLong(2), category = getString(3),
        merchant = getString(4), note = getString(5), ts = getLong(6), source = getString(7), raw = getString(8),
    )

    private val cols = "id, kind, amount, category, merchant, note, ts, source, raw"

    private fun query(sql: String, vararg args: String): List<Tx> =
        readableDatabase.rawQuery(sql, args).use { c -> buildList { while (c.moveToNext()) add(c.tx()) } }

    fun insert(t: Tx): Long = writableDatabase.insert("tx", null, t.values()).also { changed() }

    fun update(t: Tx) {
        writableDatabase.update("tx", t.values(), "id = ?", arrayOf(t.id.toString()))
        changed()
    }

    fun delete(id: Long) {
        writableDatabase.delete("tx", "id = ?", arrayOf(id.toString()))
        changed()
    }

    fun tx(id: Long): Tx? = query("SELECT $cols FROM tx WHERE id = ?", id.toString()).firstOrNull()

    fun between(fromMs: Long, toMs: Long): List<Tx> =
        query("SELECT $cols FROM tx WHERE ts >= ? AND ts < ? ORDER BY ts DESC, id DESC", fromMs.toString(), toMs.toString())

    fun all(): List<Tx> = query("SELECT $cols FROM tx ORDER BY ts, id")

    /**
     * Одна и та же операция может прийти дважды: обновлённое уведомление, повторный
     * импорт SMS, или и push, и SMS сразу. Такие дубли отбрасываем.
     */
    fun isDuplicate(t: Tx): Boolean = readableDatabase.rawQuery(
        """SELECT 1 FROM tx WHERE
             (raw = ? AND raw != '' AND ABS(ts - ?) < 600000)
          OR (kind = ? AND amount = ? AND source != 'manual' AND source != ? AND ABS(ts - ?) < 300000)
           LIMIT 1""",
        arrayOf(t.raw, t.ts.toString(), t.kind.name, t.amount.toString(), t.source, t.ts.toString()),
    ).use { it.moveToFirst() }

    // ---------- правила «магазин → категория» ----------

    fun rule(merchantLower: String): String? = readableDatabase
        .rawQuery("SELECT category FROM rules WHERE merchant = ?", arrayOf(merchantLower))
        .use { if (it.moveToFirst()) it.getString(0) else null }

    /** Запоминает категорию для магазина и переносит в неё все его прошлые операции. */
    fun setRule(merchant: String, category: String) {
        val db = writableDatabase
        db.insertWithOnConflict("rules", null, ContentValues().apply {
            put("merchant", merchant.lowercase()); put("category", category)
        }, SQLiteDatabase.CONFLICT_REPLACE)
        db.update("tx", ContentValues().apply { put("category", category) }, "merchant = ?", arrayOf(merchant))
        changed()
    }

    // ---------- журнал нераспознанных сообщений ----------

    fun addUnparsed(ts: Long, origin: String, text: String) {
        val db = writableDatabase
        val exists = db.rawQuery("SELECT 1 FROM unparsed WHERE text = ? LIMIT 1", arrayOf(text)).use { it.moveToFirst() }
        if (exists) return
        db.insert("unparsed", null, ContentValues().apply { put("ts", ts); put("origin", origin); put("text", text) })
        db.execSQL("DELETE FROM unparsed WHERE id NOT IN (SELECT id FROM unparsed ORDER BY id DESC LIMIT 200)")
        changed()
    }

    fun unparsed(): List<Unparsed> = readableDatabase
        .rawQuery("SELECT id, ts, origin, text FROM unparsed ORDER BY ts DESC", null)
        .use { c -> buildList { while (c.moveToNext()) add(Unparsed(c.getLong(0), c.getLong(1), c.getString(2), c.getString(3))) } }

    fun clearUnparsed() {
        writableDatabase.delete("unparsed", null, null)
        changed()
    }
}
