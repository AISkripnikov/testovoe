"""Учёт личных доходов и расходов: Flask + SQLite."""
import csv
import io
import os
import sqlite3
from datetime import date

from flask import Flask, Response, flash, g, redirect, render_template, request, url_for

DEFAULT_CATEGORIES = {
    "expense": ["Продукты", "Кафе и рестораны", "Транспорт", "Жильё и ЖКХ", "Связь и интернет",
                "Здоровье", "Одежда", "Развлечения", "Подписки", "Подарки", "Другое"],
    "income": ["Зарплата", "Подработка", "Подарки", "Проценты и кэшбэк", "Другое"],
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT    NOT NULL CHECK (kind IN ('income', 'expense')),
    amount   INTEGER NOT NULL CHECK (amount > 0),   -- в копейках
    category TEXT    NOT NULL,
    day      TEXT    NOT NULL,                       -- YYYY-MM-DD
    note     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tx_day ON transactions(day);
CREATE TABLE IF NOT EXISTS budgets (
    category TEXT PRIMARY KEY,
    amount   INTEGER NOT NULL CHECK (amount > 0)     -- лимит в месяц, в копейках
);
"""

MONTHS = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", "Июль",
          "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"]


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FINANCE_SECRET_KEY", "dev-only-change-me")
    app.config["DATABASE"] = db_path or os.environ.get(
        "FINANCE_DB", os.path.join(os.path.dirname(__file__), "finance.db"))

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    with app.app_context():
        db().executescript(SCHEMA)

    # ---------- helpers ----------

    @app.template_filter("money")
    def money(kopecks):
        rub = (kopecks or 0) / 100
        s = f"{abs(rub):,.2f}".replace(",", " ").replace(".", ",")
        if s.endswith(",00"):
            s = s[:-3]
        return ("−" if rub < 0 else "") + s + " ₽"

    def parse_amount(raw):
        try:
            value = round(float(raw.replace(" ", "").replace(",", ".")) * 100)
        except (AttributeError, ValueError):
            return None
        return value if value > 0 else None

    def parse_month(raw):
        try:
            y, m = map(int, (raw or "").split("-"))
            if 1 <= m <= 12 and 1900 < y < 3000:
                return y, m
        except ValueError:
            pass
        today = date.today()
        return today.year, today.month

    def shift(y, m, delta):
        idx = y * 12 + (m - 1) + delta
        return idx // 12, idx % 12 + 1

    def all_categories(kind):
        rows = db().execute("SELECT DISTINCT category FROM transactions WHERE kind = ?", (kind,))
        cats = list(DEFAULT_CATEGORIES[kind])
        cats += sorted(r["category"] for r in rows if r["category"] not in cats)
        return cats

    def read_form(form):
        kind = form.get("kind")
        amount = parse_amount(form.get("amount", ""))
        category = (form.get("category") or "").strip()
        day = form.get("day") or date.today().isoformat()
        note = (form.get("note") or "").strip()
        errors = []
        if kind not in ("income", "expense"):
            errors.append("Выберите тип: доход или расход.")
        if amount is None:
            errors.append("Сумма должна быть положительным числом.")
        if not category:
            errors.append("Укажите категорию.")
        try:
            date.fromisoformat(day)
        except ValueError:
            errors.append("Неверная дата.")
        return (kind, amount, category, day, note), errors

    # ---------- pages ----------

    @app.route("/")
    def index():
        y, m = parse_month(request.args.get("month"))
        start = f"{y:04d}-{m:02d}-01"
        ny, nm = shift(y, m, 1)
        end = f"{ny:04d}-{nm:02d}-01"
        kind_filter = request.args.get("kind", "")
        cat_filter = request.args.get("category", "")

        sql = "SELECT * FROM transactions WHERE day >= ? AND day < ?"
        params = [start, end]
        if kind_filter in ("income", "expense"):
            sql += " AND kind = ?"
            params.append(kind_filter)
        if cat_filter:
            sql += " AND category = ?"
            params.append(cat_filter)
        txs = db().execute(sql + " ORDER BY day DESC, id DESC", params).fetchall()

        totals = {r["kind"]: r["s"] for r in db().execute(
            "SELECT kind, SUM(amount) s FROM transactions WHERE day >= ? AND day < ? GROUP BY kind",
            (start, end))}
        income, expense = totals.get("income", 0), totals.get("expense", 0)

        overall = db().execute(
            "SELECT COALESCE(SUM(CASE WHEN kind='income' THEN amount ELSE -amount END), 0) "
            "FROM transactions").fetchone()[0]

        by_cat = db().execute(
            "SELECT category, SUM(amount) s FROM transactions "
            "WHERE kind='expense' AND day >= ? AND day < ? GROUP BY category ORDER BY s DESC",
            (start, end)).fetchall()
        spent = {r["category"]: r["s"] for r in by_cat}

        budgets = [
            {"category": r["category"], "limit": r["amount"], "spent": spent.get(r["category"], 0),
             "pct": round(spent.get(r["category"], 0) * 100 / r["amount"])}
            for r in db().execute("SELECT * FROM budgets ORDER BY category")
        ]

        # динамика за 6 месяцев, заканчивая выбранным
        trend = []
        for d in range(-5, 1):
            ty, tm = shift(y, m, d)
            key = f"{ty:04d}-{tm:02d}"
            row = db().execute(
                "SELECT COALESCE(SUM(CASE WHEN kind='income' THEN amount END), 0) inc, "
                "COALESCE(SUM(CASE WHEN kind='expense' THEN amount END), 0) exp "
                "FROM transactions WHERE substr(day, 1, 7) = ?", (key,)).fetchone()
            trend.append({"label": MONTHS[tm - 1][:3], "income": row["inc"] / 100,
                          "expense": row["exp"] / 100})

        py, pm = shift(y, m, -1)
        return render_template(
            "index.html",
            txs=txs, income=income, expense=expense, overall=overall,
            by_cat=[{"category": r["category"], "sum": r["s"] / 100} for r in by_cat],
            budgets=budgets, trend=trend,
            month_key=f"{y:04d}-{m:02d}", month_title=f"{MONTHS[m - 1]} {y}",
            prev_month=f"{py:04d}-{pm:02d}", next_month=f"{ny:04d}-{nm:02d}",
            kind_filter=kind_filter, cat_filter=cat_filter,
            categories={k: all_categories(k) for k in DEFAULT_CATEGORIES},
            today=date.today().isoformat(),
        )

    @app.post("/add")
    def add():
        values, errors = read_form(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            db().execute("INSERT INTO transactions (kind, amount, category, day, note) "
                         "VALUES (?, ?, ?, ?, ?)", values)
            db().commit()
            flash("Операция добавлена.", "ok")
        return redirect(url_for("index", month=values[3][:7] if not errors else None))

    @app.route("/edit/<int:tx_id>", methods=["GET", "POST"])
    def edit(tx_id):
        tx = db().execute("SELECT * FROM transactions WHERE id = ?", (tx_id,)).fetchone()
        if tx is None:
            flash("Операция не найдена.", "error")
            return redirect(url_for("index"))
        if request.method == "POST":
            values, errors = read_form(request.form)
            if not errors:
                db().execute("UPDATE transactions SET kind=?, amount=?, category=?, day=?, note=? "
                             "WHERE id=?", (*values, tx_id))
                db().commit()
                flash("Изменения сохранены.", "ok")
                return redirect(url_for("index", month=values[3][:7]))
            for e in errors:
                flash(e, "error")
        return render_template("edit.html", tx=tx,
                               categories={k: all_categories(k) for k in DEFAULT_CATEGORIES})

    @app.post("/delete/<int:tx_id>")
    def delete(tx_id):
        db().execute("DELETE FROM transactions WHERE id = ?", (tx_id,))
        db().commit()
        flash("Операция удалена.", "ok")
        return redirect(request.referrer or url_for("index"))

    @app.post("/budget")
    def set_budget():
        category = (request.form.get("category") or "").strip()
        amount = parse_amount(request.form.get("amount", ""))
        if not category or amount is None:
            flash("Для лимита нужны категория и положительная сумма.", "error")
        else:
            db().execute("INSERT INTO budgets (category, amount) VALUES (?, ?) "
                         "ON CONFLICT(category) DO UPDATE SET amount = excluded.amount",
                         (category, amount))
            db().commit()
            flash(f"Лимит для «{category}» сохранён.", "ok")
        return redirect(request.referrer or url_for("index"))

    @app.post("/budget/delete")
    def delete_budget():
        db().execute("DELETE FROM budgets WHERE category = ?", (request.form.get("category"),))
        db().commit()
        return redirect(request.referrer or url_for("index"))

    @app.route("/export.csv")
    def export_csv():
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(["Дата", "Тип", "Категория", "Сумма", "Комментарий"])
        for r in db().execute("SELECT * FROM transactions ORDER BY day, id"):
            w.writerow([r["day"], "Доход" if r["kind"] == "income" else "Расход", r["category"],
                        f"{r['amount'] / 100:.2f}".replace(".", ","), r["note"]])
        # BOM, чтобы Excel правильно открыл кириллицу
        return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=finance.csv"})

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
