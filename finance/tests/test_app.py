import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "test.db"))
    app.config["TESTING"] = True
    return app.test_client()


def add(client, **kw):
    data = {"kind": "expense", "amount": "100", "category": "Продукты", "day": "2026-11-05", "note": ""}
    data.update(kw)
    return client.post("/add", data=data, follow_redirects=True)


def test_summary_and_balance(client):
    add(client, kind="income", amount="50000", category="Зарплата")
    add(client, amount="1200,50")
    add(client, amount="300", category="Транспорт")
    html = client.get("/?month=2026-11").get_data(as_text=True)
    assert "50 000 ₽" in html          # доходы
    assert "1 500,50 ₽" in html        # расходы
    assert "48 499,50 ₽" in html       # итог
    # в другом месяце операций нет, но общий баланс виден
    other = client.get("/?month=2026-10").get_data(as_text=True)
    assert "Операций нет" in other and "48 499,50 ₽" in other


def test_validation(client):
    html = add(client, amount="-5").get_data(as_text=True)
    assert "положительным" in html
    html = add(client, amount="abc", category="").get_data(as_text=True)
    assert "Укажите категорию" in html


def test_edit_and_delete(client):
    add(client, amount="100", note="хлеб")
    client.post("/edit/1", data={"kind": "expense", "amount": "250", "category": "Кафе и рестораны",
                                 "day": "2026-11-06", "note": "обед"})
    html = client.get("/?month=2026-11").get_data(as_text=True)
    assert "обед" in html and "250 ₽" in html and "хлеб" not in html
    client.post("/delete/1")
    assert "Операций нет" in client.get("/?month=2026-11").get_data(as_text=True)


def test_budget(client):
    client.post("/budget", data={"category": "Продукты", "amount": "1000"})
    add(client, amount="1200")
    html = client.get("/?month=2026-11").get_data(as_text=True)
    assert "Превышение на 200 ₽" in html


def test_filter_and_export(client):
    add(client, kind="income", amount="10", category="Подработка", note="фриланс")
    add(client, amount="20", note="молоко")
    html = client.get("/?month=2026-11&kind=income").get_data(as_text=True)
    assert "фриланс" in html and "молоко" not in html
    csv = client.get("/export.csv").get_data(as_text=True)
    assert "Доход;Подработка;10,00;фриланс" in csv
