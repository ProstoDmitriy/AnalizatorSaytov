import os
import sys
import asyncio
import sqlite3
import re
import json
import socket
import whois
import requests
import aiohttp
from bs4 import BeautifulSoup

def install_missing_packages():
    required_modules = ["whois", "requests", "bs4", "aiohttp"]
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            os.system(f"{sys.executable} -m pip install {module}")

install_missing_packages()

# Глобальный HTML-кэш (можно расширить логику кэширования)
html_cache = {}

async def get_html(url):
    # Если URL уже запрошен, возвращаем закэшированный HTML
    if url in html_cache:
        return html_cache[url]
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            text = await response.text()
            html_cache[url] = text
            return text

def extract_domain(url):
    # Удаляем протокол, www и всё, что после первого слэша
    return re.sub(r"https?://(www\.)?|/.*", "", url)

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "created": w.creation_date,
            "updated": w.updated_date,
            "expires": w.expiration_date,
            "registrar": w.registrar,
            "status": w.status,
            "org": w.org,
            "email": w.emails
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip_data(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_server_info(domain):
    try:
        response = requests.get(f"http://{domain}")
        headers = dict(response.headers)
        return {"headers": headers}
    except Exception as e:
        return {"error": str(e)}

async def check_metrics(domain):
    url = f"http://{domain}"
    html = await get_html(url)
    metrics = {
        "Google Analytics": bool(re.search(r'UA-\d{4,10}-\d{1,2}', html)),
        "Яндекс.Метрика": bool(re.search(r'ym\(\d{6,10}', html)),
        "Facebook Pixel": bool(re.search(r"fbq\('track'", html))
    }
    return metrics

async def search_inn(domain):
    """
    Локальный поиск ИНН в HTML главной страницы.
    ИНН – последовательность из 10-12 цифр.
    """
    url = f"http://{domain}"
    html = await get_html(url)
    inns = set(re.findall(r'\b\d{10,12}\b', html))
    return list(inns)

async def search_inn_via_search_engines(domain):
    """
    Поиск ИНН через поисковые системы: DuckDuckGo, Яндекс и Google.
    Формируем поисковый запрос с использованием названия домена и ключевого слова \"ИНН\".
    """
    search_engines = {
        "DuckDuckGo": f"https://duckduckgo.com/html/?q=\"{domain} ИНН\"",
        "Yandex": f"https://yandex.ru/search/?text=\"{domain} ИНН\"",
        "Google": f"https://www.google.com/search?q=\"{domain} ИНН\""
    }
    inns_found = set()
    async with aiohttp.ClientSession() as session:
        tasks = []
        for engine, url in search_engines.items():
            tasks.append(session.get(url))
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for response in responses:
            if isinstance(response, Exception):
                continue
            text = await response.text()
            inns = re.findall(r'\b\d{10,12}\b', text)
            inns_found.update(inns)
    return list(inns_found)

async def search_inn_ext(domain):
    """
    Расширенный поиск ИНН: объединяет локальный поиск и поиск через поисковые системы.
    """
    local_inns = await search_inn(domain)
    engine_inns = await search_inn_via_search_engines(domain)
    # Объединяем и убираем дубликаты
    return list(set(local_inns + engine_inns))

async def get_rkn_operator_details_by_inn(inn):
    """
    Получение подробной информации об операторе из реестра РКН по ИНН.
    Демонстрационный пример: выполняется запрос к условному API.
    Здесь предполагается, что API возвращает HTML, из которого парсится таблица с данными.
    """
    # Для демонстрации используем фиктивный URL; замените на реальный URL реестра РКН.
    url = f"http://rkn.example.com/api?inn={inn}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                # Предположим, что данные оператора находятся в таблице с id \"operator-details\".
                table = soup.find("table", id="operator-details")
                details = {}
                if table:
                    for row in table.find_all("tr"):
                        cols = row.find_all("td")
                        if len(cols) == 2:
                            key = cols[0].get_text(strip=True)
                            value = cols[1].get_text(strip=True)
                            details[key] = value
                return details if details else {"error": "Данные не найдены"}
    except Exception as e:
        return {"error": str(e)}

async def batch_check_inn_from_file(filename):
    """
    Пакетная проверка ИНН: загружает список ИНН из файла (по одному ИНН на строку)
    и проверяет их пакетами (по 100 штук) через API РКН.
    """
    try:
        with open(filename, "r", encoding="utf-8") as f:
            inns = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
        return {}

    results = {}
    # Разбиваем на пакеты по 100 ИНН
    batches = [inns[i:i+100] for i in range(0, len(inns), 100)]
    for batch in batches:
        tasks = [get_rkn_operator_details_by_inn(inn) for inn in batch]
        batch_results = await asyncio.gather(*tasks)
        for inn, res in zip(batch, batch_results):
            results[inn] = res
    return results

def sync_rkn_db():
    """
    Синхронизация локальной базы данных с реестром РКН.
    Создаёт таблицу operators, если её нет.
    """
    conn = sqlite3.connect("rkn.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS operators (
        inn TEXT PRIMARY KEY,
        name TEXT,
        address TEXT
    )
    """)
    conn.commit()
    conn.close()

def main():
    sync_rkn_db()
    loop = asyncio.get_event_loop()
    while True:
        print("\nВыберите режим:")
        print("1. Проверка сайта")
        print("2. Пакетная проверка ИНН")
        print("3. Ручная проверка ИНН")
        print("4. Выход")
        choice = input("> ").strip()
        if choice == "1":
            domain_input = input("Введите адрес сайта: ").strip()
            domain = extract_domain(domain_input)
            print("\n=== Результаты проверки сайта ===")
            print("WHOIS:")
            print(get_whois_info(domain))
            print("\nIP Info:")
            print(get_ip_data(domain))
            print("\nServer Headers:")
            print(get_server_info(domain))
            metrics = loop.run_until_complete(check_metrics(domain))
            print("\nМетрики сайта:")
            print(metrics)
            # Расширенный поиск ИНН
            inns = loop.run_until_complete(search_inn_ext(domain))
            print("\nНайденные ИНН:")
            print(inns)
            # Для каждого найденного ИНН запрашиваем данные из реестра РКН
            for inn in inns:
                details = loop.run_until_complete(get_rkn_operator_details_by_inn(inn))
                print(f"\nДетали по ИНН {inn}:")
                print(details)
        elif choice == "2":
            filename = input("Введите имя файла с ИНН (по одному ИНН на строку): ").strip()
            print("\n=== Пакетная проверка ИНН ===")
            results = loop.run_until_complete(batch_check_inn_from_file(filename))
            for inn, details in results.items():
                print(f"\nИНН {inn}:")
                print(details)
        elif choice == "3":
            inn = input("Введите ИНН для проверки: ").strip()
            print(f"\nПолучение данных для ИНН {inn}:")
            details = loop.run_until_complete(get_rkn_operator_details_by_inn(inn))
            print(details)
        elif choice == "4":
            break
        else:
            print("Неверный выбор. Попробуйте ещё раз.")

if __name__ == "__main__":
    main()
