import sys
import socket
import ssl
import re
import subprocess
import sqlite3
import json
import logging
import asyncio
from datetime import datetime
from urllib.parse import urlparse, urlencode

import aiohttp
import requests  
from bs4 import BeautifulSoup
from whois import whois as get_whois_data

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Глобальный кэш для HTML главной страницы
_html_cache = {}

# Регулярное выражение для поиска ИНН (10-12 цифр, допускаются разделители)
INN_REGEX = re.compile(r"\b(?:\d[\s-]?){10,12}\b")


def fmt_date(d):
    """Форматирование даты для вывода."""
    if isinstance(d, list):
        d = d[0]
    try:
        return d.strftime("%d-%m-%Y") if isinstance(d, datetime) else str(d)
    except Exception:
        return str(d)


def extract_domain(url):
    """Извлекаем домен из переданного URL."""
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else parsed.path


async def get_main_html(domain, session):
    """
    Асинхронное получение HTML главной страницы с кэшированием.
    Используется переданный сеанс session.
    """
    if domain in _html_cache:
        return _html_cache[domain]
    try:
        async with session.get(f"http://{domain}", timeout=5) as resp:
            if resp.status == 200:
                text = await resp.text()
                _html_cache[domain] = text
                return text
    except Exception as e:
        logging.error(f"Ошибка получения HTML для {domain}: {e}")
    return ""


async def get_total_pages(domain, session):
    """Получаем количество страниц сайта через анализ sitemap.xml."""
    sitemap_url = f"http://{domain}/sitemap.xml"
    try:
        async with session.get(sitemap_url, timeout=5) as resp:
            if resp.status == 200:
                sitemap_text = await resp.text()
                soup = BeautifulSoup(sitemap_text, "xml")
                loc_tags = soup.find_all("loc")
                return len(loc_tags)
            else:
                return None
    except Exception as e:
        logging.error(f"Ошибка получения sitemap.xml для {domain}: {e}")
        return None


def get_whois_info(domain):
    """Получаем WHOIS-данные (синхронно)."""
    try:
        w = get_whois_data(domain)
        return {
            "Домен": domain,
            "Регистратор": w.registrar,
            "Дата создания": fmt_date(w.creation_date) if w.creation_date else "Неизвестно",
            "Дата обновления": fmt_date(w.updated_date) if w.updated_date else "Неизвестно",
            "Срок действия": fmt_date(w.expiration_date) if w.expiration_date else "Неизвестно",
            "Статус": w.status,
            "Организация": w.org,
            "Контактный email": w.emails if w.emails else "Не найдено"
        }
    except Exception as e:
        return f"Ошибка при получении WHOIS: {e}"


async def get_ip_data(domain, session):
    """
    Асинхронное получение IP-данных через API ip-api.com,
    обрабатываем BOM в ответе.
    """
    try:
        ip = socket.gethostbyname(domain)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,isp,as,lat,lon,org,query"
        async with session.get(url, timeout=5) as resp:
            content = await resp.read()
            data = json.loads(content.decode("utf-8-sig"))
            if data.get("status") == "success":
                return {
                    "IP адрес": ip,
                    "Страна": data.get("country", "Неизвестно"),
                    "Регион": data.get("regionName", "Неизвестно"),
                    "Город": data.get("city", "Неизвестно"),
                    "Почтовый индекс": data.get("zip", "Неизвестно"),
                    "Провайдер": data.get("isp", "Неизвестно"),
                    "ASN (автономная система)": data.get("as", "Неизвестно"),
                    "Организация": data.get("org", "Неизвестно"),
                    "Широта": data.get("lat", "Неизвестно"),
                    "Долгота": data.get("lon", "Неизвестно")
                }
            else:
                return {"IP адрес": ip, "Статус": "ошибка", "Сообщение": data.get("message", "Неизвестная ошибка")}
    except Exception as e:
        return f"Ошибка при получении IP данных: {e}"


def get_server_info(domain):
    """Получаем информацию о сервере: HTTP-заголовки, SSL-сертификат, DNS-записи."""
    info = {}
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        headers = response.headers
        info["HTTP заголовки"] = "\n".join(f"{k}: {v}" for k, v in headers.items())
    except Exception as e:
        info["HTTP заголовки"] = f"Не найдено ({e})"

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            info["SSL-сертификат"] = s.getpeercert() or "Не найдено"
    except Exception:
        info["SSL-сертификат"] = "Не найдено"

    try:
        dns = subprocess.check_output(['nslookup', '-type=ANY', domain], timeout=5).decode('utf-8', errors='ignore')
        info["DNS-записи"] = dns
    except Exception:
        info["DNS-записи"] = "Не найдено"

    return info


async def check_metrics(domain, session):
    """Проверяем наличие скриптов аналитики (Google Analytics, Яндекс.Метрика, Facebook Pixel)."""
    try:
        html = (await get_main_html(domain, session)).lower()
        patterns = [
            ("Google Analytics", "google-analytics.com"),
            ("Яндекс.Метрика", "yandex.ru/metrika"),
            ("Facebook Pixel", r"fbq\(")
        ]
        metrics = [name for name, pattern in patterns if re.search(pattern, html)]
        return metrics if metrics else ["Нет найденных метрических программ"]
    except Exception as e:
        return [f"Ошибка при проверке метрических программ: {e}"]


async def search_inn(domain, session):
    """
    Асинхронный поиск ИНН во всех источниках:
    - По WHOIS-данным (синхронно)
    - По HTML главной страницы
    - По содержимому тегов с использованием BeautifulSoup.
    """
    inns = set()

    # Поиск в WHOIS-данных (синхронно)
    whois_info = get_whois_info(domain)
    if isinstance(whois_info, dict):
        for field, text in whois_info.items():
            for match in INN_REGEX.findall(str(text)):
                clean = re.sub(r"[\s-]", "", match)
                if len(clean) in (10, 12):
                    inns.add(clean)

    # Поиск в HTML главной страницы
    html = await get_main_html(domain, session)
    if html:
        for match in INN_REGEX.findall(html):
            clean = re.sub(r"[\s-]", "", match)
            if len(clean) in (10, 12):
                inns.add(clean)

    # Поиск в метатегах, скриптах и других тегах
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["meta", "script", "div", "span", "a", "footer"]):
            content = tag.get("content") or tag.string or ""
            for match in INN_REGEX.findall(content):
                clean = re.sub(r"[\s-]", "", match)
                if len(clean) in (10, 12):
                    inns.add(clean)
    except Exception:
        pass

    return list(inns)


async def search_inn_via_search_engines(domain, session):
    """
    Асинхронный поиск ИНН через поисковые системы (DuckDuckGo, Yandex, Google).
    Используем единый сеанс для всех запросов.
    """
    query = f"ИНН владельца сайта {domain}"
    results = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    urls = [
        ("https://duckduckgo.com/html/", "q"),
        ("https://yandex.ru/search/", "text"),
        ("https://www.google.com/search", "q")
    ]

    for url, param_key in urls:
        try:
            params = {param_key: query}
            async with session.get(url, params=params, headers=headers, timeout=10) as resp:
                html = (await resp.text()).lower()
                for match in INN_REGEX.findall(html):
                    clean = re.sub(r"[\s-]", "", match)
                    if len(clean) in (10, 12):
                        results.add(clean)
        except Exception:
            continue

    return list(results)


async def search_inn_ext(domain, session):
    """Расширенный поиск ИНН, объединяющий локальный поиск и поиск через поисковые системы."""
    inns = set(await search_inn(domain, session))
    if not inns:
        inns.update(await search_inn_via_search_engines(domain, session))
    return list(inns)


async def get_rkn_operator_details_by_inn(inn, session):
    """
    Получение подробной информации из реестра РКН по ИНН.
    Сначала выполняется поиск по ИНН, затем берётся ссылка на детальную информацию.
    """
    base_url = "https://pd.rkn.gov.ru/operators-registry/operators-list/"
    params = {"inn": inn}
    search_url = base_url + "?" + urlencode(params)
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        async with session.get(search_url, headers=headers, timeout=10) as resp:
            text = await resp.text()
    except Exception as e:
        return f"Ошибка при запросе к реестру РКН: {e}"

    soup = BeautifulSoup(text, "html.parser")
    a = soup.find("a", href=re.compile(r'\?id=\S+'))
    if not a:
        return None

    detail_href = a.get("href")
    detail_url = detail_href if detail_href.startswith("http") else base_url + detail_href

    try:
        async with session.get(detail_url, headers=headers, timeout=10) as resp:
            detail_text = await resp.text()
    except Exception as e:
        return f"Ошибка при запросе подробной страницы: {e}"

    detail_soup = BeautifulSoup(detail_text, "html.parser")
    table = detail_soup.find("table")
    if not table:
        return None

    details = {}
    for row in table.find_all("tr"):
        cols = row.find_all(["th", "td"])
        if len(cols) >= 2:
            field = cols[0].get_text(strip=True)
            value = cols[1].get_text(strip=True)
            details[field] = value
    return details if details else None


def check_inn_in_rkn_registry(inn_list):
    """
    Пакетная проверка ИНН через API реестра РКН.
    Возвращает словарь с результатами проверки.
    """
    results = {}
    for inn in inn_list:
        try:
            resp = requests.get(f'https://blocklist.rkn.gov.ru/api/check?inn={inn}', timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                results[inn] = data.get('is_blocked', 'Нет данных')
            else:
                results[inn] = 'Error checking INN'
        except Exception as e:
            results[inn] = f"Ошибка: {e}"
    return results


def batch_check_inn_from_file(filename):
    """Чтение файла с ИНН (по одному на строке) и пакетная проверка."""
    try:
        with open(filename, 'r') as file:
            inn_list = [line.strip() for line in file if line.strip()]
    except Exception as e:
        logging.error(f"Ошибка при чтении файла {filename}: {e}")
        return

    batch_size = 100
    for i in range(0, len(inn_list), batch_size):
        batch = inn_list[i:i + batch_size]
        results = check_inn_in_rkn_registry(batch)
        for inn, status in results.items():
            print(f"INN: {inn}, Blocked: {status}")


def sync_rkn_db():
    """
    Демонстрационная функция синхронизации локальной базы данных с реестром РКН.
    Здесь используется SQLite. При необходимости можно расширить функционал.
    """
    conn = sqlite3.connect("rkn_operators.db")
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reg_number TEXT,
            operator_name TEXT,
            inn TEXT,
            operator_type TEXT,
            inclusion_basis TEXT,
            notification_date TEXT,
            data_start_date TEXT,
            legal_address TEXT,
            other_info TEXT
        )
    ''')
    conn.commit()

    base_url = "https://pd.rkn.gov.ru/operators-registry/operators-list/"
    headers = {"User-Agent": "Mozilla/5.0"}
    num_pages = 2  # Демонстрация: синхронизация 2 страниц; при необходимости увеличить
    for page in range(1, num_pages + 1):
        url = f"{base_url}?page={page}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except Exception as e:
            logging.error(f"Ошибка при запросе страницы {page}: {e}")
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        table = soup.find("table")
        if not table:
            continue

        rows = table.find_all("tr")
        if len(rows) <= 1:
            continue

        headers_row = [th.get_text(strip=True) for th in rows[0].find_all("th")]
        for row in rows[1:]:
            cols = row.find_all("td")
            if len(cols) < 2:
                continue
            data = {}
            for i, header in enumerate(headers_row):
                data[header] = cols[i].get_text(strip=True) if i < len(cols) else ""
            reg_number = data.get("Регистрационный номер", "")
            op_name_inn = data.get("Наименование оператора / ИНН", "")
            op_type = data.get("Тип оператора", "")
            inclusion_basis = data.get("Основание включения в реестр", "")
            notification_date = data.get("Дата регистрации уведомления", "")
            data_start = data.get("Дата начала обработки", "")
            other_info = json.dumps(data, ensure_ascii=False)
            cur.execute('''
                INSERT INTO operators 
                (reg_number, operator_name, inn, operator_type, inclusion_basis, notification_date, data_start_date, legal_address, other_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (reg_number, op_name_inn, "", op_type, inclusion_basis, notification_date, data_start, "", other_info))
            conn.commit()
            logging.info(f"Добавлен регистратор с регистрационным номером: {reg_number}")
    conn.close()


async def main():
    # Синхронизация базы данных (демонстрация)
    logging.info("Синхронизация базы данных с реестром РКН...")
    sync_rkn_db()
    logging.info("Синхронизация завершена.\n")

    # Создаём единый асинхронный сеанс для всех запросов
    async with aiohttp.ClientSession() as session:
        while True:
            print("\nВыберите режим работы:")
            print("1 - Проверка сайта")
            print("2 - Пакетная проверка ИНН из файла (inns.txt)")
            print("3 - Ручная проверка ИНН")
            mode = input("Введите номер режима: ").strip()

            if mode == "2":
                batch_check_inn_from_file("inns.txt")

            elif mode == "3":
                inn_manual = input("Введите интересующий ИНН: ").strip()
                print("\n--- Проверка ИНН в реестре РКН (ручной режим) ---")
                details = await get_rkn_operator_details_by_inn(inn_manual, session)
                if details:
                    expected_fields = [
                        "Регистрационный номер",
                        "Дата и основание внесения оператора в реестр",
                        "Наименование оператора",
                        "ИНН",
                        "Юридический адрес",
                        "Дата регистрации уведомления",
                        "Субъекты РФ, на территории которых происходит обработка персональных данных",
                        "Наличие шифровальных средств",
                        "Трансграничная передача",
                        "Сведения о местонахождении БД (страны)",
                        "Описание мер, предусмотренных ст. 18.1 и 19 Закона",
                        "ФИО физического лица или наименование юридического лица, ответственных за организацию обработки персональных данных",
                        "Контактные телефоны, почтовые адреса и адреса электронной почты",
                        "Дата начала обработки персональных данных",
                        "Срок или условие прекращения обработки персональных данных",
                        "Реорганизация или ликвидация Общества",
                        "Дата и основание внесения записи в реестр",
                        "Цели обработки персональных данных"
                    ]
                    for field in expected_fields:
                        print(f"{field}: {details.get(field, 'Не найдено')}")
                    extra = {k: v for k, v in details.items() if k not in expected_fields}
                    if extra:
                        print("\nДополнительная информация:")
                        for k, v in extra.items():
                            print(f"{k}: {v}")
                else:
                    print("Подробная информация по данному ИНН не найдена.")

            elif mode == "1":
                url_input = input("Введите адрес сайта (например, https://www.example.com): ").strip()
                domain = extract_domain(url_input)
                print("\n--- WHOIS данные ---")
                whois_info = get_whois_info(domain)
                if isinstance(whois_info, dict):
                    for k, v in whois_info.items():
                        print(f"{k}: {v}")
                else:
                    print(whois_info)

                print("\n--- IP и дополнительная информация ---")
                ip_data = await get_ip_data(domain, session)
                if isinstance(ip_data, dict):
                    for k, v in ip_data.items():
                        print(f"{k}: {v}")
                else:
                    print(ip_data)

                print("\n--- Количество страниц сайта (sitemap.xml) ---")
                total_pages = await get_total_pages(domain, session)
                if total_pages is not None:
                    print(f"Всего страниц: {total_pages}")
                else:
                    print("Не удалось определить количество страниц.")

                print("\n--- Метрические программы ---")
                metrics = await check_metrics(domain, session)
                print(", ".join(metrics))

                print("\n--- Расширенный поиск ИНН владельца ---")
                inns_found = await search_inn_ext(domain, session)
                if inns_found:
                    print("Найденные ИНН:", ", ".join(inns_found))
                else:
                    print("ИНН не найдены.")

                print("\n--- Проверка ИНН в реестре РКН ---")
                if not inns_found:
                    print("ИНН оператора не найдены, подробная информация невозможна.")
                else:
                    for inn in inns_found:
                        print(f"\nРезультат проверки для ИНН: {inn}")
                        details = await get_rkn_operator_details_by_inn(inn, session)
                        if details:
                            for field in expected_fields:
                                print(f"{field}: {details.get(field, 'Не найдено')}")
                            extra = {k: v for k, v in details.items() if k not in expected_fields}
                            if extra:
                                print("\nДополнительная информация:")
                                for k, v in extra.items():
                                    print(f"{k}: {v}")
                        else:
                            print("Подробная информация по данному ИНН не найдена.")

            else:
                print("Неверный режим. Попробуйте снова.")

            cont = input("\nПроверить другой режим/сайт? (да/нет): ").strip().lower()
            if cont != 'да':
                print("Программа завершена.")
                break


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем.")
