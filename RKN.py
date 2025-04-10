import sys, socket, ssl, re, subprocess, sqlite3, json, logging, asyncio
from urllib.parse import urlparse, urlencode
from datetime import datetime
import aiohttp
from bs4 import BeautifulSoup
from whois import whois as get_whois_data

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Функция для автоматической установки модулей (при необходимости)
def install(pkg):
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

for pkg in ['whois', 'requests', 'bs4', 'aiohttp']:
    install(pkg)

# Глобальный кэш для HTML главной страницы
_html_cache = {}

# Компилированное регулярное выражение для поиска ИНН (10-12 цифр с разделителями)
inn_regex = re.compile(r"\b(?:\d[\s-]?){10,12}\b")

# Вспомогательная функция форматирования даты
def fmt_date(d):
    if isinstance(d, list):
        d = d[0]
    try:
        return d.strftime("%d-%m-%Y") if isinstance(d, datetime) else str(d)
    except Exception:
        return str(d)

# Извлечение домена из URL
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else parsed.path

# Асинхронное получение HTML главной страницы с кэшированием
async def get_main_html(domain):
    if domain in _html_cache:
        return _html_cache[domain]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{domain}", timeout=5) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    _html_cache[domain] = text
                    return text
    except Exception as e:
        logging.error(f"Ошибка получения HTML для {domain}: {e}")
        return ""
    return ""

# Функция для получения количества страниц сайта через sitemap.xml
async def get_total_pages(domain):
    sitemap_url = f"http://{domain}/sitemap.xml"
    try:
        async with aiohttp.ClientSession() as session:
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

# Получение WHOIS-данных (синхронно)
def get_whois_info(domain):
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

# Асинхронное получение IP-данных через ip-api.com с обработкой BOM
async def get_ip_data(domain):
    try:
        ip = socket.gethostbyname(domain)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,isp,as,lat,lon,org,query"
        async with aiohttp.ClientSession() as session:
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

# Получение серверной информации (синхронно)
def get_server_info(domain):
    info = {}
    try:
        headers = requests.get(f"http://{domain}", timeout=5).headers
        info["HTTP заголовки"] = "\n".join(f"{k}: {v}" for k, v in headers.items())
    except Exception as e:
        info["HTTP заголовки"] = f"Не найдено ({e})"
    try:
        s = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=domain)
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

# Асинхронная проверка метрических программ
async def check_metrics(domain):
    try:
        html = (await get_main_html(domain)).lower()
        patterns = [
            ("Google Analytics", "google-analytics.com"),
            ("Яндекс.Метрика", "yandex.ru/metrika"),
            ("Facebook Pixel", r"fbq\(")
        ]
        metrics = [name for name, pattern in patterns if re.search(pattern, html)]
        return metrics if metrics else ["Нет найденных метрических программ"]
    except Exception as e:
        return [f"Ошибка при проверке метрических программ: {e}"]

# Асинхронный расширенный поиск ИНН во всех источниках (WHOIS, HTML, метатеги и т.д.)
async def search_inn(domain):
    inns = set()
    # Поиск в WHOIS-данных (синхронно)
    whois_info = get_whois_info(domain)
    if isinstance(whois_info, dict):
        for field, text in whois_info.items():
            for match in inn_regex.findall(str(text)):
                clean = re.sub(r"[\s-]", "", match)
                if len(clean) in (10, 12):
                    inns.add(clean)
    # Поиск в HTML главной страницы (асинхронно)
    html = await get_main_html(domain)
    if html:
        for match in inn_regex.findall(html):
            clean = re.sub(r"[\s-]", "", match)
            if len(clean) in (10, 12):
                inns.add(clean)
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["meta", "script", "div", "span", "a", "footer"]):
                content = tag.get("content") or tag.string or ""
                for match in inn_regex.findall(content):
                    clean = re.sub(r"[\s-]", "", match)
                    if len(clean) in (10, 12):
                        inns.add(clean)
        except Exception:
            pass
    return list(inns)

# Асинхронный поиск ИНН через поисковые системы (DuckDuckGo, Yandex, Google)
async def search_inn_via_search_engines(domain):
    query = f"ИНН владельца сайта {domain}"
    results = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    urls = [
        ("https://duckduckgo.com/html/", "q"),
        ("https://yandex.ru/search/", "text"),
        ("https://www.google.com/search", "q")
    ]
    async with aiohttp.ClientSession() as session:
        for url, param_key in urls:
            try:
                params = {param_key: query}
                async with session.get(url, params=params, headers=headers, timeout=10) as resp:
                    html = (await resp.text()).lower()
                    for match in inn_regex.findall(html):
                        clean = re.sub(r"[\s-]", "", match)
                        if len(clean) in (10, 12):
                            results.add(clean)
            except Exception:
                continue
    return list(results)

# Объединённый расширенный поиск ИНН
async def search_inn_ext(domain):
    inns = set(await search_inn(domain))
    if not inns:
        inns.update(await search_inn_via_search_engines(domain))
    return list(inns)

# Асинхронное получение подробной информации из реестра РКН по ИНН
# (Интегрирована логика, заимствованная из репозитория rkn_registry)
async def get_rkn_operator_details_by_inn(inn):
    base_url = "https://pd.rkn.gov.ru/operators-registry/operators-list/"
    params = {"inn": inn}
    search_url = base_url + "?" + urlencode(params)
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        async with aiohttp.ClientSession() as session:
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
        async with aiohttp.ClientSession() as session:
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

# Новая функция: Асинхронная проверка блокировки сайта через API RKN
async def check_site_rkn_api(domain):
    url = f"https://rknweb.ru/api/v3/domains/?domain={domain}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Предположим, что API возвращает ключ "blocked": True/False
                    return data.get("blocked", False)
                else:
                    return False
    except Exception as e:
        logging.error(f"Ошибка проверки домена через RKN API: {e}")
        return False

# Функция пакетной проверки ИНН через реестр РКН (синхронно)
def check_inn_in_rkn_registry(inn_list):
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

# Функция пакетной проверки ИНН из файла (обработка батчами)
def batch_check_inn_from_file(filename):
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

# Функция синхронизации базы данных с реестром РКН (демонстрационный вариант)
def sync_rkn_db():
    conn = sqlite3.connect("rkn_operators.db")
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS operators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reg_number TEXT,
                    operator_name TEXT,
                    inn TEXT,
                    operator_type TEXT,
                    inclusion_basis TEXT,
                    notification_date TEXT,
                    data_start_date TEXT,
                    legal_address TEXT,
                    other_info TEXT)''')
    conn.commit()
    base_url = "https://pd.rkn.gov.ru/operators-registry/operators-list/"
    headers = {"User-Agent": "Mozilla/5.0"}
    num_pages = 2  # Демонстрация: синхронизация 2 страниц; расширьте при необходимости
    for page in range(1, num_pages+1):
        url = base_url + "?page=" + str(page)
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
            cur.execute('''INSERT INTO operators 
                           (reg_number, operator_name, inn, operator_type, inclusion_basis, notification_date, data_start_date, legal_address, other_info) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (reg_number, op_name_inn, "", op_type, inclusion_basis, notification_date, data_start, "", other_info))
            conn.commit()
            logging.info(f"Добавлен регистратор с регистрационным номером: {reg_number}")
    conn.close()

# Основное меню и цикл программы
async def main():
    logging.info("Синхронизация базы данных с реестром РКН...")
    sync_rkn_db()
    logging.info("Синхронизация завершена.\n")
    
    while True:
        print("\nВыберите режим работы:")
        print("1 - Проверка сайта")
        print("2 - Пакетная проверка ИНН из файла (inns.txt)")
        print("3 - Ручная проверка ИНН")
        print("4 - Проверка блокировки сайта через API RKN")
        mode = input("Введите номер режима: ").strip()
        
        if mode == "2":
            batch_check_inn_from_file("inns.txt")
        elif mode == "3":
            inn_manual = input("Введите интересующий ИНН: ").strip()
            print("\n--- Проверка ИНН в реестре РКН (ручной режим) ---")
            details = await get_rkn_operator_details_by_inn(inn_manual)
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
        elif mode == "4":
            domain = extract_domain(input("Введите адрес сайта для проверки через RKN API (например, https://www.example.com): "))
            print("\n--- Проверка блокировки сайта через API RKN ---")
            is_blocked = await check_site_rkn_api(domain)
            if is_blocked:
                print(f"Сайт {domain} заблокирован (RKN API).")
            else:
                print(f"Сайт {domain} не заблокирован (RKN API).")
        else:
            domain = extract_domain(input("Введите адрес сайта (например, https://www.example.com): "))
            
            print("\n--- WHOIS данные ---")
            whois_info = get_whois_info(domain)
            if isinstance(whois_info, dict):
                for k, v in whois_info.items():
                    print(f"{k}: {v}")
            else:
                print(whois_info)
            
            print("\n--- IP и дополнительная информация ---")
            ip_data = await get_ip_data(domain)
            if isinstance(ip_data, dict):
                for k, v in ip_data.items():
                    print(f"{k}: {v}")
            else:
                print(ip_data)
            
            print("\n--- Количество страниц сайта (sitemap.xml) ---")
            total_pages = await get_total_pages(domain)
            if total_pages is not None:
                print(f"Всего страниц: {total_pages}")
            else:
                print("Не удалось определить количество страниц.")
            
            print("\n--- Метрические программы ---")
            metrics = await check_metrics(domain)
            print(", ".join(metrics))
            
            print("\n--- Расширенный поиск ИНН владельца ---")
            inns_found = await search_inn_ext(domain)
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
                    details = await get_rkn_operator_details_by_inn(inn)
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
        
        cont = input("\nПроверить другой режим/сайт? (да/нет): ").strip().lower()
        if cont != 'да':
            print("Программа завершена.")
            break

if __name__ == "__main__":
    asyncio.run(main())
