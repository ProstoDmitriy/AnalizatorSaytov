# Анализатор cайтов 🚀

Этот проект разработан на языке Python и автоматизирует сбор и анализ информации о веб-сайтах, чтобы помочь определить, кто владеет сайтом, его технические характеристики и проверить его статус в реестре Роскомнадзора (РКН). 

## Что делает проект? 🔍

Проект включает в себя следующие функциональные возможности:

- **Автоматическая установка модулей**  
  При запуске проекта проверяются и автоматически устанавливаются все необходимые зависимости, такие как:  
  - [**python-whois**](https://pypi.org/project/python-whois/) – для получения WHOIS-данных 📄  
  - [**Requests**](https://docs.python-requests.org/) – для синхронных HTTP-запросов 🌐  
  - [**BeautifulSoup (bs4)**](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) – для парсинга HTML и XML 📝  
  - [**aiohttp**](https://docs.aiohttp.org/) – для асинхронных HTTP-запросов ⚡

- **Извлечение информации о домене**  
  Используется функция `extract_domain(url)`, которая выделяет доменное имя из введённого URL, что позволяет работать с сайтом независимо от формата ссылки.  

- **Получение WHOIS-данных**  
  Проект запрашивает данные WHOIS о домене (регистратор, даты создания, обновления, окончания, статус, информация об организации и контактный email) с помощью библиотеки `python-whois`. Это позволяет узнать историю домена и основные сведения о владельце. 📑

- **Получение IP-данных**  
  С помощью модуля `socket` и API ip‑api.com происходит получение IP-адреса сайта и его подробной информации (страна, регион, город, провайдер, ASN, координаты и т.д.). Эта информация помогает понять, где расположен сервер сайта и какая организация его обслуживает. 🌍

- **Проверка количества страниц через sitemap.xml**  
  Проект пытается загрузить файл `sitemap.xml` (если он доступен) и подсчитывает количество тегов `<loc>`, что соответствует числу страниц сайта. Это полезно для оценки объёма ресурса. 📚

- **Проверка аналитических скриптов (метрические программы)**  
  Анализируется HTML сайта на наличие таких скриптов, как Google Analytics, Яндекс.Метрика, Facebook Pixel – с помощью регулярных выражений. Это позволяет понять, какие инструменты аналитики используются на сайте. 📈

- **Расширенный поиск ИНН владельца сайта**  
  Благодаря интеграции нескольких источников (WHOIS, HTML-код, метатеги и даже поисковые системы), проект ищет возможные ИНН (идентификационный номер налогоплательщика) владельца сайта. После этого для каждого найденного ИНН запрашивается подробная информация из официального реестра РКН. 🔎

- **Проверка блокировки через API РКН**  
  Помимо поиска ИНН, проект включает функционал проверки, заблокирован ли сайт, используя API [rknweb.ru](https://rknweb.ru/api/). Это помогает автоматически определить, находится ли ресурс в черном списке РКН. 🚫

- **Пакетная и ручная проверка ИНН**  
  В проекте предусмотрены различные режимы работы:
  - **Режим проверки сайта:** Автоматический сбор всех данных о сайте (WHOIS, IP, количество страниц, метрические программы, поиск ИНН и проверка информации РКН).
  - **Пакетная проверка ИНН:** Позволяет загружать список ИНН из файла `inns.txt` и проверять их пакетами по 100 штук – это удобно для массового анализа.
  - **Ручная проверка ИНН:** Вы можете ввести интересующий ИНН вручную и получить информацию из реестра РКН.

- **Синхронизация локальной базы данных с реестром РКН**  
  Для повышения надежности и быстродействия проекта реализована синхронизация локальной SQLite-базы с данными из реестра РКН. Это позволяет работать проекту «с первого раза» на любом компьютере. 💾

---

## Используемые технологии и библиотеки 📚

- **Язык программирования:** Python 3.x  
- **Библиотеки:**  
  - [python-whois](https://pypi.org/project/python-whois/)  
  - [Requests](https://docs.python-requests.org/)  
  - [BeautifulSoup (bs4)](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)  
  - [aiohttp](https://docs.aiohttp.org/)  
  - [SQLite (sqlite3)](https://docs.python.org/3/library/sqlite3.html)  
  - [Logging](https://docs.python.org/3/library/logging.html)

---

## Как запустить проект 🏃‍♂️

1. **Клонируйте репозиторий:**

   ```bash
   git clone https://github.com/ProstoDmitriy/AnalizatorSaytov.git
   cd AnalizatorSaytov
   ```

2. **Запустите скрипт:**

   Просто выполните:
   
   ```bash
   python RKN.py
   ```

   При первом запуске скрипт автоматически установит все необходимые модули и синхронизирует базу данных с данными из реестра РКН.

3. **Выберите режим работы:**

   После запуска вам будет предложено выбрать один из режимов:  
   - **1 - Проверка сайта:** Анализируем сайт (WHOIS, IP, количество страниц, метрические программы, поиск и проверка ИНН).  
   - **2 - Пакетная проверка ИНН из файла (inns.txt):** Проверяем список ИНН пакетами.  
   - **3 - Ручная проверка ИНН:** Введите интересующий ИНН для получения подробной информации.  
   - **4 - Проверка блокировки сайта через API RKN:** Проверяем, заблокирован ли сайт напрямую через API.

---

## Лицензия 📝

Этот проект распространяется под лицензией **MIT** 😎. Это означает, что вы можете свободно использовать, модифицировать и распространять код, при условии сохранения уведомления об авторских правах и отказа от гарантий.  
Подробнее см. в файле [LICENSE](LICENSE).

[![Лицензия: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
