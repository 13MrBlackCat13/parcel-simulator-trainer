# Parcel Simulator Trainer

[English](#english) | [Русский](#русский)

![Parcel Simulator](https://cdn.cloudflare.steamstatic.com/steam/apps/2424010/header.jpg)

## English

### Description
This is a memory modification tool (trainer) for the game [Parcel Simulator](https://store.steampowered.com/app/2424010/Parcel_Simulator/). It allows you to modify your in-game money amount using memory scanning techniques.

### Features
- Modify in-game money to any value
- Automatic memory scanning with multiple techniques (differential scanning, signature scanning)
- Persistent memory signatures for reliable access across game sessions
- Multi-language support (English, Russian, German)
- Automatic system language detection

### Download
You can download the latest release executable from the [Releases](https://github.com/13MrBlackCat13/parcel-simulator-trainer/releases) page.

### Usage Instructions
1. Run the game first
2. Run the trainer as administrator (right-click → Run as administrator)
3. The trainer will attempt to connect to the game and find the money address:
   - If you're running it for the first time, it will scan for the money address (follow the on-screen instructions)
   - If you've run it before, it will use saved signatures to find the address quickly
4. Once connected, you can modify your money amount from the menu

### Building from Source
If you want to build the trainer from source:

1. Clone the repository:
   ```
   git clone https://github.com/13MrBlackCat13/parcel-simulator-trainer.git
   cd parcel-simulator-trainer
   ```

2. Create a virtual environment and install dependencies:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Run the trainer:
   ```
   python main.py
   ```

4. To build an executable:
   ```
   pip install pyinstaller
   pyinstaller --onefile --icon=icon.ico main.py
   ```

### Requirements
- Windows OS
- [Parcel Simulator](https://store.steampowered.com/app/2424010/Parcel_Simulator/) game
- Administrator privileges (for memory access)

### Disclaimer
This software is provided for educational purposes only. Use at your own risk. The developer is not responsible for any consequences of using this software.

---

## Русский

### Описание
Это инструмент для модификации памяти (трейнер) для игры [Parcel Simulator](https://store.steampowered.com/app/2424010/Parcel_Simulator/). Он позволяет изменять количество денег в игре с помощью техник сканирования памяти.

### Функции
- Изменение количества денег в игре на любое значение
- Автоматическое сканирование памяти с несколькими техниками (дифференциальное сканирование, сканирование по сигнатурам)
- Постоянные сигнатуры памяти для надежного доступа между сессиями игры
- Многоязычная поддержка (английский, русский, немецкий)
- Автоматическое определение языка системы

### Скачать
Вы можете скачать готовый исполняемый файл со страницы [Релизы](https://github.com/13MrBlackCat13/parcel-simulator-trainer/releases).

### Инструкция по использованию
1. Сначала запустите игру
2. Запустите трейнер от имени администратора (правый клик → Запустить от имени администратора)
3. Трейнер попытается подключиться к игре и найти адрес денег:
   - Если вы запускаете его впервые, он просканирует память для поиска адреса денег (следуйте инструкциям на экране)
   - Если вы уже запускали его ранее, он использует сохраненные сигнатуры для быстрого поиска адреса
4. После подключения вы можете изменить количество денег через меню

### Сборка из исходников
Если вы хотите собрать трейнер из исходного кода:

1. Клонируйте репозиторий:
   ```
   git clone https://github.com/13MrBlackCat13/parcel-simulator-trainer.git
   cd parcel-simulator-trainer
   ```

2. Создайте виртуальное окружение и установите зависимости:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Запустите трейнер:
   ```
   python main.py
   ```

4. Для сборки исполняемого файла:
   ```
   pip install pyinstaller
   pyinstaller --onefile --icon=icon.ico main.py
   ```

### Требования
- Операционная система Windows
- Игра [Parcel Simulator](https://store.steampowered.com/app/2424010/Parcel_Simulator/)
- Права администратора (для доступа к памяти)

### Отказ от ответственности
Это программное обеспечение предоставляется только в образовательных целях. Используйте на свой страх и риск. Разработчик не несет ответственности за любые последствия использования данного программного обеспечения.