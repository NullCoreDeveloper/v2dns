# Инструкция по запуску MasterDnsVPN на сервере (VPS)

В этом руководстве описаны шаги для запуска серверной части `MasterDnsVPN` и её настройки в качестве службы (daemon) на Linux.

## 1. Установка форка панели 3x-ui

Перед настройкой **MasterDnsVPN** вам необходимо развернуть нашу модифицированную панель `3x-ui` (которая содержит встроенную интеграцию и токены для DNS VPN). 

### Вариант А: Если репозиторий публичный
Для установки выполните команду в терминале (от имени root):
```bash
bash <(curl -Ls https://raw.githubusercontent.com/NullCoreDeveloper/3x-ui/master/install.sh)
```
> **Примечание:** Для успешной установки убедитесь, что в репозитории `NullCoreDeveloper/3x-ui` в разделе Releases опубликованы свежие версии архивов.

### Вариант Б: Если репозиторий приватный (Для контрибьюторов)
Так как скрипт `install.sh` не имеет доступа к приватным релизам GitHub без токена, вам нужно собрать панель самостоятельно (рекомендуется через Docker):
1. Клонируйте приватный репозиторий (потребуется ваш токен или SSH ключ):
   ```bash
   git clone https://github.com/NullCoreDeveloper/3x-ui.git
   cd 3x-ui
   ```
2. Запустите сборку и запуск через Docker:
   ```bash
   docker compose up -d --build
   ```
   *(Docker автоматически соберет Go-код и Frontend, и запустит панель)*.

После завершения установки настройте панель по стандартным портам, создайте учетные данные администратора и добавьте тестового клиента (его UUID/токен потребуется для VPN).

## 2. Подготовка домена (Критически важно)
Чтобы DNS-туннель работал, вам нужен **зарегистрированный домен**, и вы должны настроить на него **NS-записи**, указывающие на ваш сервер (VPS).
Если ваш домен `example.com`, а IP-адрес вашего сервера `1.2.3.4`, создайте следующие записи в панели регистратора:

1. **A-запись:** `ns.example.com` -> `1.2.3.4`
2. **NS-запись:** `vpn.example.com` -> `ns.example.com`

Теперь любой DNS-запрос к `*.vpn.example.com` будет направляться напрямую на ваш сервер. Этот домен (`vpn.example.com`) мы будем использовать в конфигурации.

## 3. Подготовка файлов
1. Скопируйте скомпилированный бинарный файл `masterdnsvpn-server` на ваш VPS (например, в `/opt/masterdnsvpn/`).
2. Скопируйте или создайте файл `server_config.toml` рядом с бинарником.

### Пример минимального `server_config.toml`:
```toml
PROTOCOL_TYPE = "udp"
UDP_HOST = "0.0.0.0"
UDP_PORT = 53
DOMAIN = ["vpn.example.com"]

# Путь к БД 3x-ui (если используете 3x-ui для управления пользователями)
SQLITE_PATH = "/etc/x-ui/x-ui.db"

# Переадресация расшифрованного трафика в локальный SOCKS5 (от 3x-ui)
USE_EXTERNAL_SOCKS5 = true
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = 10808

ENABLE_EDNS0 = true
```

## 4. Отключение локального DNS-резолвера (systemd-resolved)
На многих Linux-системах (Ubuntu, Debian) порт `53` занят системной службой `systemd-resolved`. Нам нужно освободить его.

1. Откройте файл `/etc/systemd/resolved.conf`:
   ```bash
   sudo nano /etc/systemd/resolved.conf
   ```
2. Раскомментируйте и измените строку:
   ```ini
   DNSStubListener=no
   ```
3. Перезапустите службу и обновите симлинк `resolv.conf`:
   ```bash
   sudo systemctl restart systemd-resolved
   sudo rm /etc/resolv.conf
   sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
   ```

## 5. Настройка службы Systemd
Чтобы сервер работал в фоне и запускался при перезагрузке, создадим systemd-сервис.

1. Создайте файл `/etc/systemd/system/masterdnsvpn.service`:
   ```bash
   sudo nano /etc/systemd/system/masterdnsvpn.service
   ```
2. Вставьте следующее содержимое (убедитесь, что пути правильные):
   ```ini
   [Unit]
   Description=MasterDnsVPN Server
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/masterdnsvpn
   ExecStart=/opt/masterdnsvpn/masterdnsvpn-server --config server_config.toml
   Restart=always
   RestartSec=5
   LimitNOFILE=1048576

   [Install]
   WantedBy=multi-user.target
   ```
3. Активируйте и запустите службу:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable masterdnsvpn
   sudo systemctl start masterdnsvpn
   ```

## 6. Проверка работы
Убедитесь, что служба работает без ошибок:
```bash
sudo systemctl status masterdnsvpn
sudo journalctl -u masterdnsvpn -f
```

Попробуйте отправить пинг-запрос с вашего ПК:
```bash
nslookup -type=TXT ping.vpn.example.com 1.2.3.4
```
Если сервер работает и домен настроен верно, вы должны получить ответ от MasterDnsVPN.

## Вариант Б: Запуск через Docker (Альтернатива)

Если вы предпочитаете Docker вместо работы с бинарниками и Systemd, вы можете запустить MasterDnsVPN через готовый контейнер.

1. Убедитесь, что порт 53 свободен (см. **Шаг 3** этого гайда, отключите `systemd-resolved`).
2. Создайте папку для данных и конфига:
   ```bash
   mkdir -p /opt/masterdnsvpn/data
   ```
3. Скопируйте туда ваш файл `server_config.toml` (из Шага 2) под именем `server_config.toml`:
   ```bash
   nano /opt/masterdnsvpn/data/server_config.toml
   ```
   **Внимание:** Если вы используете базу `3x-ui`, пропишите в `server_config.toml` путь `SQLITE_PATH = "/etc/x-ui/x-ui.db"`, так как мы пробросим этот файл внутрь контейнера.
4. Запустите Docker-контейнер следующей командой:
   ```bash
   docker run -d \
     --name masterdnsvpn \
     --restart always \
     --network host \
     -v /opt/masterdnsvpn/data:/data \
     -v /etc/x-ui/x-ui.db:/etc/x-ui/x-ui.db:ro \
     ghcr.io/nullcoredeveloper/masterdnsvpn:latest
   ```
   *(Здесь мы используем `--network host`, чтобы сервер корректно получал UDP пакеты и видел локальный SOCKS5 порт от `3x-ui`, а также прокидываем файл базы данных в режиме read-only `:ro`)*.

Для просмотра логов Docker-контейнера используйте команду:
```bash
docker logs -f masterdnsvpn
```
