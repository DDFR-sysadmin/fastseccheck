#!/usr/bin/env bash
set -e

# Проверка запуска от имени root
if [ "$EUID" -ne 0 ]; then
  echo "Ошибка: Установщик необходимо запускать с правами root (sudo)."
  exit 1
fi

echo "=> Начинаем установку FastSecCheck..."

# 1. Определение дистрибутива
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=${ID_LIKE:-""}
else
    echo "Не удалось определить дистрибутив (отсутствует /etc/os-release)."
    exit 1
fi

echo "=> Обнаружена система: $PRETTY_NAME"

# 2. Функции установки зависимостей для разных пакетных менеджеров
install_apt() {
    echo "=> Использование APT для установки системных пакетов..."
    apt-get update
    apt-get install -y ufw auditd python3 python3-venv python3-pip
}

install_pacman() {
    echo "=> Использование PACMAN для установки системных пакетов..."
    pacman -Sy --noconfirm ufw audit python python-pip
}

install_dnf() {
    echo "=> Использование DNF для установки системных пакетов..."
    dnf install -y ufw audit python3 python3-pip
}

# Выбор пакетного менеджера на основе дистрибутива
if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS_LIKE" == *"debian"* || "$OS_LIKE" == *"ubuntu"* ]]; then
    install_apt
elif [[ "$OS" == "arch" || "$OS_LIKE" == *"arch"* ]]; then
    install_pacman
elif [[ "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "centos" || "$OS_LIKE" == *"rhel"* || "$OS_LIKE" == *"fedora"* ]]; then
    install_dnf
else
    echo "Внимание: Ваш дистрибутив не поддерживается автоматически. Установите ufw, auditd и python3 вручную."
fi

# 3. Создание директорий
BASE_DIR="/opt/FastSecCheck"
echo "=> Создание структуры директорий в $BASE_DIR..."
mkdir -p "$BASE_DIR"/{logs,alerts}

# ------------------------------------------------------------------
# БЕЗОПАСНОСТЬ: Ограничение прав на директории с логами и алертами
# Устанавливаем права 700 (rwx------), доступ будет только у root
# ------------------------------------------------------------------
chmod 700 "$BASE_DIR/logs"
chmod 700 "$BASE_DIR/alerts"
chmod 700 "$BASE_DIR" # Закрываем доступ и к самой директории утилиты

# 4. Настройка Python venv и установка croniter
echo "=> Создание виртуального окружения Python..."
python3 -m venv "$BASE_DIR/venv"

echo "=> Установка Python-зависимостей (croniter)..."
"$BASE_DIR/venv/bin/pip" install --quiet --upgrade pip
"$BASE_DIR/venv/bin/pip" install --quiet croniter

# 5. Копирование скрипта
echo "=> Развертывание логики утилиты..."
cp fastseccheck.py "$BASE_DIR/fastseccheck.py"
chmod 700 "$BASE_DIR/fastseccheck.py"

# 6. Создание wrapper-скрипта для глобального вызова
# Это позволяет вызывать fastseccheck из любой точки, используя изолированный venv
cat << 'EOF' > /usr/local/bin/fastseccheck
#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
  echo "Error: FastSecCheck must be run as root."
  exit 1
fi
exec /opt/FastSecCheck/venv/bin/python /opt/FastSecCheck/fastseccheck.py "$@"
EOF

chmod 755 /usr/local/bin/fastseccheck

echo "====================================================="
echo "=> Установка успешно завершена!"
echo "=> Логи защищены от чтения обычными пользователями."
echo "=> Вызовите 'sudo fastseccheck -h' для вывода справки."
echo "====================================================="
