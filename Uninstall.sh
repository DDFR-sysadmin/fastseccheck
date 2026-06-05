#!/usr/bin/env bash
set -e

# Проверка запуска от имени root
if [ "$EUID" -ne 0 ]; then
  echo "Ошибка: Деинсталлятор необходимо запускать с правами root (sudo)."
  exit 1
fi

echo "=> Начинаем удаление FastSecCheck..."

# 1. Остановка демона (если работает)
PID_FILE="/var/run/fastseccheck.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "=> Остановка процесса демона (PID: $PID)..."
    kill -9 "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
fi

# 2. Очистка правил auditd (для пункта 6)
echo "=> Очистка правил auditd..."
auditctl -d always,exit -F arch=b64 -S execve -F euid=33 -k www_data_exec 2>/dev/null || true

# 3. Удаление рабочих файлов и логов
BASE_DIR="/opt/FastSecCheck"
if [ -d "$BASE_DIR" ]; then
    echo "=> Удаление директории $BASE_DIR (включая логи и venv)..."
    rm -rf "$BASE_DIR"
fi

# 4. Удаление исполняемого симлинка/обертки
if [ -f "/usr/local/bin/fastseccheck" ]; then
    echo "=> Удаление обертки /usr/local/bin/fastseccheck..."
    rm -f "/usr/local/bin/fastseccheck"
fi

echo "====================================================="
echo "=> Удаление успешно завершено."
echo "=> Системные пакеты (ufw, auditd) не были удалены, так как они могут использоваться системой."
echo "====================================================="
