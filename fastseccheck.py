#!/usr/bin/env python3
import os
import sys
import time
import stat
import subprocess
import argparse
import logging
import locale
import re
from datetime import datetime
from pathlib import Path

try:
    from croniter import croniter
except ImportError:
    print("Ошибка: Для работы демона требуется модуль 'croniter'. Установите: pip install croniter")
    sys.exit(1)

# --- Настройки путей ---
BASE_DIR = "/opt/FastSecCheck"
LOG_DIR = f"{BASE_DIR}/logs"
ALERT_DIR = f"{BASE_DIR}/alerts"

# --- Локализация ---
TRANSLATIONS = {
    'ru': {
        'run_as_root': "Утилиту необходимо запускать с правами root (sudo).",
        'check_file': "Проверка файла: {file}",
        'fix_perms': "Исправлены права на {file} (теперь {perms})",
        'fix_prompt': "Исправить? [y/N]: ",
        'ssh_check': "Проверка конфигурации SSH...",
        'ssh_fixed': "Конфигурация SSH обновлена (RootLogin/PasswordAuth отключены). Перезапуск сервиса.",
        'fw_check': "Проверка фаервола...",
        'fw_enabled': "Фаервол (ufw) включен.",
        'fw_install_prompt': "Фаервол не найден. Установить и настроить ufw? [y/N]: ",
        'suid_check': "Поиск бесхозных SUID/SGID файлов (может занять время)...",
        'ports_check': "Сбор информации об открытых портах...",
        'user_check': "Проверка файлов системных пользователей вне их директорий...",
        'alert_suid': "[{date}] обнаружен SUID файл: {file}",
        'alert_fw': "[{date}] изменение состояния фаервола: {status}",
        'daemon_start': "Запуск демона FastSecCheck с расписанием: {cron}",
        'daemon_stop': "Остановка демона FastSecCheck...",
    },
    'en': {
        'run_as_root': "This utility must be run as root (sudo).",
        'check_file': "Checking file: {file}",
        'fix_perms': "Fixed permissions for {file} (now {perms})",
        'fix_prompt': "Fix this? [y/N]: ",
        'ssh_check': "Checking SSH configuration...",
        'ssh_fixed': "SSH config updated (RootLogin/PasswordAuth disabled). Restarting service.",
        'fw_check': "Checking firewall...",
        'fw_enabled': "Firewall (ufw) enabled.",
        'fw_install_prompt': "Firewall not found. Install and configure ufw? [y/N]: ",
        'suid_check': "Searching for orphaned SUID/SGID files (may take a while)...",
        'ports_check': "Gathering info on open ports...",
        'user_check': "Checking system user files outside their directories...",
        'alert_suid': "[{date}] SUID file detected: {file}",
        'alert_fw': "[{date}] firewall state changed: {status}",
        'daemon_start': "Starting FastSecCheck daemon with schedule: {cron}",
        'daemon_stop': "Stopping FastSecCheck daemon...",
    }
}

class FastSecCheck:
    def __init__(self, autofix=False, iac=False, lang='en'):
        self.autofix = autofix
        self.iac = iac
        self.lang = lang if lang in TRANSLATIONS else 'en'
        self.t = TRANSLATIONS[self.lang]
        
        self.setup_logging()

    def _(self, key, **kwargs):
        """Возвращает переведенную строку"""
        return self.t.get(key, key).format(**kwargs)

    def setup_logging(self):
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path(ALERT_DIR).mkdir(parents=True, exist_ok=True)

        # Основной логер
        self.logger = logging.getLogger("FastSecCheck")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(f"{LOG_DIR}/main.log")
        fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        sh = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(fh)
        self.logger.addHandler(sh)

        # Алерт логер (для демона)
        self.alert_logger = logging.getLogger("Alerts")
        self.alert_logger.setLevel(logging.WARNING)
        afh = logging.FileHandler(f"{ALERT_DIR}/alerts.log")
        afh.setFormatter(logging.Formatter('%(message)s')) # Формат задается вручную при вызове
        self.alert_logger.addHandler(afh)

    def ask_fix(self, prompt_text):
        if self.iac: return True
        if self.autofix:
            ans = input(prompt_text).strip().lower()
            return ans == 'y'
        return False

    def run_cmd(self, cmd, shell=False):
        try:
            res = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
            return res.returncode == 0, res.stdout.strip()
        except Exception:
            return False, ""

    # 1. Проверка важных файлов
    def check_critical_files(self):
        files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
            '/etc/group': 0o644
        }
        for file_path, target_mode in files.items():
            self.logger.info(self._('check_file', file=file_path))
            if os.path.exists(file_path):
                current_mode = stat.S_IMODE(os.stat(file_path).st_mode)
                if current_mode != target_mode:
                    self.logger.warning(f"Bad permissions on {file_path}: {oct(current_mode)}")
                    if self.ask_fix(self._('fix_prompt')):
                        os.chmod(file_path, target_mode)
                        self.logger.info(self._('fix_perms', file=file_path, perms=oct(target_mode)))

    # 2. Проверка SSH
    def check_ssh(self):
        self.logger.info(self._('ssh_check'))
        ssh_conf = '/etc/ssh/sshd_config'
        if os.path.exists(ssh_conf):
            with open(ssh_conf, 'r') as f:
                content = f.read()
            
            needs_fix = False
            if not re.search(r'^PermitRootLogin\s+no', content, re.MULTILINE):
                self.logger.warning("SSH: PermitRootLogin is not 'no'")
                needs_fix = True
            if not re.search(r'^PasswordAuthentication\s+no', content, re.MULTILINE):
                self.logger.warning("SSH: PasswordAuthentication is not 'no'")
                needs_fix = True

            if needs_fix and self.ask_fix(self._('fix_prompt')):
                content = re.sub(r'^#?PermitRootLogin.*', 'PermitRootLogin no', content, flags=re.MULTILINE)
                content = re.sub(r'^#?PasswordAuthentication.*', 'PasswordAuthentication no', content, flags=re.MULTILINE)
                with open(ssh_conf, 'w') as f:
                    f.write(content)
                self.run_cmd(["systemctl", "reload", "sshd"])
                self.logger.info(self._('ssh_fixed'))

    # 3. Проверка фаервола
    def check_firewall(self):
        self.logger.info(self._('fw_check'))
        success, output = self.run_cmd(["ufw", "status"])
        if "inactive" in output or not success:
            self.logger.warning("Firewall is DISABLED or not found.")
            if self.ask_fix(self._('fw_install_prompt')):
                # Базовая настройка
                self.run_cmd(["apt-get", "install", "-y", "ufw"])
                self.run_cmd(["ufw", "allow", "ssh"])
                self.run_cmd(["ufw", "--force", "enable"])
                self.logger.info(self._('fw_enabled'))
                self.alert_logger.warning(self._('alert_fw', date=datetime.now().isoformat(), status="Enabled via AutoFix"))

    # 4. SUID/SGID
    def check_suid(self):
        self.logger.info(self._('suid_check'))
        # Ищем SUID/SGID файлы.
        success, output = self.run_cmd("find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null", shell=True)
        if output:
            for line in output.split('\n'):
                self.logger.warning(f"SUID/SGID found: {line}")
                # Для демона пишем в алерты 
                self.alert_logger.warning(self._('alert_suid', date=datetime.now().isoformat(), file=line))

    # 5. Открытые порты
    def check_ports(self):
        self.logger.info(self._('ports_check'))
        success, output = self.run_cmd(["ss", "-tulpan"])
        if success:
            with open(f"{LOG_DIR}/ports.log", "w") as f:
                f.write(output)
            self.logger.info("Open ports saved to logs/ports.log")

    # 6. Системные пользователи (www-data и файлы вне /var/www)
    def check_system_users(self):
        self.logger.info(self._('user_check'))
        # Пример: ищем файлы www-data вне /var/www
        cmd = "find / -user www-data -not -path '/var/www/*' -not -path '/proc/*' -not -path '/sys/*' -type f 2>/dev/null"
        success, output = self.run_cmd(cmd, shell=True)
        if output:
            for line in output.split('\n')[:10]: # Выводим первые 10 для лога
                self.logger.warning(f"Out-of-bounds file owned by www-data: {line}")

    # Полный скан (для разового запуска)
    def run_full_scan(self):
        self.logger.info(f"--- Starting FastSecCheck ({self.lang}) ---")
        self.check_critical_files()
        self.check_ssh()
        self.check_firewall()
        self.check_suid()
        self.check_ports()
        self.check_system_users()
        self.logger.info("--- Scan Complete ---")


def handle_daemon(cron_expr, checker_instance):
    if cron_expr == "-":
        checker_instance.logger.info(checker_instance._('daemon_stop'))
        # Логика убийства демона (через pid файл)
        pid_file = Path("/var/run/fastseccheck.pid")
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), 9)
                pid_file.unlink()
            except ProcessLookupError:
                pass
        sys.exit(0)

    # Демонизация (простой fork)
    if os.fork() > 0:
        sys.exit(0)
    
    Path("/var/run/fastseccheck.pid").write_text(str(os.getpid()))
    checker_instance.logger.info(checker_instance._('daemon_start', cron=cron_expr))

    # Для мониторинга команд (демон) мы бы настроили auditd правила
    checker_instance.run_cmd("auditctl -a always,exit -F arch=b64 -S execve -F euid=33 -k www_data_exec", shell=True)

    while True:
        try:
            # Высчитываем время до следующего запуска по крону
            cron = croniter(cron_expr, datetime.now())
            next_run = cron.get_next(datetime)
            sleep_time = (next_run - datetime.now()).total_seconds()
            
            if sleep_time > 0:
                time.sleep(sleep_time)
            
            # Запуск проверок демоном
            checker_instance.run_full_scan()
            
            # Парсинг auditd логов на предмет запуска команд пользователем www-data
            success, output = checker_instance.run_cmd("ausearch -k www_data_exec -ts recent 2>/dev/null", shell=True)
            if success and "execve" in output:
                checker_instance.alert_logger.warning(f"[{datetime.now().isoformat()}] ALERT: www-data executed a shell command!")

        except Exception as e:
            checker_instance.logger.error(f"Daemon error: {e}")
            time.sleep(60)

def main():
    if os.geteuid() != 0:
        print("Error: FastSecCheck must be run as root.")
        sys.exit(1)

    sys_lang = locale.getdefaultlocale()[0][:2] if locale.getdefaultlocale()[0] else 'en'
    
    parser = argparse.ArgumentParser(description="FastSecCheck - Security Auditing & Fix Utility")
    parser.add_argument('-d', '--deamon', type=str, metavar="CRON", help='Run as daemon with cron schedule (or "-" to stop)')
    parser.add_argument('-aF', '--auto-fix', action='store_true', help='Interactive fix mode')
    parser.add_argument('--IaC', action='store_true', help='Non-interactive auto fix mode')
    parser.add_argument('--Language', type=str, help='Output language (en/ru)', default=sys_lang)
    
    args = parser.parse_args()

    # Инициализация ядра утилиты
    checker = FastSecCheck(autofix=args.auto_fix, iac=args.IaC, lang=args.Language)

    if args.deamon:
        handle_daemon(args.deamon, checker)
    else:
        checker.run_full_scan()

if __name__ == "__main__":
    main()
