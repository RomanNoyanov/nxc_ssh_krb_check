#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssh_krb_check — модуль NetExec (nxc, протокол SSH): проверка входа на хост
по Kerberos-билету (GSSAPI / gssapi-with-mic) без пароля. Файл работает и
автономно: python3 ssh_krb_check.py --help

Установка: cp ssh_krb_check.py ~/.nxc/modules/

Используется системный ssh: в paramiko >= 4 GSS-API аутентификация удалена.
"""

import getpass
import ipaddress
import re
import shutil
import subprocess
import sys

try:
    from nxc.helpers.misc import CATEGORY

    _CATEGORY = CATEGORY.ENUMERATION
except ImportError:
    _CATEGORY = "Enumeration"

try:
    from nxc.helpers.logger import highlight as _highlight
except ImportError:
    def _highlight(text, color="yellow"):
        return f"\033[1;33m{text}\033[0m"

_UNREACH_KEYWORDS = (
    "timed out",
    "connection refused",
    "no route",
    "network is unreachable",
    "could not resolve",
    "name or service not known",
    "reset by peer",
    "connection closed",
    "broken pipe",
)


def _as_str(value):
    # часть аргументов CLI nxc приходит списками (-u) — берём первый элемент
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return str(value) if value else ""


def _gssapi_ssh_cmd(host, user, port=22, timeout=8, command="true", delegate=False):
    return [
        "ssh",
        "-n",
        "-F", "/dev/null",  # игнорировать ~/.ssh/config
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(timeout)}",
        "-o", "PreferredAuthentications=gssapi-with-mic",
        "-o", "PubkeyAuthentication=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "GSSAPIAuthentication=yes",
        "-o", f"GSSAPIDelegateCredentials={'yes' if delegate else 'no'}",
        "-o", "ControlPath=none",  # не переиспользовать существующий ControlMaster
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-p", str(int(port)),
        "-l", user,
        host,
        command,
    ]


def krb_ticket_status():
    """(валиден ли билет, принципал|None); (None, None) — klist недоступен."""
    if shutil.which("klist") is None:
        return None, None
    valid = subprocess.run(["klist", "-s"], capture_output=True).returncode == 0
    principal = None
    try:
        out = subprocess.run(["klist"], capture_output=True, text=True).stdout
        m = re.search(r"(?im)^\s*(?:default\s+)?principal:\s*(\S+)", out)  # MIT и Heimdal
        if m:
            principal = m.group(1)
    except OSError:
        pass
    return valid, principal


def krb_ssh_login(host, user, port=22, timeout=8, command="true", delegate=False, verbose=False):
    """→ (статус, сообщение): OK | FAIL | UNREACH."""
    cmd = _gssapi_ssh_cmd(host, user, port, timeout, command, delegate)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return "UNREACH", f"хост недоступен (превышен таймаут {int(timeout)}с)"
    except FileNotFoundError:
        return "FAIL", "ssh не найден в PATH"

    err = (proc.stderr or "").strip()
    if proc.returncode == 0:
        msg = f"вход по Kerberos без пароля прошёл ({user}@{host}:{port})"
        out = (proc.stdout or "").strip()
        if out:
            msg += f" [{out}]"
        return "OK", msg

    low = err.lower()
    if any(k in low for k in _UNREACH_KEYWORDS):
        return "UNREACH", "хост недоступен (сеть/DNS/порт)"
    detail = err.splitlines()[-1] if err else f"rc={proc.returncode}"
    if verbose and err:
        detail = err.replace("\n", " | ")
    return "FAIL", f"аутентификация по Kerberos НЕ прошла ({detail})"


def krb_ssh_exec(host, user, command, port=22, timeout=8, codec="utf-8"):
    """Выполняет command на host по билету. → (успех, вывод stdout+stderr)."""
    if shutil.which("ssh") is None:
        return False, "ssh не найден в PATH"
    cmd = _gssapi_ssh_cmd(host, user, port, timeout, f"{command} 2>&1")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return False, f"превышен таймаут {int(timeout)}с"
    out = (proc.stdout or b"") + (proc.stderr or b"")
    return proc.returncode == 0, out.decode(codec, errors="replace").strip()


def _gssapi_scp_cmd(user, host, port, src, dst, put=True):
    cmd = [
        "scp",
        "-F", "/dev/null",
        "-o", "BatchMode=yes",
        "-o", "PreferredAuthentications=gssapi-with-mic",
        "-o", "PubkeyAuthentication=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "GSSAPIAuthentication=yes",
        "-o", "ControlPath=none",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-P", str(int(port)),
    ]
    remote = f"{user}@{host}:{dst if put else src}"
    return cmd + ([src, remote] if put else [remote, dst])


def _credless_target(conn):
    """(target, user, port, timeout) для krb-операций вне paramiko-сессии."""
    user = (
        _as_str(getattr(conn, "username", ""))
        or (NXCModule._principal or "").split("@")[0].split("/")[0]
        or getpass.getuser()
    )
    target = _as_str(getattr(conn, "hostname", None) or getattr(conn, "host", ""))
    port = int(getattr(conn, "port", 0) or 22)
    timeout = float(getattr(conn.args, "ssh_timeout", 8) or 8)
    return target, user, port, timeout


def _krb_sudo_probe(conn):
    """--sudo-check без кредов: проба passwordless sudo (sudo -n -l)."""
    target, user, port, timeout = _credless_target(conn)
    ok, out = krb_ssh_exec(target, user, "sudo -n -l", port=port, timeout=timeout, codec=getattr(conn.args, "codec", "utf-8"))
    if ok:
        conn.logger.success(f"Passwordless sudo (NOPASSWD) доступен для {user}")
        for line in out.splitlines():
            conn.logger.highlight(line)
    else:
        detail = out.splitlines()[-1] if out else "нет ответа"
        conn.logger.fail(f"sudo по билету недоступен ({detail})")


def _find_ssh_class():
    # класс ssh грузится ProtocolLoader'ом в анонимный модуль — ищем в подклассах
    try:
        from nxc.connection import connection as _base
    except ImportError:
        return None, None
    for sub in _base.__subclasses__():
        if sub.__name__ == "ssh":
            return _base, sub
    return _base, None


def _install_nocreds_hook():
    """Runtime-хуки в памяти (файлы nxc не меняются). Ставятся из options(),
    который netexec выполняет при sanity-check модулей — до соединений.

    login: SSH + пустые -u/-p/--key-file/--cred-id + -M → модули вызываются
    без входа (аналог null-session у SMB).
    call_modules: в ssh-протоколе nxc -M и флаги -x/--put-file/--get-file
    взаимоисключающие — выполняем их после модулей.
    execute/put_file/get_file: без аутентифицированной paramiko-сессии
    операция выполняется по билету через системный ssh/scp; --sudo-check
    без кредов — проба passwordless sudo (sudo -n -l).

    Обёртки идемпотентны; при любой ошибке остаётся штатное поведение.
    """
    base, cls = _find_ssh_class()
    if base is None:
        return

    if not getattr(base, "_ssh_krb_check_nocreds", False):
        base_login = base.login

        def login_with_nocreds(self):
            result = base_login(self)
            if result:
                return True
            if str(getattr(self, "protocol", "")).lower() != "ssh":
                return False
            no_creds = not (
                getattr(self.args, "cred_id", None)
                or getattr(self.args, "username", None)
                or getattr(self.args, "password", None)
                or getattr(self.args, "key_file", None)
            )
            if no_creds and getattr(self.args, "module", None):
                self.logger.debug("ssh_krb_check: кредов нет — вызываю модули без входа (runtime-фолбэк)")
                return True
            return False

        try:
            base.login = login_with_nocreds
            base._ssh_krb_check_nocreds = True
        except Exception:
            pass

    if cls is None or getattr(cls, "_ssh_krb_check_hooks", False):
        return

    orig_call_modules = cls.call_modules

    def call_modules_and_cmd_args(self):
        orig_call_modules(self)
        cmd_flags = (
            getattr(self.args, "execute", None)
            or getattr(self.args, "put_file", None)
            or getattr(self.args, "get_file", None)
        )
        if not cmd_flags and not getattr(self.args, "sudo_check", None):
            return
        try:
            transport = self.conn.get_transport() if self.conn else None
            authed = transport is not None and transport.is_authenticated()
            # обёртки execute/put_file/get_file сами выберут paramiko или билет
            if cmd_flags:
                self.call_cmd_args()
            if getattr(self.args, "sudo_check", None) and not authed:
                _krb_sudo_probe(self)
        except Exception as e:
            self.logger.fail(f"ssh_krb_check: ошибка выполнения флагов после модулей: {e}")

    orig_execute = cls.execute

    def execute_with_krb(self, payload=None, get_output=False):
        transport = self.conn.get_transport() if self.conn else None
        if transport is not None and transport.is_authenticated():
            return orig_execute(self, payload, get_output)
        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True
        target, user, port, timeout = _credless_target(self)
        ok, output = krb_ssh_exec(target, user, payload, port=port, timeout=timeout, codec=getattr(self.args, "codec", "utf-8"))
        if not ok:
            self.logger.fail(f"Execute command failed, error: {output}")
            return False
        self.logger.success("Executed command")
        if get_output:
            for line in output.replace("\r\n", "\n").rstrip("\n").split("\n"):
                self.logger.highlight(line.strip("\n"))
        return output

    orig_put_file = cls.put_file

    def put_file(self):
        transport = self.conn.get_transport() if self.conn else None
        if transport is not None and transport.is_authenticated():
            return orig_put_file(self)
        target, user, port, _ = _credless_target(self)
        for src, dst in self.args.put_file:
            self.logger.display(f'Copying "{src}" to "{dst}"')
            proc = subprocess.run(_gssapi_scp_cmd(user, target, port, src, dst, put=True), capture_output=True)
            err = (proc.stderr or b"").decode("utf-8", "replace").strip()
            if proc.returncode == 0:
                self.logger.success(f'Created file "{src}" on "{dst}"')
            else:
                self.logger.fail(f'Error writing file to "{dst}": {err.splitlines()[-1] if err else proc.returncode}')

    orig_get_file = cls.get_file

    def get_file(self):
        transport = self.conn.get_transport() if self.conn else None
        if transport is not None and transport.is_authenticated():
            return orig_get_file(self)
        target, user, port, _ = _credless_target(self)
        for src, dst in self.args.get_file:
            self.logger.display(f'Copying "{src}" to "{dst}"')
            proc = subprocess.run(_gssapi_scp_cmd(user, target, port, src, dst, put=False), capture_output=True)
            err = (proc.stderr or b"").decode("utf-8", "replace").strip()
            if proc.returncode == 0:
                self.logger.success(f'File "{src}" was downloaded to "{dst}"')
            else:
                self.logger.fail(f'Error getting file: {err.splitlines()[-1] if err else proc.returncode}')

    try:
        cls.call_modules = call_modules_and_cmd_args
        cls.execute = execute_with_krb
        cls.put_file = put_file
        cls.get_file = get_file
        cls._ssh_krb_check_hooks = True
    except Exception:
        pass


class NXCModule:
    name = "ssh_krb_check"
    description = "Проверка возможности входа по Kerberos-билету (SSH/GSSAPI) без пароля"
    supported_protocols = ["ssh"]
    category = _CATEGORY
    opsec_safe = True  # файлов на цели не создаёт; каждая проверка — запись в логе sshd
    multiple_hosts = True

    _banner_shown = False
    _principal = None

    def __init__(self):
        self.timeout = 8
        self.delegate = False
        self.verbose = False

    def options(self, context, module_options):
        """
        TIMEOUT   таймаут соединения в секундах (по умолчанию: 8)
        DELEGATE  делегировать билет хосту, как ssh -K (по умолчанию: FALSE)
        VERBOSE   при ошибке показывать полный вывод ssh (по умолчанию: FALSE)

        Пользователь: -u из nxc; без него — из принципала билета. Порт — из
        --port nxc, проверяется только факт входа.
        """
        try:
            self.timeout = int(float(module_options.get("TIMEOUT") or 8))
        except (TypeError, ValueError):
            self.timeout = 8
        self.delegate = str(module_options.get("DELEGATE", "false")).lower() in ("true", "1", "yes")
        self.verbose = str(module_options.get("VERBOSE", "false")).lower() in ("true", "1", "yes")
        _install_nocreds_hook()

    def on_login(self, context, connection):
        log = context.log

        if shutil.which("ssh") is None:
            if not NXCModule._banner_shown:
                NXCModule._banner_shown = True
                log.fail("ssh_krb_check: ssh не найден в PATH")
            return

        if not NXCModule._banner_shown:
            NXCModule._banner_shown = True
            valid, principal = krb_ticket_status()
            NXCModule._principal = principal
            if valid is False:
                log.highlight("ssh_krb_check: действующий билет Kerberos не найден (выполните kinit) — вход по билету не состоится")
            elif valid is None:
                log.highlight("ssh_krb_check: klist недоступен — состояние билета неизвестно")
            else:
                log.highlight(f"ssh_krb_check: билет Kerberos: {principal or '<принципал не определён>'}")

        target = _as_str(getattr(connection, "hostname", None) or getattr(connection, "host", ""))
        # принципал добываем независимо от баннера: при параллельных хостах
        # соседний поток может ещё не успеть заполнить _principal
        user = _as_str(getattr(connection, "username", ""))
        if not user:
            principal = NXCModule._principal
            if not principal:
                principal = NXCModule._principal = (krb_ticket_status()[1] or "")
            user = principal.split("@")[0].split("/")[0] or getpass.getuser()
        port = getattr(connection, "port", None) or 22

        status, msg = krb_ssh_login(target, user, port, self.timeout, "true", self.delegate, self.verbose)
        if status == "OK":
            try:
                connection.logger.success(f"{user}: (kerberos ticket) {_highlight('Linux - Shell access!')}")
            except Exception:
                log.success(f"ssh_krb_check: {msg}")
        else:
            if "таймаут" in msg:
                msg += " (хост доступен; вероятно, завис поиск KDC — экспортируйте KRB5_CONFIG)"
            log.fail(f"ssh_krb_check: {msg}")


def _expand_targets(items):
    """Раскрывает диапазоны IP: полные (10.10.10.1-10.10.10.50) и
    сокращённые по последнему октету (10.10.10.1-50)."""
    hosts = []
    for item in items:
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})", item)
        m_short = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})", item)
        if m:
            a, b = (int(ipaddress.IPv4Address(x)) for x in m.groups())
            if b < a:
                a, b = b, a
            if b - a > 65535:
                print(f"Ошибка: диапазон слишком велик (>65536 хостов): {item}", file=sys.stderr)
                sys.exit(2)
            hosts.extend(str(ipaddress.IPv4Address(i)) for i in range(a, b + 1))
        elif m_short:
            base, last = m_short.groups()
            prefix, a = base.rsplit(".", 1)
            a, b = int(a), int(last)
            if not (0 <= a <= 255 and 0 <= b <= 255):
                print(f"Ошибка: некорректный диапазон: {item}", file=sys.stderr)
                sys.exit(2)
            if b < a:
                a, b = b, a
            hosts.extend(f"{prefix}.{i}" for i in range(a, b + 1))
        else:
            hosts.append(item)
    return hosts


def _cli(argv):
    import argparse
    import concurrent.futures

    parser = argparse.ArgumentParser(
        description="Проверка SSH-аутентификации по Kerberos (GSSAPI) без пароля на пуле хостов.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Хост: IP, hostname или диапазон IP, напр. 10.10.10.1-10.10.10.50\n"
            "Статусы: OK — вход по билету прошёл; FAIL — аутентификация НЕ прошла; UNREACH — хост недоступен\n"
            "Коды выхода: 0 — все хосты OK; 1 — есть FAIL/UNREACH; 2 — ошибка аргументов/окружения"
        ),
    )
    parser.add_argument("-u", "--user", default=None, help="пользователь для SSH (по умолчанию: из принципала билета, иначе — текущий пользователь)")
    parser.add_argument("-p", "--port", type=int, default=22, help="порт SSH (по умолчанию: %(default)s)")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="таймаут соединения в секундах (по умолчанию: %(default)s)")
    parser.add_argument("-c", "--command", default="true", help="команда на хосте после входа (по умолчанию: '%(default)s' — только вход)")
    parser.add_argument("-K", "--delegate", action="store_true", help="делегировать билет хосту (как ssh -K)")
    parser.add_argument("-P", "--parallel", type=int, default=10, help="число параллельных проверок (по умолчанию: %(default)s)")
    parser.add_argument("-f", "--hosts-file", help="файл со списком хостов (по одному в строке; '#' — комментарий)")
    parser.add_argument("-o", "--output", help="сохранить список хостов с успешной аутентификацией в файл")
    parser.add_argument("-l", "--list-only", action="store_true", help="только вывести список хостов после раскрытия диапазонов")
    parser.add_argument("-v", "--verbose", action="store_true", help="при ошибке показывать полный вывод ssh")
    parser.add_argument("hosts", nargs="*", help="IP, hostname или диапазон IP")
    args = parser.parse_args(argv)

    if shutil.which("ssh") is None:
        print("Ошибка: ssh не найден в PATH", file=sys.stderr)
        return 2

    raw = list(args.hosts)
    if args.hosts_file:
        try:
            with open(args.hosts_file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        raw.append(line)
        except OSError as e:
            print(f"Ошибка: файл недоступен для чтения: {e}", file=sys.stderr)
            return 2
    if not raw:
        parser.print_help()
        return 2

    hosts = _expand_targets(raw)
    if args.list_only:
        print("\n".join(hosts))
        return 0

    tty = sys.stdout.isatty()

    def paint(code, text):
        return f"\033[{code}m{text}\033[0m" if tty else text

    valid, principal = krb_ticket_status()
    if args.user is None:
        args.user = principal.split("@")[0].split("/")[0] if principal else getpass.getuser()
    if valid is False:
        print(paint("1;33", "ВНИМАНИЕ: действующий билет Kerberos не найден (выполните kinit) — все проверки дадут FAIL.\n"), file=sys.stderr)
    else:
        print(paint("1;36", f"Пользователь: {args.user}   Керберос-билет: {principal or '<не определён>'}"))
    print(f"Хостов к проверке: {len(hosts)}   Параллельно: {args.parallel}   Таймаут: {args.timeout}с\n")

    results = {}

    def check(host):
        return host, krb_ssh_login(host, args.user, args.port, args.timeout, args.command, args.delegate, args.verbose)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        for host, (status, msg) in pool.map(check, hosts):
            results[host] = status
            color = {"OK": "1;32", "FAIL": "1;31", "UNREACH": "1;33"}[status]
            print(f"{paint(color, f'[{status:<7}]')} {host:<32} {msg}")

    ok_n = sum(1 for s in results.values() if s == "OK")
    fail_n = sum(1 for s in results.values() if s == "FAIL")
    unr_n = sum(1 for s in results.values() if s == "UNREACH")

    print(f"\n{paint('1;36', '============= ИТОГ =============')}")
    print(f"Всего: {len(results)}   {paint('1;32', f'OK: {ok_n}')}   {paint('1;31', f'FAIL: {fail_n}')}   {paint('1;33', f'UNREACH: {unr_n}')}")

    if ok_n:
        print("\nХосты с успешным входом по Kerberos:")
        for host, status in results.items():
            if status == "OK":
                print(f"  {host}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(h for h, s in results.items() if s == "OK"))
            if ok_n:
                fh.write("\n")
        print(f"\nСписок OK-хостов записан в: {args.output}")

    return 0 if (fail_n == 0 and unr_n == 0) else 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
