# ssh_krb_check

**Русский** | [English](README.en.md)

Проверка входа на хосты по Kerberos-билету (SSH, GSSAPI / gssapi-with-mic) без пароля. Два режима: модуль NetExec (nxc) и автономный CLI.

На каждой цели открывается отдельное ssh-соединение, в котором разрешён только `gssapi-with-mic` (ключи, пароли, ssh-agent, ControlMaster отключены) — успех гарантирует, что сработал именно билет.

## Требования

- билет Kerberos (`kinit`), переменные `KRB5_CONFIG`, `KRB5CCNAME`
- `ssh`, `klist` в PATH
- Python 3 (только stdlib); для режима модуля — NetExec

## Установка

```bash
cp ssh_krb_check.py ~/.nxc/modules/
```

## Окружение Kerberos

```bash
export KRB5CCNAME=/path/to/krb5cc          # кэш с билетом
export KRB5_CONFIG=/path/to/krb5.conf      # конфиг с адресом KDC

# krb5.conf можно сгенерировать самим nxc:
nxc smb <ip> -u <user> -p <pass> --generate-krb5-file krb5.conf
```

Без `KRB5_CONFIG` проверка проходит только для целей, сервисный билет на которых уже есть в кэше; новые цели уходят в таймаут (поиск KDC через DNS).

## Модуль nxc: варианты запуска

Только билет, вообще без кредов (пользователь — из билета):

```bash
nxc ssh 10.10.10.1-50 -M ssh_krb_check
```

Свой порт:

```bash
nxc ssh 10.10.10.5 --port 2222 -M ssh_krb_check
```

Флаги выполнения — комбинируются с `-M` (в штатном ssh-протоколе nxc `-M` их игнорирует), работают и с паролем/ключом, и без кредов:

```bash
nxc ssh 10.10.10.5 -M ssh_krb_check -x 'id'                            # команда
nxc ssh 10.10.10.5 -M ssh_krb_check --put-file file.txt /tmp/file.txt  # загрузить файл
nxc ssh 10.10.10.5 -M ssh_krb_check --get-file /etc/hosts hosts.txt    # скачать файл
nxc ssh 10.10.10.5 -M ssh_krb_check -x 'id' --put-file a.txt /tmp/a.txt --get-file /tmp/b.txt b.txt
```

Без кредов команда и передача файлов идут по билету (системные `ssh`/`scp`),c паролем/ключом — штатные механизмы nxc (paramiko/SFTP).

Опции модуля (`-o KEY=VALUE`, можно несколько):

| Опция | По умолчанию | Описание |
|---|---|---|
| `TIMEOUT` | `8` | таймаут соединения, сек |
| `DELEGATE` | `FALSE` | делегировать билет хосту (`ssh -K`) |
| `VERBOSE` | `FALSE` | полный вывод ssh при ошибке |

```bash
nxc ssh hosts.txt -M ssh_krb_check -o TIMEOUT=5 DELEGATE=true
```

Пользователь: `-u` из nxc, иначе принципал билета. Порт: `--port` из nxc.

Вывод:

```
SSH            10.111.222.11   22   [+] testuser: (kerberos ticket) Linux - Shell access!
SSH_KRB_CHECK  10.111.222.13   22   [-] ssh_krb_check: аутентификация по Kerberos НЕ прошла (Permission denied ...)
```

## Автономный режим: варианты запуска

IP, имена, полные диапазоны (`10.10.10.1-10.10.10.50`) и сокращённые (`10.10.10.1-50`):

```bash
python3 ssh_krb_check.py 10.10.10.1 10.10.10.5-10.10.10.20 srv01.corp.local
python3 ssh_krb_check.py 10.10.10.1-50
```

Файл хостов, параллельность, выгрузка OK-списка:

```bash
python3 ssh_krb_check.py -f hosts.txt -P 20 -t 5 -o ok_hosts.txt
```

Свой пользователь и порт, команда после входа, детали ошибок:

```bash
python3 ssh_krb_check.py -u admin -p 2222 -c 'id' -v srv01.corp.local
```

Делегирование билета (эквивалент `ssh -K`);

```bash
python3 ssh_krb_check.py -K 10.10.10.5
python3 ssh_krb_check.py -l 10.10.10.1-50
```

Флаги:

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-u` | принципал билета, иначе текущий пользователь | пользователь SSH |
| `-p` | `22` | порт SSH |
| `-t` | `8` | таймаут, сек |
| `-c` | `true` | команда после входа |
| `-K` | выкл. | делегировать билет (`ssh -K`) |
| `-P` | `10` | параллельных проверок |
| `-f` | — | файл хостов (`#` — комментарий) |
| `-o` | — | файл для списка OK-хостов |
| `-l` | — | только вывести список хостов после раскрытия диапазонов |
| `-v` | — | полный вывод ssh при ошибке |

Статусы: `OK` — вход по билету прошёл; `FAIL` — аутентификация не прошла; `UNREACH` — хост недоступен. Коды выхода: `0` — все OK, `1` — есть FAIL/UNREACH, `2` — ошибка аргументов.

## Ограничения

- для IP-целей сервисный принципал `host/<fqdn>` разрешается через обратный DNS krb5; предпочтительны FQDN
- каждая проверка — попытка входа в логе sshd цели
- `--sudo-check` без кредов не копирует `/etc/shadow` (штатный сценарий требует пароль) — только проверка NOPASSWD
