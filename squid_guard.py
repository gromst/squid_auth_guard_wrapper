#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-
"""
squid_guard.py - единый helper для Squid 6: пропуск по IP, запоминание IP,
защита от перебора паролей для auth_param basic.

Режим задаётся первым аргументом:

  check     external_acl_type, формат "%>a"
            OK  - с этого IP была успешная авторизация за последние --ttl секунд
            ERR - нет (или memcached недоступен: без авторизации не пускаем)

  remember  external_acl_type, формат "%>a %ul"
            запоминает IP -> логин на --ttl секунд, всегда OK

  auth      auth_param basic program - обёртка над basic_ncsa_auth.
            Нужен  auth_param basic key_extras "%>a" - тогда строка от squid
            имеет вид "логин пароль IP".
            * --user-fails неудач по логину за --window сек -> пароль этого
              логина не проверяется --user-lock сек (сразу ERR);
            * --ip-fails неудачных проверок пароля с IP за --window сек ->
              с этого IP пароли не проверяются --ip-lock сек (сразу ERR).
            Сам пароль проверяет basic_ncsa_auth (дочерний процесс).

Примеры:
  squid_guard.py check
  squid_guard.py remember --ttl 600
  squid_guard.py auth /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
"""

import argparse
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
import time

from pymemcache.client.base import Client


# Ключ "SQUID:<ip>" совпадает со старыми ext_acl_ip2usr/ext_acl_ip2chk,
# поэтому новый helper можно ставить поверх старых без потери состояния.
# Служебные ключи содержат буквы вне [0-9a-f:.], с IP они не пересекаются.
K_FAIL_USER = "failuser:"
K_LOCK_USER = "lockuser:"
K_FAIL_IP = "failip:"
K_LOCK_IP = "lockip:"

SAFE_KEY_PART = re.compile(r"[!-~]{1,200}\Z")   # печатный ASCII без пробелов

MODE = "?"
DEBUG = False


def log(msg):
    # stderr helper'а squid пишет в cache.log
    sys.stderr.write("squid_guard(%s)[%d]: %s\n" % (MODE, os.getpid(), msg))
    sys.stderr.flush()


def dbg(msg):
    if DEBUG:
        log(msg)


def key_part(s):
    """Кусок ключа memcached: как есть, если безопасен, иначе sha1."""
    if SAFE_KEY_PART.match(s):
        return s
    return "sha1:" + hashlib.sha1(s.encode("utf-8", "surrogateescape")).hexdigest()


class MC(object):
    """Обёртка над memcached: любая ошибка -> McError, в лог не чаще раза в минуту."""

    class McError(Exception):
        pass

    def __init__(self, server, prefix):
        host, _, port = server.rpartition(":")
        self.prefix = prefix
        self.client = Client(
            (host.strip("[]") or "127.0.0.1", int(port)),
            connect_timeout=0.2,
            timeout=0.2,
            no_delay=True,
        )
        self._last_err_log = 0.0

    def _fail(self, op, exc):
        now = time.time()
        if now - self._last_err_log > 60:
            log("memcached %s failed: %r" % (op, exc))
            self._last_err_log = now
        raise MC.McError(exc)

    def k(self, name):
        return self.prefix + name

    def get(self, name):
        try:
            return self.client.get(self.k(name))
        except Exception as e:
            self._fail("get", e)

    def get_many(self, names):
        try:
            got = self.client.get_many([self.k(n) for n in names])
        except Exception as e:
            self._fail("get_many", e)
        plen = len(self.prefix)
        return set(k[plen:] if isinstance(k, str) else k.decode()[plen:] for k in got)

    def set(self, name, value, ttl):
        try:
            self.client.set(self.k(name), value, expire=ttl, noreply=False)
        except Exception as e:
            self._fail("set", e)

    def delete(self, name):
        try:
            self.client.delete(self.k(name), noreply=True)
        except Exception as e:
            self._fail("delete", e)

    def bump(self, name, ttl):
        """Атомарный счётчик с окном ttl от первой неудачи. Возвращает новое значение."""
        key = self.k(name)
        try:
            n = self.client.incr(key, 1, noreply=False)
            if n is None:
                if self.client.add(key, b"1", expire=ttl, noreply=False):
                    return 1
                n = self.client.incr(key, 1, noreply=False)   # параллельный add
            return int(n or 1)
        except Exception as e:
            self._fail("incr", e)


# --------------------------------------------------------------------------
# check / remember
# --------------------------------------------------------------------------

def mode_check(mc, args, line):
    parts = line.split()
    if not parts or parts[0] == "-":
        return "ERR"
    try:
        found = mc.get(parts[0]) is not None
    except MC.McError:
        return "ERR"            # memcached недоступен: без авторизации не пускаем
    dbg("check %s -> %s" % (parts[0], found))
    return "OK" if found else "ERR"


def mode_remember(mc, args, line):
    parts = line.split()
    if len(parts) < 2 or parts[0] == "-" or parts[1] == "-":
        return "OK"
    try:
        mc.set(parts[0], parts[1], args.ttl)
        dbg("remember %s = %s for %ds" % (parts[0], parts[1], args.ttl))
    except MC.McError:
        pass                    # memcached недоступен: запрос пользователя не блокируем
    return "OK"


# --------------------------------------------------------------------------
# auth: обёртка над basic_ncsa_auth
# --------------------------------------------------------------------------

class Verifier(object):
    """Постоянный дочерний basic_ncsa_auth, перезапуск при падении."""

    def __init__(self, argv):
        self.argv = argv
        self.proc = None

    def _start(self):
        self.proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,            # stderr ncsa тоже уходит в cache.log
            bufsize=0,
            close_fds=True,
        )

    def _stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            p.stdin.close()
        except Exception:
            pass
        try:
            p.wait(timeout=2)
        except Exception:
            p.kill()

    def ask(self, user, password):
        """user/password - в том виде, как прислал squid (rfc1738-escaped)."""
        request = (user + " " + password + "\n").encode("latin-1", "surrogateescape")
        for attempt in (1, 2):
            try:
                if self.proc is None or self.proc.poll() is not None:
                    if self.proc is not None:
                        log("%s exited with %s, restarting" % (self.argv[0], self.proc.returncode))
                    self._start()
                self.proc.stdin.write(request)
                reply = self.proc.stdout.readline()
                if reply:
                    return reply.decode("latin-1").rstrip("\r\n")
            except (OSError, ValueError) as e:
                log("%s: %r" % (self.argv[0], e))
            self._stop()
        return None

    def close(self):
        self._stop()


def ip_bucket(ip, v6_prefix):
    """IPv4 - адрес как есть; IPv6 - сеть /v6_prefix (перебор по всей /64 считается одним IP)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return key_part(ip)
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        if v6_prefix < 128:
            return str(ipaddress.ip_network("%s/%d" % (a, v6_prefix), strict=False))
    return str(a)


class Auth(object):

    def __init__(self, mc, args):
        self.mc = mc
        self.a = args
        self.verifier = Verifier(args.command)
        self.warned_no_ip = False

    def handle(self, line):
        a = self.a
        # squid: "user pass [key_extras]" - user и pass rfc1738-escaped, без пробелов
        parts = line.split(" ")
        if len(parts) < 2 or not parts[0]:
            return 'ERR message="bad request"'
        user, password = parts[0], parts[1]
        ip = parts[2] if len(parts) > 2 and parts[2] not in ("", "-") else None
        if ip is None and not self.warned_no_ip:
            log('no client IP in request: add  auth_param basic key_extras "%>a"  '
                '(per-IP limit is off)')
            self.warned_no_ip = True

        u = key_part(user)
        net = ip_bucket(ip, a.ipv6_prefix) if ip else None

        # 1. Действующие блокировки
        mc_ok = True
        try:
            locks = self.mc.get_many([K_LOCK_USER + u] + ([K_LOCK_IP + net] if net else []))
        except MC.McError:
            mc_ok = False
            locks = set()
            if a.fail_closed:
                return 'ERR message="auth temporarily unavailable"'

        if net and (K_LOCK_IP + net) in locks:
            dbg("reject %s from %s: address locked" % (user, ip))
            return 'ERR message="too many failed logins from this address"'
        if (K_LOCK_USER + u) in locks:
            dbg("reject %s from %s: user locked" % (user, ip))
            return 'ERR message="too many failed logins for this user"'

        # 2. Проверка пароля
        reply = self.verifier.ask(user, password)
        if reply is None:
            return 'BH message="password checker unavailable"'
        verdict = reply.split(" ", 1)[0]
        dbg("%s from %s -> %s" % (user, ip, reply))

        if not mc_ok:
            return reply

        # 3. Учёт результата
        try:
            if verdict == "OK":
                self.mc.delete(K_FAIL_USER + u)
            elif verdict == "ERR":
                n = self.mc.bump(K_FAIL_USER + u, a.window)
                if n >= a.user_fails:
                    self.mc.set(K_LOCK_USER + u, b"1", a.user_lock)
                    self.mc.delete(K_FAIL_USER + u)
                    log("user %s locked for %ds after %d failures (last from %s)"
                        % (user, a.user_lock, n, ip or "?"))
                if net:
                    m = self.mc.bump(K_FAIL_IP + net, a.window)
                    if m >= a.ip_fails:
                        self.mc.set(K_LOCK_IP + net, b"1", a.ip_lock)
                        self.mc.delete(K_FAIL_IP + net)
                        log("address %s locked for %ds after %d failures" % (net, a.ip_lock, m))
        except MC.McError:
            pass
        return reply

    def close(self):
        self.verifier.close()


# --------------------------------------------------------------------------

def parse_args(argv):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--memcached", default="127.0.0.1:11211", metavar="HOST:PORT")
    common.add_argument("--prefix", default="SQUID:", help="префикс ключей (по умолчанию SQUID:)")
    common.add_argument("-d", "--debug", action="store_true", help="подробный лог в cache.log")

    p = argparse.ArgumentParser(description="Squid helper: IP bypass / remember / brute-force guard")
    sub = p.add_subparsers(dest="mode")
    sub.required = True

    for name in ("check", "remember"):
        sp = sub.add_parser(name, parents=[common])
        sp.add_argument("--ttl", type=int, default=600,
                        help="сколько секунд помнить IP после авторизованного запроса (remember)")

    sp = sub.add_parser("auth", parents=[common])
    sp.add_argument("--user-fails", type=int, default=3, help="неудач по логину до блокировки")
    sp.add_argument("--user-lock", type=int, default=600, help="блокировка логина, сек")
    sp.add_argument("--ip-fails", type=int, default=10, help="неудач с IP до блокировки")
    sp.add_argument("--ip-lock", type=int, default=600, help="блокировка IP, сек")
    sp.add_argument("--window", type=int, default=600, help="окно подсчёта неудач, сек")
    sp.add_argument("--ipv6-prefix", type=int, default=64, help="IPv6 считаем по сетям /N")
    sp.add_argument("--fail-closed", action="store_true",
                    help="если memcached недоступен - отказывать (по умолчанию пароль проверяется без лимитов)")
    sp.add_argument("command", nargs=argparse.REMAINDER,
                    help="команда проверки пароля, напр. /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd")

    args = p.parse_args(argv)
    if args.mode == "auth":
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        if not args.command:
            p.error("auth: укажите команду, напр. /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd")
    return args


def main():
    global MODE, DEBUG
    args = parse_args(sys.argv[1:])
    MODE, DEBUG = args.mode, args.debug
    mc = MC(args.memcached, args.prefix)

    if args.mode == "check":
        handler, on_error, close = (lambda l: mode_check(mc, args, l)), "ERR", None
    elif args.mode == "remember":
        handler, on_error, close = (lambda l: mode_remember(mc, args, l)), "OK", None
    else:
        auth = Auth(mc, args)
        handler, on_error, close = auth.handle, 'BH message="internal error"', auth.close

    # Читаем байты и декодируем latin-1: так не упадём на любом входе.
    stdin = sys.stdin.buffer
    out = sys.stdout
    try:
        for raw in stdin:
            line = raw.decode("latin-1").rstrip("\r\n")
            try:
                result = handler(line)
            except Exception as e:
                log("unexpected error: %r" % (e,))
                result = on_error
            out.write(result + "\n")
            out.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        if close:
            close()


if __name__ == "__main__":
    main()
