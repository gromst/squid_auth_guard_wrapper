# squid_auth_guard_wrapper

Brute-force protection for SQUID basic_ncsa_auth helper
<pre>
  Защищает авторизацию прокси-сервера SQUID на базе basic_ncsa_auth от перебора паролей.
  Обертка для basic_ncsa_auth.
  На вход подается 3 параметра "USERNAME PASSWORD IP\n"
  Четвертая по счету попытка авторизоваться для одного USERNAME отключает ее на 10 минут.
  Десятая по счету попытка авторизоваться с одного IP адреса также отключает ее на 10 минут.
  Использует `memcaced` для хранения временных данных.
</pre>
<pre>
  Лимиты настраиваются параметрами: --user-fails 3, --ip-fails 10, --user-lock/--ip-lock/--window по 600 секунд.
  squid_guard.py - единый helper для Squid 6: пропуск по IP, запоминание IP, защита от перебора паролей для auth_param basic.
</pre>
Режим задаётся первым аргументом:
<pre>
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
</pre>
Примеры:
<pre>
  squid_guard.py check
  squid_guard.py remember --ttl 600
  squid_guard.py auth /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
</pre>

# squid.conf
```
auth_param basic program /usr/local/lib/squid/squid_guard.py auth /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic key_extras "%>a"
auth_param basic children 10 startup=2 idle=1
auth_param basic realm Proxy

external_acl_type ip_known    ttl=60 negative_ttl=0 %>a     /usr/local/lib/squid/squid_guard.py check
external_acl_type ip_remember ttl=60 negative_ttl=0 %>a %ul /usr/local/lib/squid/squid_guard.py remember --ttl 600

acl known_ip    external ip_known
acl authed      proxy_auth REQUIRED
acl remember_ip external ip_remember

http_access allow known_ip
http_access allow authed remember_ip
http_access deny all
```
