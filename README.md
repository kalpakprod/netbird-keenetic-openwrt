# NetBird на Zig для роутеров Keenetic (Entware) и OpenWrt

[![ci](https://github.com/kalpakprod/netbird-keenetic-openwrt/actions/workflows/ci.yml/badge.svg)](https://github.com/kalpakprod/netbird-keenetic-openwrt/actions/workflows/ci.yml)

Проект переписывает клиент [NetBird](https://github.com/netbirdio/netbird) с Go на Zig: маленький статический бинарь без C и низкое потребление памяти, чтобы клиент работал на слабых роутерах, включая ядро Linux 4.9. Сборка: `zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSmall` (Zig 0.17). Клиент на Zig ещё не работает, ход работ в [PLAN.md](PLAN.md). Перенесённый код NetBird идёт под BSD-3-Clause, см. [LICENSES/](LICENSES/).

NetBird client rewritten in Zig for Keenetic and OpenWrt routers: small static binary, low RAM, Linux 4.9+. Work in progress.

## Установщик официального клиента

Один скрипт ставит NetBird-клиент на роутер так, чтобы после перезагрузки туннель поднимался сам и роутер оставался доступен из сети NetBird. Платформа определяется автоматически. На Keenetic бинарь по умолчанию берётся из официальных GitHub-релизов NetBird, где архитектура известна, иначе — из пакета Entware; на OpenWrt всегда из официального фида. Подробнее в «Источники бинаря».

**Зачем.** Постоянный удалённый доступ к роутеру и домашней сети без проброса портов и белого IP. NetBird сам пробивает NAT, роутер становится обычным пиром в вашей mesh-сети.

## Требования

Нет, не на любом роутере: нужна Linux-система с пакетным менеджером, `/dev/net/tun` и автозапуском. Поддерживаются ровно две платформы.

**Keenetic:** любая модель, куда ставится Entware (USB-накопитель или встроенное хранилище) и компонент **WireGuard VPN** (даёт `/dev/net/tun`); KeeneticOS 3.3+, лучше 4.2+. Все архитектуры: `aarch64`/`x86_64`/`armv6/v7` ставятся из upstream, `mips` — из пакета Entware. Нужно примерно 35 MB свободно в `/opt` и желательно от 128 MB RAM (на меньших следи за OOM, watchdog включён).

**OpenWrt:** проверены 24.10 (opkg) и 25.12 (apk); нужен `kmod-tun` (зависимости wireguard тянет сам пакет) и место под пакет (~10 MB плюс kmods).

**Не поддерживается:** стоковые прошивки без Entware/OpenWrt, KeeneticOS 2.x (нет WireGuard и `/dev/net/tun`), роутеры без накопителя под Entware.

## Быстрый старт

### 0. Setup Key и доступ

1. В панели NetBird открой Setup Keys -> Add key и создай ключ с настройками:

| Параметр | Ставь | Почему |
|---|---|---|
| Type | reusable | переустановка и повторная регистрация не требуют нового ключа |
| Ephemeral | выкл | ephemeral-пиры удаляются после простоя, роутер должен жить постоянно |
| Expires | без срока или длинный | иначе в следующий раз ставить будет нечем |
| Auto groups | группа роутера (например `routers`) | пир сразу попадает в нужную группу для политик |

2. Заранее проверь Access Control: между группой роутера и группой твоих устройств должна быть разрешающая политика, иначе peer-to-peer трафика не будет. Симптом отсутствия: `netbird status` показывает Connected, но Peers 0/0 с обеих сторон. Без политики дальше шага проверки не уйти.

### Keenetic

Предварительно в веб-интерфейсе:

1. [Entware на USB или встроенное хранилище](https://help.keenetic.com/hc/ru/articles/360021214160). С KeeneticOS 4.2 одной командой в CLI (`192.168.1.1/a`): `opkg disk storage:/ https://bin.entware.net/<arch>/installer/<arch>-installer.tar.gz` (архитектуру см. в таблице ниже).
2. Компонент **WireGuard VPN** (Управление -> Параметры системы -> Компоненты). Он даёт `/dev/net/tun`. Без него скрипт остановится с понятной ошибкой.

Затем по SSH в Entware (порт **222**, пользователь `root`, пароль по умолчанию `keenetic`):

```sh
opkg update && opkg install curl ca-bundle
curl -fsSL https://raw.githubusercontent.com/kalpakprod/netbird-keenetic-openwrt/main/install.sh -o /tmp/nb.sh
sh /tmp/nb.sh <SETUP_KEY>
```

### OpenWrt

По SSH на роутер (порт 22, `root`):

```sh
wget -qO /tmp/nb.sh https://raw.githubusercontent.com/kalpakprod/netbird-keenetic-openwrt/main/install.sh
sh /tmp/nb.sh <SETUP_KEY>
```

Работает на 24.10 (opkg) и 25.12 (apk). Оба проверяются в CI на каждый коммит.

### Self-hosted NetBird

```sh
sh /tmp/nb.sh <SETUP_KEY> https://netbird.example.com
```

## Источники бинаря (Keenetic)

`NB_SOURCE=auto` (по умолчанию) выбирает источник по архитектуре:

| `uname -m` | Авто-выбор | Почему |
|---|---|---|
| `aarch64` | upstream `arm64` | проверено на железе (Keenetic, ядро 4.9-ndm-5) |
| `x86_64` | upstream `amd64` | проверено в Docker |
| `armv6l`, `armv7l` | upstream `armv6` | бинарь armv6 работает на armv7; установка сверяет версию до записи на флеш |
| `mips` и остальные | пакет Entware | для mips upstream публикует сборки, но без проверки на железе нельзя выбрать soft-float/hard-float; пакет Entware для mips проверен |

`NB_SOURCE=upstream` или `=entware` задаёт источник принудительно. `NB_VERSION` по умолчанию зафиксирована на проверенной (сейчас 0.79.0, она же latest на сентябрь 2026); `NB_VERSION=latest` резолвится через GitHub API с откатом на проверенную при неудаче. `NB_ARCH` принудительно задаёт архитектуру upstream-бинаря (экспертный режим, тоже под защитой проверки версии).

Перед записью на флеш скрипт всегда проверяет SHA256 архива и запуск бинаря (`version` должен совпасть): неподходящая архитектура падает до любых изменений. На UBIFS запись идёт кусками по 1 MiB с контролем свободного места, резерв 4 MiB.

### Мало места на /opt

Upstream-бинарь — один статический файл ~40 МБ (демон + CLI + WireGuard + ICE + DNS + файрвол; апстрим уже собирает его без символов, strip ничего не даёт). `NB_COMPRESS=1` упаковывает его через UPX до ~13-15 МБ (x64: 14.9, arm64: 13.0): сжатие идёт после проверки SHA256, упакованный файл проверяется запуском до записи на флеш (замер на железе, 0.79.0 arm64: 40.2 -> 13.0 МБ; пакет `upx` ~0.8 МБ ставится сам, после установки его можно удалить — при следующей переустановке скрипт поставит заново). При переустановке на забитом томе старый бинарь удаляется до записи нового (демон к этому моменту уже остановлен, identity в `/opt/var/lib/netbird` не трогается), так что пик занятого места — один файл.

## Проверка

```sh
netbird status          # Management: Connected, Signal: Connected
reboot
```

Через 2 минуты с любого другого пира NetBird:

| Платформа | Команда |
|---|---|
| Keenetic, шелл Entware | `ssh -p 222 root@<NetBird-IP роутера>` |
| Keenetic, CLI KeeneticOS | `ssh admin@<NetBird-IP роутера>` (если SSH-сервер включён в компонентах) |
| Keenetic, веб-интерфейс | `http://<NetBird-IP роутера>` |
| OpenWrt | `ssh root@<NetBird-IP роутера>`, LuCI по `http://<NetBird-IP>` |

NetBird-IP роутера скрипт печатает в конце; всегда виден в панели NetBird. Если `netbird status` показывает Peers 0/0 — вернись к шагу 0 и создай access policy между группами.

## Архитектуры Keenetic

Пакет `netbird` есть во всех репозиториях Entware, которые использует Keenetic (проверено по `bin.entware.net/<arch>/Packages`, версия 0.66.4 на сентябрь 2026). Upstream-релизы NetBird тоже содержат mips-сборки (mips/mipsle, soft- и hard-float), но скрипт не выбирает их автоматически: без проверки на железе нельзя отличить soft-float от hard-float. Для mips используется проверенный пакет Entware; энтузиасты могут попробовать `NB_SOURCE=upstream NB_ARCH=mipsle_softfloat` (или `mipsle_hardfloat`) — неподходящий бинарь будет отвергнут проверкой версии до записи на флеш.

| SoC | Примеры моделей | `uname -m` | Репозиторий Entware |
|---|---|---|---|
| MediaTek MT7621, MT7628 | Giga (KN-1010/1011), Ultra (KN-1810), Viva, Hero 4G, Runner 4G, Speedster, Air, Extra, Omni, Start, Lite | `mips` (little-endian, это mipsel) | `mipselsf-k3.4` |
| MediaTek MT7622 | Peak (KN-2710), Titan (KN-1811), Hopper (KN-3810) | `aarch64` | `aarch64-k3.10` |
| MediaTek MT7981, MT7986, MT7988 | Sprinter, Skipper, Hero 4G+, Giga Pro и другие Wi-Fi 6/7 модели | `aarch64` | `aarch64-k3.10` |

Проверить свою: в шелле Entware `uname -m; cat /proc/cpuinfo | head -5`. Список моделей ориентировочный, точный SoC своей модели смотри на [keenetic.com/ru/support](https://help.keenetic.com/) или в `/proc/cpuinfo`. Скрипт печатает архитектуру первой строкой и сам проверяет, что пакет для неё существует.

## Версии KeeneticOS

| KeeneticOS | Что важно |
|---|---|
| 4.2 и новее | Entware ставится одной командой из CLI; компонент WireGuard есть. Основная целевая версия. |
| 4.0, 4.1 | Entware ставится через веб-интерфейс (папка `install` на накопителе); WireGuard есть с 3.3. |
| 3.x | WireGuard появился в 3.3. Хуки `/opt/etc/ndm/netfilter.d` работают, но сборка Entware может быть старой: сделай `opkg update && opkg upgrade` перед установкой. Не проверялось. |
| 2.x | Не поддерживается: нет компонента WireGuard, нет `/dev/net/tun`. |

Хуки ndm (`/opt/etc/ndm/netfilter.d/*.sh`) поддерживаются KeeneticOS начиная с 2.x и не менялись до 4.x, это документированный механизм Keenetic для Entware-скриптов.

## Что именно делает скрипт

### Keenetic (ветка `install_keenetic`)

| Что | Где | Зачем |
|---|---|---|
| `opkg install netbird iptables cron` (`NB_SOURCE=entware`) | Entware | официальный пакет; `iptables` для правил, `cron` для watchdog |
| Флаги демона (только Entware) | `/opt/etc/netbird/env` | читается штатным `S99netbird` из пакета; лог в `/opt/var/log/netbird.log` |
| Upstream-бинарь (`NB_SOURCE=upstream`) | `/opt/lib/netbird/netbird` + враппер `/opt/bin/netbird` + свой `S99netbird` | tarball с GitHub, SHA256, стейджинг; состояние в `/opt/var/lib/netbird`, лог в `/opt/var/log/netbird.log` |
| Автозапуск | `/opt/etc/init.d/S99netbird` | стартует при загрузке роутера; identity переживает reboot на накопителе |
| Хук фаервола | `/opt/etc/ndm/netfilter.d/netbird.sh` | KeeneticOS вызывает его при каждой пересборке netfilter (загрузка, смена WAN, любое изменение в веб-интерфейсе). Разрешает INPUT на `wt0` (icmp + порты из `NB_PORTS`, по умолчанию 22 222 80 443), FORWARD wt0<->br0, MASQUERADE для 100.64.0.0/10, ставит `rp_filter=0`. Без него демон живёт, но зайти на роутер через туннель нельзя |
| Watchdog | `/opt/etc/netbird/watchdog.sh` + `/opt/etc/crontab` | каждые 2 минуты перезапускает демон, если процесс умер (OOM на роутере с 128-256 MB бывает) |
| `netbird up --disable-dns` | | NetBird не трогает DNS роутера, домашняя сеть не теряет резолв |

### OpenWrt (ветка `install_openwrt`)

| Что | Где | Зачем |
|---|---|---|
| `apk add netbird` или `opkg install netbird` | официальный фид OpenWrt | тянет `kmod-wireguard` зависимостью |
| Интерфейс | `uci network.netbird` proto `unmanaged`, device `wt0` | чтобы фаервол мог привязать зону к устройству NetBird |
| Зона фаервола | `uci firewall.netbird` + forwarding netbird<->lan | input/forward ACCEPT для трафика из mesh, masq для доступа в LAN. Всё в `/etc/config`, переживает reboot и sysupgrade с сохранением настроек |
| Автозапуск | `/etc/init.d/netbird enable` | procd-сервис из пакета |

Соответствует официальной инструкции [docs.netbird.io/get-started/install/openwrt](https://docs.netbird.io/get-started/install/openwrt).

### Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `NB_PLATFORM` | автоопределение | `keenetic` или `openwrt` принудительно |
| `NB_NO_UP` | | `1`: поставить всё, но не выполнять `netbird up` (для CI) |
| `NB_SOURCE` | `auto` | источник бинаря на Keenetic: `auto`, `upstream`, `entware` |
| `NB_VERSION` | проверенная (0.79.0) | версия upstream-релиза; `latest` резолвится через GitHub API |
| `NB_ARCH` | по `uname -m` | принудительная архитектура upstream-бинаря (экспертный режим) |
| `NB_SETUP_KEY_FILE` | | файл с Setup Key вместо первого аргумента |
| `NB_MANAGEMENT_URL` | `https://api.netbird.io` | то же, что второй аргумент |
| `NB_LOG_LEVEL` | `warning` | уровень лога демона на Keenetic; для отладки `info` или `debug` |
| `NB_COMPRESS` | | `1`: сжать upstream-бинарь через UPX (~40 МБ -> ~13-15 МБ) для тесного `/opt`. Цена: сжатый бинарь целиком живёт в RAM (~40 МБ), упаковка на роутере требует ~120 МБ свободной RAM; скрипт проверяет это заранее. На UBIFS (встроенная флешь) обычно не нужен: флешь сжимает сама, несжатый бинарь занимает ~17 МБ |
| `NB_GOMEMLIMIT` | `auto` | лимит памяти демона: `auto` ставит `GOGC=50 GOMEMLIMIT=32MiB` при RAM < 512 МБ, `off` отключает, можно задать своё значение (`48MiB`) |
| `NB_HOSTNAME` | hostname системы | имя пира в панели NetBird (A-Z a-z 0-9 . _ -); задавай осмысленное, иначе получишь второй «Keenetic» |
| `NB_SKIP_PREFLIGHT` | | `1`: не останавливаться, если management недоступен (экспертный режим) |
| `NB_LAN` | `br0` | LAN-интерфейс Keenetic (для гостевого сегмента другой) |
| `NB_PORTS` | `22 222 80 443` | порты роутера, открываемые из сети NetBird (Keenetic) |
| `NB_UP_FLAGS` | | дополнительные флаги к `netbird up`, например `--disable-firewall` |

Пример: `NB_PORTS="222" sh /tmp/nb.sh <KEY>` откроет из mesh только SSH в Entware.

## Почему ветки разные и нельзя перенести OpenWrt-вариант на Keenetic

OpenWrt: procd, uci, netfilter под управлением fw4. NetBird там ставится штатно, зона фаервола описывается декларативно и сама переживает перезагрузку.

KeeneticOS: закрытая система, нет uci и procd. Entware живёт в `/opt` и стартует через `/opt/etc/init.d/S*`. Фаервол собирает демон `ndm`, при каждой пересборке он затирает чужие правила, поэтому Keenetic предоставляет хуки `/opt/etc/ndm/netfilter.d/` именно для этого случая. Один скрипт, две ветки, каждая на штатных механизмах своей системы.

## Как это тестируется

`tests/run.sh` прогоняет полный цикл install -> assert -> uninstall в Docker:

| Цель | Образ | Что проверяется |
|---|---|---|
| `openwrt-24` | `openwrt/rootfs:x86-64-24.10.8` | пакет через opkg, `/etc/rc.d/S99netbird`, uci-интерфейс и зона, идемпотентность повторного запуска, полное удаление |
| `openwrt-25` | `openwrt/rootfs:x86-64-25.12.4` | то же через apk |
| `entware` | Debian + официальный Entware x64 в `/opt` | пакет из Entware, `S99netbird`, env, хук: синтаксис, реальные правила iptables, идемпотентность при повторных вызовах (нет дубликатов), watchdog в cron, stop/start демона как эмуляция перезагрузки |
| `upstream` | тот же образ | upstream tarball amd64: SHA256, версия, враппер, init, хук, watchdog, stop/start, полное удаление |
| `unit` | без Docker | `test-register-peer.sh` (4 кейса регистрации на моках) и `test-source-select.sh` (маппинг архитектур) |

Локально: `sh tests/run.sh all` (нужен Docker; для `entware`/`upstream` на хосте нужны модули `ip_tables iptable_filter iptable_nat`) и `sh tests/test-register-peer.sh && sh tests/test-source-select.sh`. В CI (`.github/workflows/ci.yml`) плюс `shellcheck -s sh`.

Что Docker не покрывает и проверяется только на железе: сам вызов хука демоном ndm, `/dev/net/tun` от компонента WireGuard, реальный `netbird up`. Если после `reboot` `netbird status` показывает ошибку, пришли `tail -50 /opt/var/log/netbird.log` (Keenetic) или `logread -e netbird` (OpenWrt) в issue.

## Удаление

```sh
curl -fsSL https://raw.githubusercontent.com/kalpakprod/netbird-keenetic-openwrt/main/uninstall.sh | sh
```

Снимает бинарь любого источника (пакет Entware или upstream-файлы), хук, watchdog, uci-объекты и состояние. На Keenetic правила iptables для `wt0` исчезают при следующей пересборке фаервола или после `reboot`.

## Если что-то пошло не так

| Симптом | Что это значит | Действие |
|---|---|---|
| `Error: daemon up failed: ... DeadlineExceeded` при `netbird up` | CLI не дождался ответа демона за свой таймаут; регистрация при этом может продолжаться. Скрипт не доверяет коду возврата: ждёт до 120 с, проверяет адрес `wt0` и `Management: Connected`, при рассинхроне завершается ошибкой | подожди минуту, `netbird status`; если Management не Connected дольше 2 минут — смотри следующий пункт |
| `netbird status` показывает `Management: Disconnected` дольше 2 минут | нет доступа к `api.netbird.io:443` или неверный Setup Key | `tail -50 /opt/var/log/netbird.log` (оба источника на Keenetic; на OpenWrt `logread -e netbird`); проверь ключ, повтори `netbird up --setup-key <KEY> --disable-dns` |
| `netbird status` показывает Peers 0/0 при Connected с обеих сторон | нет access policy между группами пиров: management не сводит пиры | в панели NetBird (Access Control) создай политику, покрывающую группы обоих пиров |
| Пир в панели есть, но ssh на NetBird-IP не отвечает | правила для `wt0` не применились | `table=filter /opt/etc/ndm/netfilter.d/netbird.sh; iptables -S INPUT \| grep wt0`; на KeeneticOS проверь, что LAN-мост действительно `br0` (`ip link`), иначе `NB_LAN=<имя>` |
| Процесса `netbird` нет в `pidof` | демон умер; на роутерах со 128–256 MB вероятная причина — OOM | `cat /opt/var/log/netbird_watchdog.log`; watchdog поднимает его каждые 2 минуты, это штатно |

## Известные ограничения

- `--disable-dns` включён всегда: NetBird DNS (резолв имён пиров `*.netbird.cloud`) на роутере не работает. Имена пиров резолвятся на других устройствах, роутеру они не нужны.
- Политики доступа NetBird применяются на management-стороне и на пирах; сам роутер фильтрует входящий из mesh трафик только по `NB_PORTS`.
- Keenetic с 128 MB RAM: бинарь netbird занимает ~35-40 MB на диске и 30-60 MB в памяти. На таких моделях watchdog нужен, OOM реален.
- Лог демона (`/opt/var/log/netbird.log`) пишется с уровнем `warning` и обрезается watchdog'ом свыше 1 МБ до хвоста 512 КБ, чтобы INFO-шум (~1.5 МБ/час) не съедал флешь. Для детальной диагностики ставь с `NB_LOG_LEVEL=info` (или `debug`).

## Источники

- Upstream-релизы: [github.com/netbirdio/netbird/releases](https://github.com/netbirdio/netbird/releases) (клиентские `netbird_<версия>_linux_<арх>.tar.gz` и `netbird_<версия>_checksums.txt`).
- Пакет Entware: `https://bin.entware.net/<arch>/Packages`, Maintainer: Entware team. Содержимое ipk проверено распаковкой: `/opt/sbin/netbird`, `/opt/etc/init.d/S99netbird`, `/opt/etc/netbird/env`.
- Пакет OpenWrt: [openwrt/packages net/netbird](https://github.com/openwrt/packages/tree/master/net/netbird).
- Хук netfilter для Keenetic: [forum.keenetic.ru/topic/21273-netbird](https://forum.keenetic.ru/topic/21273-netbird/).
- Entware на Keenetic и архитектуры: [help.keenetic.com](https://help.keenetic.com/hc/ru/articles/360021214160), [keeneticported.dev/wiki/helpful/entware](https://keeneticported.dev/wiki/helpful/entware).
- NetBird на OpenWrt: [docs.netbird.io/get-started/install/openwrt](https://docs.netbird.io/get-started/install/openwrt).

## Лицензия

MIT.

## Роутеры с 256 МБ RAM и соседями (AWG Manager, sing-box)

Проверено на Xiaomi AX3000T с портированной KeeneticOS 5.1 (256 МБ). Каждый Go-сервис занимает десятки мегабайт, UPX-сжатые бинари держат в RAM весь распакованный образ. Если свободной памяти меньше ~50 МБ, роутер уходит в своп и перестаёт отвечать на DNS: у клиентов пропадает интернет. Поэтому здесь:

- без `NB_COMPRESS`, если `/opt` на UBIFS (встроенная флешь сама сжимает, бинарь в памяти подгружается страницами и вытесняется);
- лимит памяти демона включается сам (`NB_GOMEMLIMIT=auto`);
- не держи рядом UPX-сжатый sing-box: это ещё ~60 МБ RAM;
- не останавливай NetBird, если подключён к роутеру через NetBird: зайди по LAN или другим путём.

Watchdog каждые 2 минуты возвращает правила доступа к роутеру наверх цепочки INPUT: NetBird при переподключении вставляет свой DROP для `wt0` выше них. Lock прерванной установки (OOM, обрыв SSH) убирается автоматически.
