# Инвентаризация: что компилируется в Linux arm64-клиент NetBird v0.79.0

Дата: 2026-10-03. Автор: GLM-5.3-Flash (Droid), карточка r1-glm.

## Метод

Точный набор пакетов и файлов получен командой (cwd `upstream/netbird`):

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go list -mod=vendor -deps \
  -f '{{if not .Standard}}{{.ImportPath}}	{{.Dir}}	{{join .GoFiles " "}}{{end}}' ./client
```

Это список всех нестандартных пакетов, которые реально компилируются в arm64-клиент
с точно теми файлами (`.GoFiles`), что входят в сборку linux/arm64. Число строк —
`wc -l` по каждому файлу из `.GoFiles` (без `_test.go`, их в `.GoFiles` и нет).
Модуль пакета определён по `vendor/modules.txt` с учётом секции замен `old => new`
(например `golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go`,
`github.com/pion/ice/v4 => github.com/netbirdio/ice/v4`).

Промежуточные данные и скрипты: `~/.cache/netbird-zig-context/`
(`pkgraw.txt`, `pkglines.txt`, `pkg_final.txt`, `modsum3.txt`, `inv2.sh`, `gen_tables.py`).

## Итоги

- 736 нестандартных пакетов, 3974 Go-файла, **1 031 228** строк (без тестов).
- Из них свой код NetBird (`github.com/netbirdio/netbird`): **171 пакет, 141 301 строка**.
- Внешние зависимости: 565 пакетов, 889 927 строк, 117 модулей — в Zig-порт целиком
  не переносятся: большинство заменяется кодом Zig std, самописными модулями
  (`src/proto`, gRPC/HTTP2, ICE, relay) или отбрасывается (AWS SDK, Prometheus,
  eBPF, gVisor netstack, Wails/мобильные ветки).
- В рантайм-путь клиента на роутере (userspace WG) попадает меньшинство: см.
  `council/r1-glm.md`, раздел «Рантайм-путь».

Роль модуля указана по назначению; для ключевых протокольных модулей роль
проверена по коду клиента (упоминания в `client/internal/connect.go`,
`client/internal/engine.go`, `client/internal/peer/conn.go`, `client/internal/relay/relay.go`),
для остальных — вывод по имени/содержимому модуля (помечено в тексте роли словом
«транзитивная», если пакет в порт напрямую не входит).

## Сводка по модулям (по убыванию размера)

| Модуль | строк | пакетов | роль |
|---|---:|---:|---|
| `github.com/netbirdio/netbird (own)` | 141301 | 171 | порт: сам клиент |
| `gvisor.dev/gvisor` | 95029 | 42 | gVisor netstack — только netstack-режим; на роутере (TUN) не нужен |
| `github.com/gopacket/gopacket` | 53564 | 2 | парсер пакетов (uspfilter/forwarder, netflow) |
| `github.com/aws/aws-sdk-go-v2/service/route53` | 53326 | 4 | Route53 (динамический DNS через libdns) |
| `google.golang.org/protobuf` | 48662 | 41 | protobuf-рантайм → заменяется src/proto |
| `github.com/google/gopacket` | 38991 | 2 | старый gopacket (транзитивный) |
| `google.golang.org/grpc` | 35669 | 63 | gRPC-фреймворк → в Zig заменяется своим HTTP/2+gRPC-клиентом |
| `=>` | 32936 | 28 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `golang.org/x/net` | 29098 | 16 | HTTP/2 (для gRPC), websocket, idna |
| `github.com/cilium/ebpf` | 29002 | 15 | eBPF загрузка (wgproxy/ebpf, rosenpass) |
| `github.com/quic-go/quic-go` | 27864 | 16 | QUIC — dialer relay (shared/relay/client/dialer/quic) |
| `github.com/vishvananda/netlink` | 27788 | 2 | marшруты/линки через netlink |
| `golang.org/x/crypto` | 23849 | 21 | ssh, chacha20poly1305, hkdf и пр. |
| `golang.org/x/sys` | 21613 | 2 | сырые syscall-обёртки |
| `github.com/miekg/dns` | 21253 | 1 | DNS-библиотека (dnsfwd, пробы) |
| `github.com/klauspost/compress` | 18400 | 7 | zstd и пр. (сжатие) |
| `golang.org/x/text` | 15548 | 4 | unicode/idna |
| `github.com/goccy/go-yaml` | 14282 | 9 | yaml (конфиги/дебаг) |
| `github.com/huin/goupnp` | 13954 | 7 | UPnP (NAT-traversal) |
| `github.com/pion/dtls/v3` | 12613 | 21 | DTLS (TURN over DTLS, rosenpass-канал) |
| `github.com/prometheus/client_golang` | 11433 | 6 | метрики Prometheus (localmetrics) |
| `gopkg.in/yaml.v3` | 11285 | 1 | yaml (транзитивное) |
| `github.com/aws/aws-sdk-go-v2/service/sts` | 11135 | 3 | AWS STS (транзитивное route53) |
| `github.com/prometheus/procfs` | 10969 | 3 | метрики из /proc |
| `github.com/pkg/sftp` | 10939 | 3 | SFTP (встроенный SSH) |
| `github.com/aws/smithy-go` | 10279 | 23 | AWS SDK рантайм |
| `github.com/pion/dtls/v2` | 10079 | 18 | транзитивный DTLS старой версии |
| `github.com/aws/aws-sdk-go-v2` | 10015 | 24 | AWS SDK — базовое |
| `github.com/caddyserver/certmagic` | 9775 | 1 | ACME-сертификаты (проверить путь в клиенте) |
| `go.yaml.in/yaml/v2` | 9639 | 1 | yaml (транзитивное) |
| `github.com/google/nftables` | 9024 | 7 | nftables-клиент (firewall) |
| `go.uber.org/zap` | 7680 | 9 | структурные логи (транзитивное) |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | 7240 | 3 | AWS SSOOIDC (транзитивное config) |
| `github.com/godbus/dbus/v5` | 6453 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/aws/aws-sdk-go-v2/config` | 6344 | 1 | AWS config (транзитивное route53) |
| `github.com/spf13/pflag` | 6251 | 1 | флаги CLI |
| `github.com/spf13/cobra` | 6080 | 1 | CLI |
| `github.com/pion/turn/v4` | 5960 | 6 | TURN-клиент |
| `github.com/prometheus/common` | 5823 | 2 | метрики |
| `github.com/aws/aws-sdk-go-v2/service/sso` | 5638 | 3 | AWS SSO (транзитивное config) |
| `github.com/pion/transport/v3` | 5622 | 8 | транспортные помощники pion |
| `github.com/shirou/gopsutil/v4` | 5594 | 6 | системная статистика (debug) |
| `github.com/pion/turn/v3` | 5350 | 6 | транзитивный TURN старой версии |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | 4204 | 3 | REST-шлюз поверх gRPC (daemon API) |
| `github.com/mholt/acmez/v2` | 3791 | 2 | ACME |
| `github.com/pion/stun/v3` | 3636 | 2 | STUN-протокол (пробы, binding) |
| `github.com/pion/stun/v2` | 3487 | 2 | транзитивный STUN старой версии |
| `github.com/coder/websocket` | 3297 | 3 | WebSocket-клиент — транспорт relay |
| `github.com/golang/protobuf` | 3177 | 1 | старый protobuf-рантайм (транзитивный) |
| `github.com/ti-mo/conntrack` | 2938 | 1 | conntrack (netflow) |
| `cunicu.li/go-rosenpass` | 2620 | 3 | Rosenpass (post-quantum PSK) |
| `github.com/mdlayher/netlink` | 2573 | 3 | netlink-библиотека |
| `github.com/jmespath/go-jmespath` | 2549 | 1 | JSON-запросы (AWS) |
| `github.com/aws/aws-sdk-go-v2/credentials` | 2509 | 7 | AWS credentials |
| `github.com/netbirdio/go-nat` | 2477 | 2 | NAT-PMP/UPnP проброс порта |
| `github.com/klauspost/cpuid/v2` | 2456 | 1 | CPU-детект (compress) |
| `github.com/sirupsen/logrus` | 2236 | 2 | логирование |
| `github.com/golang-jwt/jwt/v5` | 2169 | 1 | JWT (SSO) |
| `github.com/awnumar/memguard` | 1995 | 2 | защита ключей в памяти |
| `golang.zx2c4.com/wireguard/wgctrl` | 1854 | 5 | UAPI/netlink конфигурация WG-устройства |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | 1752 | 2 | AWS EC2 IMDS |
| `github.com/gliderlabs/ssh` | 1709 | 1 | SSH-сервер |
| `google.golang.org/genproto/googleapis/rpc` | 1675 | 2 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `rsc.io/qr` | 1572 | 3 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/things-go/go-socks5` | 1501 | 3 | SOCKS5 (netstack proxy) |
| `github.com/pion/transport/v2` | 1457 | 5 | транспортные помощники pion (стар.) |
| `golang.org/x/oauth2` | 1434 | 2 | OAuth2 для SSO |
| `github.com/DeRuina/timberjack` | 1414 | 1 | ротация логов |
| `github.com/prometheus/client_model` | 1399 | 1 | метрики |
| `github.com/google/uuid` | 1311 | 1 | UUID |
| `github.com/pion/mdns/v2` | 1288 | 1 | mDNS-кандидаты ICE |
| `github.com/lrh3321/ipset-go` | 1239 | 1 | ipset (firewall) |
| `github.com/fsnotify/fsnotify` | 1239 | 2 | файловые события |
| `golang.org/x/term` | 1237 | 1 | терминал (CLI) |
| `github.com/mdlayher/socket` | 1226 | 1 | дубликат роли netlink-сокет |
| `github.com/google/btree` | 1083 | 1 | btree (nftables/conntrack) |
| `github.com/koron/go-ssdp` | 1049 | 3 | SSDP-поиск UPnP |
| `github.com/zcalusic/sysinfo` | 972 | 2 | system info |
| `github.com/zeebo/blake3` | 971 | 10 | blake3 (где применяется — выяснить) |
| `github.com/coreos/go-iptables` | 803 | 1 | iptables-клиент (firewall) |
| `github.com/ti-mo/netfilter` | 766 | 1 | netfilter netlink |
| `github.com/tklauser/go-sysconf` | 760 | 1 | sysconf |
| `github.com/hashicorp/go-version` | 759 | 1 | сравнение версий (updater) |
| `go.uber.org/multierr` | 694 | 1 | транзитивное zap |
| `github.com/cenkalti/backoff/v4` | 660 | 1 | retry backoff |
| `github.com/libdns/route53` | 657 | 1 | Route53 provider |
| `github.com/aws/aws-sdk-go-v2/internal/ini` | 656 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/caddyserver/zerossl` | 598 | 1 | ZeroSSL ACME |
| `github.com/mitchellh/hashstructure/v2` | 526 | 1 | хеш структур (конфиги) |
| `github.com/pkg/errors` | 503 | 1 | ошибки (транзитивное) |
| `github.com/libp2p/go-netroute` | 499 | 1 | выбор исходящего интерфейса |
| `golang.org/x/time` | 496 | 1 | rate/timeout |
| `github.com/mdlayher/genetlink` | 454 | 1 | generic netlink |
| `github.com/vishvananda/netns` | 370 | 1 | netns (транзитивное) |
| `golang.org/x/sync` | 365 | 2 | errgroup/semaphore |
| `github.com/pion/logging` | 319 | 1 | лог-адаптер pion |
| `github.com/beorn7/perks` | 316 | 1 | метрики (транзитивное) |
| `github.com/cespare/xxhash/v2` | 316 | 1 | хеш (транзитивное) |
| `github.com/hashicorp/go-multierror` | 308 | 1 | мультиошибки |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | 308 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/tklauser/numcpus` | 286 | 1 | numcpus |
| `github.com/creack/pty` | 271 | 1 | PTY для SSH |
| `github.com/jackpal/go-nat-pmp` | 265 | 1 | NAT-PMP |
| `github.com/mdp/qrterminal/v3` | 264 | 1 | QR в терминале |
| `google.golang.org/genproto/googleapis/api` | 235 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/libdns/libdns` | 225 | 1 | абстракция DNS-провайдера |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | 204 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/anmitsu/go-shlex` | 193 | 1 | shlex (ssh-тесты) |
| `github.com/munnerz/goautoneg` | 189 | 1 | content-negotiation (транзитивное) |
| `github.com/hashicorp/errwrap` | 178 | 1 | транзитивное multierror |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | 175 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/awnumar/memcall` | 159 | 1 | memcall (транзитивное memguard) |
| `golang.org/x/exp` | 140 | 2 | экспериментальное (транзитивное) |
| `github.com/kr/fs` | 131 | 1 | sftp (транзитивное) |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | 128 | 1 | транзитивная зависимость; в Zig-порт напрямую не переносится |
| `github.com/pion/randutil` | 102 | 1 | рандом для pion |
| `github.com/skratchdot/open-golang` | 68 | 1 | открыть браузер (SSO) |
| `github.com/wlynxg/anet` | 37 | 1 | net iface (Android) |

## Свои пакеты NetBird (171 пакет, 141 301 строка) — прямые цели порта

| Пакет | строк | роль |
|---|---:|---|
| `shared/management/proto` | 14778 | сообщения management-gRPC (LoginRequest, SyncResponse, NetworkMap) |
| `client/proto` | 13006 | протокол демона (IPC): Login/Up/Status и пр. |
| `client/cmd` | 7242 | CLI: up, down, login, service, status |
| `client/internal/dns` | 6413 | DNS-менеджер: цепочка хендлеров, resolvconf, локальный резолвер |
| `client/internal` | 5567 | ядро: Engine, конфиг, мониторы, события |
| `client/server` | 5379 | демон: gRPC-сервер, запуск/останов инстанса |
| `client/internal/peer` | 5094 | соединение пира: ICE/relay, offer/answer, статусы |
| `client/firewall/nftables` | 4281 | firewall-бэкенд nftables |
| `client/firewall/uspfilter` | 3959 | userspace-файрвол (для userspace WG) |
| `client/internal/debug` | 3386 | сбор диагностики/логов |
| `client/ssh/server` | 3370 | встроенный SSH-сервер |
| `client/internal/profilemanager` | 2604 | профили, конфиг и state-файлы |
| `client/firewall/iptables` | 2543 | firewall-бэкенд iptables |
| `shared/relay/client` | 2488 | relay-клиент: dialer, health |
| `shared/management/networkmap` | 2482 | SyncResponse → NetworkMap |
| `shared/management/types` | 1989 | общие типы management |
| `util/capture` | 1757 | перехват пакетов (диагностика) |
| `client/internal/routemanager/systemops` | 1636 | системные маршруты (netlink) |
| `client/internal/auth` | 1591 | SSO/OIDC-логин (браузер/device flow) |
| `client/firewall/uspfilter/forwarder` | 1587 | форвардер userspace-трафика |
| `client/firewall/uspfilter/conntrack` | 1546 | conntrack userspace-фильтра |
| `client/iface/device` | 1298 | WG-устройства: TUN/kernel/netstack |
| `shared/management/client` | 1250 | management gRPC-клиент (Login/Sync) |
| `client/internal/routemanager` | 1210 | менеджер маршрутов |
| `client/status` | 1182 | статус-рекордер |
| `client/iface/udpmux` | 1169 | UDP-mux поверх одного сокета (ICE+WG) |
| `client/internal/metrics` | 1137 | клиентские метрики |
| `client/iface/configurer` | 1127 | конфигураторы WG (kernel/USP) |
| `flow/proto` | 961 | flow-протобуф (экспорт событий) |
| `util` | 938 | утилиты: лог, файлы, backoff |
| `client/internal/dnsfwd` | 930 | форвардер DNS-запросов |
| `shared/signal/client` | 881 | signal gRPC-клиент + шифрование сообщений |
| `shared/management/networkmap/nmdata` | 871 | данные network map |
| `client/iface/bind` | 867 | ICEBind — WG bind поверх ICE |
| `client/net` | 851 | сетевые хелперы (dialer и пр.) |
| `shared/signal/proto` | 837 | signal-протобуф |
| `client/ssh/client` | 801 | SSH-клиент |
| `client/anonymize` | 797 | анонимизация логов |
| `client/internal/dns/mgmt` | 779 | DNS-записи от management |
| `client/internal/ipcauth` | 763 | аутентификация IPC (SO_PEERCRED) |
| `client/mdm` | 743 | MDM-политики |
| `client/internal/acl` | 682 | ACL-менеджер |
| `client/internal/dns/local` | 677 | локальный DNS-хендлер |
| `client/system` | 657 | информация о системе |
| `client/internal/routemanager/dnsinterceptor` | 635 | перехват DNS-маршрутов |
| `client/ssh/proxy` | 623 | SSH-прокси |
| `client/internal/lazyconn/manager` | 619 | менеджер ленивых соединений |
| `client/iface/wgproxy/ebpf` | 595 | eBPF WG-прокси |
| `client/internal/routemanager/client` | 584 | клиентские маршруты сетей |
| `client/internal/rosenpass` | 582 | rosenpass-менеджер |
| `shared/auth/jwt` | 563 | JWT-помощники |
| `client/internal/updater` | 563 | автообновление клиента |
| `client/internal/peer/guard` | 563 | сторож состояний соединения |
| `client/internal/statemanager` | 539 | сохранение состояния (state.json) |
| `client/internal/routemanager/refcounter` | 537 | счётчики маршрутов |
| `client/internal/portforward` | 527 | проброс портов |
| `client/internal/netflow/conntrack` | 516 | netflow по conntrack |
| `client/firewall/manager` | 498 | интерфейс firewall-менеджера |
| `client/internal/lazyconn/activity` | 488 | активность ленивых соединений |
| `client/iface` | 480 | WG-интерфейс: create/up/down |
| `client/firewall/uspfilter/log` | 476 | лог userspace-фильтра |
| `client/internal/stdnet` | 475 | выбор сети (dialer netstack) |
| `client/internal/dns/resutil` | 469 | DNS-утилиты |
| `client/internal/auth/sessionwatch` | 464 | наблюдение SSO-сессии |
| `client/internal/updater/installer` | 446 | установщик обновлений |
| `client/iface/wgproxy/udp` | 430 | UDP-прокси WG (routed traffic) |
| `client/ssh` | 427 | общее для ssh |
| `client/internal/routemanager/dynamic` | 413 | динамические маршруты (HA) |
| `sharedsock` | 405 | shared socket (WG bind) |
| `shared/relay/messages` | 399 | relay-протобуф |
| `client/internal/routeselector` | 365 | селектор маршрутов |
| `client/internal/relay` | 358 | пробы STUN/TURN (StunTurnProbe) |
| `client/internal/netflow` | 356 | netflow-менеджер |
| `version` | 347 | версия |
| `flow/client` | 344 | flow-клиент |
| `dns` | 340 | типы DNS |
| `client/internal/getent` | 340 | getent (hostname) |
| `client/ssh/config` | 335 | ssh-конфиг |
| `shared/management/status` | 306 | статусы management |
| `client/netevents/sweep` | 306 | свип событий сети |
| `client/internal/ebpf/ebpf` | 304 | eBPF-объекты |
| `route` | 300 | типы маршрутов |
| `client/system/detect_cloud` | 298 | детект облака |
| `shared/relay/client/dialer/quic` | 288 | QUIC-dialer relay |
| `client/internal/peer/ice` | 281 | ICE-конфиг/сессия |
| `shared/relay/healthcheck` | 275 | health check relay |
| `client/internal/localmetrics` | 274 | локальные метрики |
| `client/firewall/firewalld` | 271 | firewalld (DBus) бэкенд |
| `client/firewall` | 266 | общий firewall (create) |
| `client/iface/netstack` | 262 | netstack TUN (gVisor) |
| `client/internal/daemonaddr` | 259 | адрес демона |
| `encryption` | 245 | шифрование mgmt/signal (Curve25519+ChaCha20Poly1305) |
| `client/iface/wgproxy/bind` | 239 | bind-прокси WG |
| `util/netrelay` | 238 | relay-утилиты |
| `shared/management/domain` | 235 | доменные списки |
| `shared/relay/client/dialer/ws` | 232 | WS-dialer relay |
| `client/internal/dns/config` | 201 | конфиг DNS |
| `shared/relay/client/dialer` | 198 | интерфейс dialer |
| `client/ssh/auth` | 196 | ssh-аутентификация |
| `client/internal/syncstore` | 193 | стор синхронизации (persist) |
| `client/internal/networkmonitor` | 190 | монитор сети |
| `client/grpc` | 189 | gRPC-dialer демона (unix socket) |
| `client/internal/routemanager/server` | 186 | серверные маршруты (routing peers) |
| `client/internal/expose` | 186 | expose-менеджер |
| `client/internal/routemanager/ipfwdstate` | 184 | состояние IP-forwarding |
| `shared/relay/auth/hmac/v2` | 183 | HMAC-аутентификация relay v2 |
| `client/internal/netflow/types` | 179 | типы netflow |
| `client/internal/lazyconn/inactivity` | 179 | неактивность ленивых соединений |
| `client/netevents` | 173 | события сети |
| `client/internal/lazyconn` | 171 | lazyconn-типы |
| `client/internal/netflow/store` | 164 | стор netflow |
| `client/internal/netflow/logger` | 162 | логгер netflow |
| `client/internal/metrics/remoteconfig` | 149 | remote config метрик |
| `client/internal/routemanager/fakeip` | 145 | fake IP (DNS-маршруты) |
| `client/iface/wgproxy` | 143 | wgproxy-интерфейс |
| `client/internal/peerstore` | 138 | стор пиров |
| `shared/relay/auth/hmac` | 136 | HMAC relay v1 |
| `formatter/hook` | 126 | хук форматтера логов |
| `client/internal/tunnelnotifier` | 124 | уведомления туннеля |
| `client/internal/routemanager/sysctl` | 122 | sysctl (IP forwarding) |
| `client/internal/ingressgw` | 111 | ingress gateway |
| `client/iface/wgaddr` | 111 | адрес WG-интерфейса |
| `client/netevents/netstate` | 110 | netstate |
| `client/ssh/detection` | 99 | детект ssh-окружения |
| `client/system/detect_platform` | 94 | детект платформы |
| `client/net/hooks` | 93 | хуки net |
| `client/iface/wgproxy/rawsocket` | 90 | raw-socket прокси |
| `shared/relay/tls` | 81 | TLS-конфиг relay |
| `client/jobexec` | 80 | выполнение job |
| `client/internal/sleep/handler` | 80 | sleep-хендлер |
| `shared/netiputil` | 78 | netip-утилиты |
| `client/internal/routemanager/static` | 71 | статические маршруты |
| `shared/management/grpc` | 67 | mgmt grpc-типы |
| `client/internal/acl/id` | 65 | ACL id |
| `client/internal/routemanager/notifier` | 63 | нотификаторы маршрутов |
| `formatter/txt` | 60 | текстовый форматтер |
| `client/internal/peer/worker` | 55 | worker пиров |
| `client/internal/peer/dispatcher` | 52 | dispatcher сообщений |
| `formatter/logcat` | 50 | logcat-форматтер |
| `client/internal/sleep` | 46 | sleep |
| `util/embeddedroots` | 42 | встроенные корневые сертификаты |
| `formatter/syslog` | 39 | syslog-форматтер |
| `formatter` | 38 | интерфейс форматтера |
| `shared/auth` | 37 | auth-типы |
| `client/firewall/uspfilter/common` | 37 | общее uspfilter |
| `monotime` | 35 | monotonic clock |
| `client/internal/routemanager/iface` | 32 | iface для routemanager |
| `client/iface/wgproxy/listener` | 32 | listener прокси |
| `client/internal/routemanager/common` | 30 | общее routemanager |
| `client/errors` | 30 | ошибки клиента |
| `client/internal/peer/conntype` | 29 | типы соединений |
| `client/configs` | 28 | конфиги |
| `shared/sshauth` | 28 | ssh-auth типы |
| `util/wsproxy` | 20 | ws-прокси утилита |
| `shared/management/client/common` | 20 | common mgmt client |
| `client/internal/routemanager/util` | 19 | утилиты routemanager |
| `upload-server/types` | 18 | типы upload-сервера |
| `client/internal/routemanager/vars` | 18 | переменные routemanager |
| `client/internal/ebpf` | 15 | ebpf-интерфейс |
| `client` | 13 | корневой пакет клиента |
| `shared/relay/client/dialer/net` | 12 | net-dialer relay |
| `shared/relay` | 11 | relay-типы |
| `shared/context` | 10 | context-хелперы |
| `client/internal/listener` | 9 | listener событий |
| `client/iface/bufsize` | 9 | размер буфера |
| `client/internal/templates` | 8 | шаблоны конфига |
| `client/internal/ebpf/manager` | 7 | ebpf-менеджер |
| `client/internal/peer/id` | 5 | id пира |
| `shared/management/operations` | 4 | operations API |
| `formatter/levels` | 3 | уровни форматтера |
| `client/internal/dns/types` | 3 | типы dns |

## Ограничения метода

- `.GoFiles` — файлы сборки linux/arm64; файлы под другими build-тегами (windows,
  ios, android, js) в подсчёт не попадают, что и требуется.
- Числа строк — `wc -l` по исходникам, включая комментарии и пустые строки.
- Роли своих пакетов проставлены по путям и прочитанному коду (engine.go,
  connect.go, peer/conn.go, relay.go, iface/*, login.go); роль отдельного мелкого
  пакета может уточняться при порте. Роли внешних модулей: ключевые проверены по
  коду, остальные — по имени/назначению модуля.
- В client попадают ветки, которые на Keenetic не нужны (AWS SDK для
  route53/libdns — динамический DNS, eBPF-прокси, gVisor netstack, Prometheus,
  Wails UI, мобильные биндинги). Это кандидаты на выбрасывание в Zig-порте,
  если карта владельца не требует обратного.

## Приложение: все внешние пакеты по модулям

### gvisor.dev/gvisor — gVisor netstack — только netstack-режим; на роутере (TUN) не нужен

| Пакет | строк |
|---|---:|
| `gvisor.dev/gvisor/pkg/tcpip/stack` | 19020 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/tcp` | 15969 |
| `gvisor.dev/gvisor/pkg/tcpip` | 8619 |
| `gvisor.dev/gvisor/pkg/tcpip/header` | 8326 |
| `gvisor.dev/gvisor/pkg/tcpip/network/ipv6` | 7904 |
| `gvisor.dev/gvisor/pkg/state` | 5197 |
| `gvisor.dev/gvisor/pkg/tcpip/network/ipv4` | 4930 |
| `gvisor.dev/gvisor/pkg/tcpip/network/internal/ip` | 2267 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/udp` | 1917 |
| `gvisor.dev/gvisor/pkg/buffer` | 1763 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/icmp` | 1513 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/packet` | 1437 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/raw` | 1370 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/internal/network` | 1294 |
| `gvisor.dev/gvisor/pkg/sync` | 1102 |
| `gvisor.dev/gvisor/pkg/tcpip/network/internal/fragmentation` | 1044 |
| `gvisor.dev/gvisor/pkg/state/wire` | 983 |
| `gvisor.dev/gvisor/pkg/sync/locking` | 960 |
| `gvisor.dev/gvisor/pkg/cpuid` | 909 |
| `gvisor.dev/gvisor/pkg/atomicbitops` | 879 |
| `gvisor.dev/gvisor/pkg/log` | 852 |
| `gvisor.dev/gvisor/pkg/tcpip/ports` | 813 |
| `gvisor.dev/gvisor/pkg/tcpip/adapters/gonet` | 716 |
| `gvisor.dev/gvisor/pkg/waiter` | 663 |
| `gvisor.dev/gvisor/pkg/tcpip/link/channel` | 590 |
| `gvisor.dev/gvisor/pkg/sleep` | 587 |
| `gvisor.dev/gvisor/pkg/tcpip/network/internal/multicast` | 580 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack` | 508 |
| `gvisor.dev/gvisor/pkg/refs` | 378 |
| `gvisor.dev/gvisor/pkg/context` | 259 |
| `gvisor.dev/gvisor/pkg/tcpip/checksum` | 256 |
| `gvisor.dev/gvisor/pkg/tcpip/header/parse` | 246 |
| `gvisor.dev/gvisor/pkg/tcpip/transport/internal/noop` | 218 |
| `gvisor.dev/gvisor/pkg/rand` | 216 |
| `gvisor.dev/gvisor/pkg/gohacks` | 154 |
| `gvisor.dev/gvisor/pkg/bits` | 114 |
| `gvisor.dev/gvisor/pkg/tcpip/network/hash` | 96 |
| `gvisor.dev/gvisor/pkg/tcpip/internal/tcp` | 86 |
| `gvisor.dev/gvisor/pkg/tcpip/hash/jenkins` | 82 |
| `gvisor.dev/gvisor/pkg/linewriter` | 79 |
| `gvisor.dev/gvisor/pkg/tcpip/transport` | 68 |
| `gvisor.dev/gvisor/pkg/tcpip/seqnum` | 65 |

### github.com/gopacket/gopacket — парсер пакетов (uspfilter/forwarder, netflow)

| Пакет | строк |
|---|---:|
| `github.com/gopacket/gopacket/layers` | 50492 |
| `github.com/gopacket/gopacket` | 3072 |

### github.com/aws/aws-sdk-go-v2/service/route53 — Route53 (динамический DNS через libdns)

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/route53` | 47896 |
| `github.com/aws/aws-sdk-go-v2/service/route53/types` | 4833 |
| `github.com/aws/aws-sdk-go-v2/service/route53/internal/endpoints` | 387 |
| `github.com/aws/aws-sdk-go-v2/service/route53/internal/customizations` | 210 |

### google.golang.org/protobuf — protobuf-рантайм → заменяется src/proto

| Пакет | строк |
|---|---:|
| `google.golang.org/protobuf/internal/impl` | 16250 |
| `google.golang.org/protobuf/types/descriptorpb` | 5243 |
| `google.golang.org/protobuf/internal/filedesc` | 3329 |
| `google.golang.org/protobuf/reflect/protoreflect` | 2954 |
| `google.golang.org/protobuf/proto` | 2381 |
| `google.golang.org/protobuf/internal/genid` | 2294 |
| `google.golang.org/protobuf/encoding/protojson` | 1951 |
| `google.golang.org/protobuf/internal/encoding/text` | 1775 |
| `google.golang.org/protobuf/reflect/protodesc` | 1734 |
| `google.golang.org/protobuf/internal/encoding/json` | 1155 |
| `google.golang.org/protobuf/encoding/prototext` | 1154 |
| `google.golang.org/protobuf/reflect/protoregistry` | 882 |
| `google.golang.org/protobuf/types/known/structpb` | 767 |
| `google.golang.org/protobuf/internal/protolazy` | 740 |
| `google.golang.org/protobuf/types/known/wrapperspb` | 648 |
| `google.golang.org/protobuf/encoding/protowire` | 571 |
| `google.golang.org/protobuf/types/known/fieldmaskpb` | 560 |
| `google.golang.org/protobuf/types/known/anypb` | 469 |
| `google.golang.org/protobuf/internal/descfmt` | 414 |
| `google.golang.org/protobuf/types/known/timestamppb` | 356 |
| `google.golang.org/protobuf/types/known/durationpb` | 346 |
| `google.golang.org/protobuf/types/gofeaturespb` | 311 |
| `google.golang.org/protobuf/internal/filetype` | 296 |
| `google.golang.org/protobuf/internal/strs` | 267 |
| `google.golang.org/protobuf/internal/encoding/messageset` | 242 |
| `google.golang.org/protobuf/runtime/protoiface` | 217 |
| `google.golang.org/protobuf/internal/encoding/defval` | 213 |
| `google.golang.org/protobuf/internal/encoding/tag` | 208 |
| `google.golang.org/protobuf/internal/order` | 204 |
| `google.golang.org/protobuf/encoding/protodelim` | 160 |
| `google.golang.org/protobuf/runtime/protoimpl` | 108 |
| `google.golang.org/protobuf/internal/errors` | 104 |
| `google.golang.org/protobuf/internal/version` | 79 |
| `google.golang.org/protobuf/internal/detrand` | 69 |
| `google.golang.org/protobuf/internal/set` | 58 |
| `google.golang.org/protobuf/internal/flags` | 34 |
| `google.golang.org/protobuf/protoadapt` | 31 |
| `google.golang.org/protobuf/internal/pragma` | 29 |
| `google.golang.org/protobuf/internal/descopts` | 29 |
| `google.golang.org/protobuf/internal/editionssupport` | 18 |
| `google.golang.org/protobuf/internal/editiondefaults` | 12 |

### github.com/google/gopacket — старый gopacket (транзитивный)

| Пакет | строк |
|---|---:|
| `github.com/google/gopacket/layers` | 36151 |
| `github.com/google/gopacket` | 2840 |

### google.golang.org/grpc — gRPC-фреймворк → в Zig заменяется своим HTTP/2+gRPC-клиентом

| Пакет | строк |
|---|---:|
| `google.golang.org/grpc` | 10306 |
| `google.golang.org/grpc/internal/transport` | 7205 |
| `google.golang.org/grpc/internal/channelz` | 1659 |
| `google.golang.org/grpc/internal/binarylog` | 1058 |
| `google.golang.org/grpc/binarylog/grpc_binarylog_v1` | 1004 |
| `google.golang.org/grpc/balancer/pickfirst` | 961 |
| `google.golang.org/grpc/mem` | 718 |
| `google.golang.org/grpc/credentials` | 659 |
| `google.golang.org/grpc/resolver` | 640 |
| `google.golang.org/grpc/health/grpc_health_v1` | 640 |
| `google.golang.org/grpc/balancer` | 588 |
| `google.golang.org/grpc/internal/balancer/gracefulswitch` | 505 |
| `google.golang.org/grpc/internal/resolver/delegatingresolver` | 477 |
| `google.golang.org/grpc/experimental/stats` | 473 |
| `google.golang.org/grpc/internal/resolver/dns` | 472 |
| `google.golang.org/grpc/stats` | 471 |
| `google.golang.org/grpc/grpclog` | 432 |
| `google.golang.org/grpc/internal` | 389 |
| `google.golang.org/grpc/balancer/endpointsharding` | 388 |
| `google.golang.org/grpc/grpclog/internal` | 380 |
| `google.golang.org/grpc/codes` | 361 |
| `google.golang.org/grpc/internal/mem` | 338 |
| `google.golang.org/grpc/balancer/base` | 331 |
| `google.golang.org/grpc/internal/serviceconfig` | 310 |
| `google.golang.org/grpc/metadata` | 295 |
| `google.golang.org/grpc/internal/idle` | 289 |
| `google.golang.org/grpc/internal/stats` | 287 |
| `google.golang.org/grpc/internal/grpcutil` | 284 |
| `google.golang.org/grpc/internal/grpcsync` | 277 |
| `google.golang.org/grpc/internal/envconfig` | 276 |
| `google.golang.org/grpc/internal/status` | 246 |
| `google.golang.org/grpc/encoding` | 228 |
| `google.golang.org/grpc/internal/credentials` | 220 |
| `google.golang.org/grpc/attributes` | 174 |
| `google.golang.org/grpc/internal/resolver` | 167 |
| `google.golang.org/grpc/status` | 162 |
| `google.golang.org/grpc/internal/metadata` | 144 |
| `google.golang.org/grpc/internal/buffer` | 117 |
| `google.golang.org/grpc/encoding/proto` | 112 |
| `google.golang.org/grpc/internal/syscall` | 112 |
| `google.golang.org/grpc/internal/backoff` | 109 |
| `google.golang.org/grpc/credentials/insecure` | 104 |
| `google.golang.org/grpc/keepalive` | 99 |
| `google.golang.org/grpc/connectivity` | 94 |
| `google.golang.org/grpc/peer` | 83 |
| `google.golang.org/grpc/internal/grpclog` | 79 |
| `google.golang.org/grpc/internal/resolver/unix` | 78 |
| `google.golang.org/grpc/internal/resolver/dns/internal` | 77 |
| `google.golang.org/grpc/internal/pretty` | 73 |
| `google.golang.org/grpc/balancer/roundrobin` | 72 |
| `google.golang.org/grpc/internal/balancer/weight` | 66 |
| `google.golang.org/grpc/internal/resolver/passthrough` | 64 |
| `google.golang.org/grpc/tap` | 62 |
| `google.golang.org/grpc/resolver/dns` | 60 |
| `google.golang.org/grpc/internal/proxyattributes` | 54 |
| `google.golang.org/grpc/backoff` | 52 |
| `google.golang.org/grpc/balancer/grpclb/state` | 51 |
| `google.golang.org/grpc/internal/balancerload` | 46 |
| `google.golang.org/grpc/internal/transport/networktype` | 46 |
| `google.golang.org/grpc/serviceconfig` | 44 |
| `google.golang.org/grpc/balancer/pickfirst/internal` | 37 |
| `google.golang.org/grpc/channelz` | 36 |
| `google.golang.org/grpc/encoding/internal` | 28 |

### => — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/pion/ice/v4` | 9315 |
| `github.com/cloudflare/circl/kem/mceliece/internal` | 6264 |
| `golang.zx2c4.com/wireguard/device` | 5241 |
| `github.com/kardianos/service` | 2334 |
| `golang.zx2c4.com/wireguard/tun` | 1820 |
| `github.com/cloudflare/circl/kem/mceliece/mceliece460896` | 1565 |
| `golang.zx2c4.com/wireguard/conn` | 1180 |
| `golang.zx2c4.com/wireguard/tun/netstack` | 1076 |
| `github.com/cloudflare/circl/pke/kyber/internal/common` | 926 |
| `github.com/cloudflare/circl/internal/sha3` | 867 |
| `github.com/cloudflare/circl/kem/kyber/kyber512` | 402 |
| `github.com/cloudflare/circl/pke/kyber/kyber512/internal` | 401 |
| `golang.zx2c4.com/wireguard/ipc` | 195 |
| `github.com/cloudflare/circl/simd/keccakf1600` | 162 |
| `github.com/cloudflare/circl/pke/kyber/kyber512` | 145 |
| `golang.zx2c4.com/wireguard/ratelimiter` | 137 |
| `github.com/cloudflare/circl/math/gf2e13` | 130 |
| `github.com/pion/ice/v4/internal/taskloop` | 121 |
| `github.com/cloudflare/circl/kem` | 118 |
| `golang.zx2c4.com/wireguard/rwcancel` | 117 |
| `github.com/cloudflare/circl/math/gf2e12` | 83 |
| `github.com/pion/ice/v4/internal/stun` | 72 |
| `github.com/cloudflare/circl/internal/nist` | 64 |
| `golang.zx2c4.com/wireguard/replay` | 62 |
| `github.com/pion/ice/v4/internal/fakenet` | 53 |
| `golang.zx2c4.com/wireguard/tai64n` | 41 |
| `github.com/pion/ice/v4/internal/atomic` | 24 |
| `github.com/cloudflare/circl/pke/kyber/internal/common/params` | 21 |

### golang.org/x/net — HTTP/2 (для gRPC), websocket, idna

| Пакет | строк |
|---|---:|
| `golang.org/x/net/idna` | 6576 |
| `golang.org/x/net/http2` | 5639 |
| `golang.org/x/net/dns/dnsmessage` | 3075 |
| `golang.org/x/net/ipv4` | 2185 |
| `golang.org/x/net/trace` | 2027 |
| `golang.org/x/net/ipv6` | 1941 |
| `golang.org/x/net/http2/hpack` | 1606 |
| `golang.org/x/net/bpf` | 1418 |
| `golang.org/x/net/internal/socket` | 1264 |
| `golang.org/x/net/internal/httpsfv` | 665 |
| `golang.org/x/net/internal/httpcommon` | 643 |
| `golang.org/x/net/internal/timeseries` | 525 |
| `golang.org/x/net/internal/socks` | 485 |
| `golang.org/x/net/proxy` | 429 |
| `golang.org/x/net/http/httpguts` | 397 |
| `golang.org/x/net/internal/iana` | 223 |

### github.com/cilium/ebpf — eBPF загрузка (wgproxy/ebpf, rosenpass)

| Пакет | строк |
|---|---:|
| `github.com/cilium/ebpf` | 9238 |
| `github.com/cilium/ebpf/btf` | 7148 |
| `github.com/cilium/ebpf/link` | 3770 |
| `github.com/cilium/ebpf/asm` | 2939 |
| `github.com/cilium/ebpf/internal/sys` | 2308 |
| `github.com/cilium/ebpf/internal` | 949 |
| `github.com/cilium/ebpf/internal/tracefs` | 413 |
| `github.com/cilium/ebpf/internal/kallsyms` | 402 |
| `github.com/cilium/ebpf/internal/linux` | 385 |
| `github.com/cilium/ebpf/internal/testutils/testmain` | 380 |
| `github.com/cilium/ebpf/internal/sysenc` | 290 |
| `github.com/cilium/ebpf/internal/unix` | 275 |
| `github.com/cilium/ebpf/internal/kconfig` | 274 |
| `github.com/cilium/ebpf/rlimit` | 124 |
| `github.com/cilium/ebpf/internal/platform` | 107 |

### github.com/quic-go/quic-go — QUIC — dialer relay (shared/relay/client/dialer/quic)

| Пакет | строк |
|---|---:|
| `github.com/quic-go/quic-go` | 14536 |
| `github.com/quic-go/quic-go/internal/wire` | 3054 |
| `github.com/quic-go/quic-go/internal/ackhandler` | 2619 |
| `github.com/quic-go/quic-go/internal/handshake` | 2107 |
| `github.com/quic-go/quic-go/qlog` | 1817 |
| `github.com/quic-go/quic-go/internal/protocol` | 836 |
| `github.com/quic-go/quic-go/internal/congestion` | 836 |
| `github.com/quic-go/quic-go/internal/utils` | 359 |
| `github.com/quic-go/quic-go/qlogwriter` | 353 |
| `github.com/quic-go/quic-go/qlogwriter/jsontext` | 324 |
| `github.com/quic-go/quic-go/quicvarint` | 278 |
| `github.com/quic-go/quic-go/internal/utils/linkedlist` | 264 |
| `github.com/quic-go/quic-go/internal/qerr` | 221 |
| `github.com/quic-go/quic-go/internal/utils/ringbuffer` | 92 |
| `github.com/quic-go/quic-go/internal/monotime` | 90 |
| `github.com/quic-go/quic-go/internal/utils/minheap` | 78 |

### github.com/vishvananda/netlink — marшруты/линки через netlink

| Пакет | строк |
|---|---:|
| `github.com/vishvananda/netlink` | 21813 |
| `github.com/vishvananda/netlink/nl` | 5975 |

### golang.org/x/crypto — ssh, chacha20poly1305, hkdf и пр.

| Пакет | строк |
|---|---:|
| `golang.org/x/crypto/ssh` | 12660 |
| `golang.org/x/crypto/acme` | 2522 |
| `golang.org/x/crypto/acme/autocert` | 1615 |
| `golang.org/x/crypto/cryptobyte` | 1358 |
| `golang.org/x/crypto/ocsp` | 800 |
| `golang.org/x/crypto/blake2b` | 699 |
| `golang.org/x/crypto/blake2s` | 627 |
| `golang.org/x/crypto/salsa20/salsa` | 598 |
| `golang.org/x/crypto/ssh/knownhosts` | 553 |
| `golang.org/x/crypto/blowfish` | 457 |
| `golang.org/x/crypto/chacha20` | 456 |
| `golang.org/x/crypto/internal/poly1305` | 420 |
| `golang.org/x/crypto/chacha20poly1305` | 303 |
| `golang.org/x/crypto/nacl/box` | 182 |
| `golang.org/x/crypto/nacl/secretbox` | 173 |
| `golang.org/x/crypto/curve25519` | 93 |
| `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf` | 93 |
| `golang.org/x/crypto/poly1305` | 91 |
| `golang.org/x/crypto/ed25519` | 72 |
| `golang.org/x/crypto/cryptobyte/asn1` | 46 |
| `golang.org/x/crypto/internal/alias` | 31 |

### golang.org/x/sys — сырые syscall-обёртки

| Пакет | строк |
|---|---:|
| `golang.org/x/sys/unix` | 20658 |
| `golang.org/x/sys/cpu` | 955 |

### github.com/miekg/dns — DNS-библиотека (dnsfwd, пробы)

| Пакет | строк |
|---|---:|
| `github.com/miekg/dns` | 21253 |

### github.com/klauspost/compress — zstd и пр. (сжатие)

| Пакет | строк |
|---|---:|
| `github.com/klauspost/compress/zstd` | 12581 |
| `github.com/klauspost/compress/huff0` | 2865 |
| `github.com/klauspost/compress/fse` | 1539 |
| `github.com/klauspost/compress/internal/snapref` | 1016 |
| `github.com/klauspost/compress/zstd/internal/xxhash` | 257 |
| `github.com/klauspost/compress` | 85 |
| `github.com/klauspost/compress/internal/le` | 57 |

### golang.org/x/text — unicode/idna

| Пакет | строк |
|---|---:|
| `golang.org/x/text/unicode/norm` | 10352 |
| `golang.org/x/text/unicode/bidi` | 4147 |
| `golang.org/x/text/transform` | 709 |
| `golang.org/x/text/secure/bidirule` | 340 |

### github.com/goccy/go-yaml — yaml (конфиги/дебаг)

| Пакет | строк |
|---|---:|
| `github.com/goccy/go-yaml` | 4958 |
| `github.com/goccy/go-yaml/parser` | 2550 |
| `github.com/goccy/go-yaml/ast` | 2368 |
| `github.com/goccy/go-yaml/scanner` | 1985 |
| `github.com/goccy/go-yaml/token` | 1177 |
| `github.com/goccy/go-yaml/internal/format` | 539 |
| `github.com/goccy/go-yaml/printer` | 436 |
| `github.com/goccy/go-yaml/internal/errors` | 246 |
| `github.com/goccy/go-yaml/lexer` | 23 |

### github.com/huin/goupnp — UPnP (NAT-traversal)

| Пакет | строк |
|---|---:|
| `github.com/huin/goupnp/dcps/internetgateway2` | 6891 |
| `github.com/huin/goupnp/dcps/internetgateway1` | 4760 |
| `github.com/huin/goupnp/soap` | 789 |
| `github.com/huin/goupnp` | 577 |
| `github.com/huin/goupnp/ssdp` | 419 |
| `github.com/huin/goupnp/httpu` | 342 |
| `github.com/huin/goupnp/scpd` | 176 |

### github.com/pion/dtls/v3 — DTLS (TURN over DTLS, rosenpass-канал)

| Пакет | строк |
|---|---:|
| `github.com/pion/dtls/v3` | 6190 |
| `github.com/pion/dtls/v3/pkg/protocol/handshake` | 1252 |
| `github.com/pion/dtls/v3/internal/ciphersuite` | 1023 |
| `github.com/pion/dtls/v3/pkg/protocol/extension` | 937 |
| `github.com/pion/dtls/v3/pkg/crypto/ciphersuite` | 590 |
| `github.com/pion/dtls/v3/internal/net/udp` | 413 |
| `github.com/pion/dtls/v3/pkg/protocol/recordlayer` | 304 |
| `github.com/pion/dtls/v3/pkg/protocol` | 303 |
| `github.com/pion/dtls/v3/pkg/crypto/prf` | 264 |
| `github.com/pion/dtls/v3/pkg/crypto/ccm` | 261 |
| `github.com/pion/dtls/v3/internal/net` | 242 |
| `github.com/pion/dtls/v3/pkg/protocol/alert` | 167 |
| `github.com/pion/dtls/v3/pkg/crypto/hash` | 136 |
| `github.com/pion/dtls/v3/pkg/crypto/elliptic` | 117 |
| `github.com/pion/dtls/v3/pkg/crypto/signaturehash` | 114 |
| `github.com/pion/dtls/v3/pkg/net` | 111 |
| `github.com/pion/dtls/v3/internal/util` | 53 |
| `github.com/pion/dtls/v3/internal/closer` | 50 |
| `github.com/pion/dtls/v3/internal/ciphersuite/types` | 34 |
| `github.com/pion/dtls/v3/pkg/crypto/signature` | 27 |
| `github.com/pion/dtls/v3/pkg/crypto/clientcertificate` | 25 |

### github.com/prometheus/client_golang — метрики Prometheus (localmetrics)

| Пакет | строк |
|---|---:|
| `github.com/prometheus/client_golang/prometheus` | 8457 |
| `github.com/prometheus/client_golang/prometheus/promhttp` | 1781 |
| `github.com/prometheus/client_golang/prometheus/internal` | 993 |
| `github.com/prometheus/client_golang/internal/github.com/golang/gddo/httputil/header` | 145 |
| `github.com/prometheus/client_golang/internal/github.com/golang/gddo/httputil` | 36 |
| `github.com/prometheus/client_golang/prometheus/promhttp/internal` | 21 |

### gopkg.in/yaml.v3 — yaml (транзитивное)

| Пакет | строк |
|---|---:|
| `gopkg.in/yaml.v3` | 11285 |

### github.com/aws/aws-sdk-go-v2/service/sts — AWS STS (транзитивное route53)

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/sts` | 10180 |
| `github.com/aws/aws-sdk-go-v2/service/sts/internal/endpoints` | 563 |
| `github.com/aws/aws-sdk-go-v2/service/sts/types` | 392 |

### github.com/prometheus/procfs — метрики из /proc

| Пакет | строк |
|---|---:|
| `github.com/prometheus/procfs` | 10587 |
| `github.com/prometheus/procfs/internal/util` | 324 |
| `github.com/prometheus/procfs/internal/fs` | 58 |

### github.com/pkg/sftp — SFTP (встроенный SSH)

| Пакет | строк |
|---|---:|
| `github.com/pkg/sftp` | 7890 |
| `github.com/pkg/sftp/internal/encoding/ssh/filexfer` | 2586 |
| `github.com/pkg/sftp/internal/encoding/ssh/filexfer/openssh` | 463 |

### github.com/aws/smithy-go — AWS SDK рантайм

| Пакет | строк |
|---|---:|
| `github.com/aws/smithy-go/transport/http` | 2435 |
| `github.com/aws/smithy-go/middleware` | 1936 |
| `github.com/aws/smithy-go/ptr` | 1105 |
| `github.com/aws/smithy-go/encoding/xml` | 947 |
| `github.com/aws/smithy-go/encoding/json` | 606 |
| `github.com/aws/smithy-go/encoding/httpbinding` | 571 |
| `github.com/aws/smithy-go/auth/bearer` | 365 |
| `github.com/aws/smithy-go` | 364 |
| `github.com/aws/smithy-go/document` | 240 |
| `github.com/aws/smithy-go/tracing` | 223 |
| `github.com/aws/smithy-go/internal/sync/singleflight` | 218 |
| `github.com/aws/smithy-go/metrics` | 203 |
| `github.com/aws/smithy-go/private/requestcompression` | 185 |
| `github.com/aws/smithy-go/time` | 134 |
| `github.com/aws/smithy-go/io` | 124 |
| `github.com/aws/smithy-go/rand` | 121 |
| `github.com/aws/smithy-go/waiter` | 102 |
| `github.com/aws/smithy-go/auth` | 95 |
| `github.com/aws/smithy-go/logging` | 82 |
| `github.com/aws/smithy-go/context` | 81 |
| `github.com/aws/smithy-go/transport/http/internal/io` | 75 |
| `github.com/aws/smithy-go/encoding` | 44 |
| `github.com/aws/smithy-go/endpoints` | 23 |

### github.com/pion/dtls/v2 — транзитивный DTLS старой версии

| Пакет | строк |
|---|---:|
| `github.com/pion/dtls/v2` | 5141 |
| `github.com/pion/dtls/v2/pkg/protocol/handshake` | 1203 |
| `github.com/pion/dtls/v2/internal/ciphersuite` | 949 |
| `github.com/pion/dtls/v2/pkg/protocol/extension` | 666 |
| `github.com/pion/dtls/v2/pkg/crypto/ciphersuite` | 463 |
| `github.com/pion/dtls/v2/pkg/protocol` | 267 |
| `github.com/pion/dtls/v2/pkg/crypto/prf` | 255 |
| `github.com/pion/dtls/v2/pkg/crypto/ccm` | 254 |
| `github.com/pion/dtls/v2/pkg/protocol/recordlayer` | 187 |
| `github.com/pion/dtls/v2/pkg/protocol/alert` | 166 |
| `github.com/pion/dtls/v2/pkg/crypto/hash` | 129 |
| `github.com/pion/dtls/v2/pkg/crypto/elliptic` | 115 |
| `github.com/pion/dtls/v2/pkg/crypto/signaturehash` | 108 |
| `github.com/pion/dtls/v2/internal/closer` | 48 |
| `github.com/pion/dtls/v2/internal/util` | 42 |
| `github.com/pion/dtls/v2/internal/ciphersuite/types` | 34 |
| `github.com/pion/dtls/v2/pkg/crypto/signature` | 27 |
| `github.com/pion/dtls/v2/pkg/crypto/clientcertificate` | 25 |

### github.com/aws/aws-sdk-go-v2 — AWS SDK — базовое

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/aws` | 2204 |
| `github.com/aws/aws-sdk-go-v2/aws/retry` | 1766 |
| `github.com/aws/aws-sdk-go-v2/aws/signer/v4` | 1197 |
| `github.com/aws/aws-sdk-go-v2/aws/middleware` | 974 |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/awsrulesfn` | 712 |
| `github.com/aws/aws-sdk-go-v2/aws/transport/http` | 577 |
| `github.com/aws/aws-sdk-go-v2/aws/signer/internal/v4` | 524 |
| `github.com/aws/aws-sdk-go-v2/aws/protocol/query` | 466 |
| `github.com/aws/aws-sdk-go-v2/internal/auth` | 236 |
| `github.com/aws/aws-sdk-go-v2/internal/sync/singleflight` | 217 |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints` | 201 |
| `github.com/aws/aws-sdk-go-v2/aws/ratelimit` | 199 |
| `github.com/aws/aws-sdk-go-v2/internal/auth/smithy` | 183 |
| `github.com/aws/aws-sdk-go-v2/aws/defaults` | 133 |
| `github.com/aws/aws-sdk-go-v2/aws/protocol/restjson` | 85 |
| `github.com/aws/aws-sdk-go-v2/internal/sdk` | 83 |
| `github.com/aws/aws-sdk-go-v2/internal/context` | 52 |
| `github.com/aws/aws-sdk-go-v2/aws/protocol/xml` | 48 |
| `github.com/aws/aws-sdk-go-v2/internal/shareddefaults` | 47 |
| `github.com/aws/aws-sdk-go-v2/internal/middleware` | 42 |
| `github.com/aws/aws-sdk-go-v2/internal/rand` | 33 |
| `github.com/aws/aws-sdk-go-v2/internal/timeconv` | 13 |
| `github.com/aws/aws-sdk-go-v2/internal/sdkio` | 12 |
| `github.com/aws/aws-sdk-go-v2/internal/strings` | 11 |

### github.com/caddyserver/certmagic — ACME-сертификаты (проверить путь в клиенте)

| Пакет | строк |
|---|---:|
| `github.com/caddyserver/certmagic` | 9775 |

### go.yaml.in/yaml/v2 — yaml (транзитивное)

| Пакет | строк |
|---|---:|
| `go.yaml.in/yaml/v2` | 9639 |

### github.com/google/nftables — nftables-клиент (firewall)

| Пакет | строк |
|---|---:|
| `github.com/google/nftables/expr` | 3905 |
| `github.com/google/nftables` | 3636 |
| `github.com/google/nftables/xt` | 932 |
| `github.com/google/nftables/alignedbuff` | 300 |
| `github.com/google/nftables/binaryutil` | 125 |
| `github.com/google/nftables/userdata` | 115 |
| `github.com/google/nftables/internal/parseexprfunc` | 11 |

### go.uber.org/zap — структурные логи (транзитивное)

| Пакет | строк |
|---|---:|
| `go.uber.org/zap` | 3569 |
| `go.uber.org/zap/zapcore` | 3495 |
| `go.uber.org/zap/buffer` | 199 |
| `go.uber.org/zap/internal/stacktrace` | 181 |
| `go.uber.org/zap/internal/exit` | 66 |
| `go.uber.org/zap/internal/pool` | 58 |
| `go.uber.org/zap/internal/color` | 44 |
| `go.uber.org/zap/internal` | 37 |
| `go.uber.org/zap/internal/bufferpool` | 31 |

### github.com/aws/aws-sdk-go-v2/service/ssooidc — AWS SSOOIDC (транзитивное config)

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | 6193 |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc/internal/endpoints` | 597 |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc/types` | 450 |

### github.com/godbus/dbus/v5 — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/godbus/dbus/v5` | 6453 |

### github.com/aws/aws-sdk-go-v2/config — AWS config (транзитивное route53)

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/config` | 6344 |

### github.com/spf13/pflag — флаги CLI

| Пакет | строк |
|---|---:|
| `github.com/spf13/pflag` | 6251 |

### github.com/spf13/cobra — CLI

| Пакет | строк |
|---|---:|
| `github.com/spf13/cobra` | 6080 |

### github.com/pion/turn/v4 — TURN-клиент

| Пакет | строк |
|---|---:|
| `github.com/pion/turn/v4/internal/client` | 1700 |
| `github.com/pion/turn/v4` | 1650 |
| `github.com/pion/turn/v4/internal/server` | 884 |
| `github.com/pion/turn/v4/internal/proto` | 836 |
| `github.com/pion/turn/v4/internal/allocation` | 834 |
| `github.com/pion/turn/v4/internal/ipnet` | 56 |

### github.com/prometheus/common — метрики

| Пакет | строк |
|---|---:|
| `github.com/prometheus/common/expfmt` | 3113 |
| `github.com/prometheus/common/model` | 2710 |

### github.com/aws/aws-sdk-go-v2/service/sso — AWS SSO (транзитивное config)

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/sso` | 4863 |
| `github.com/aws/aws-sdk-go-v2/service/sso/internal/endpoints` | 597 |
| `github.com/aws/aws-sdk-go-v2/service/sso/types` | 178 |

### github.com/pion/transport/v3 — транспортные помощники pion

| Пакет | строк |
|---|---:|
| `github.com/pion/transport/v3/vnet` | 3869 |
| `github.com/pion/transport/v3` | 419 |
| `github.com/pion/transport/v3/netctx` | 387 |
| `github.com/pion/transport/v3/packetio` | 381 |
| `github.com/pion/transport/v3/replaydetector` | 220 |
| `github.com/pion/transport/v3/stdnet` | 168 |
| `github.com/pion/transport/v3/deadline` | 158 |
| `github.com/pion/transport/v3/utils/xor` | 20 |

### github.com/shirou/gopsutil/v4 — системная статистика (debug)

| Пакет | строк |
|---|---:|
| `github.com/shirou/gopsutil/v4/process` | 2029 |
| `github.com/shirou/gopsutil/v4/net` | 1162 |
| `github.com/shirou/gopsutil/v4/internal/common` | 990 |
| `github.com/shirou/gopsutil/v4/cpu` | 699 |
| `github.com/shirou/gopsutil/v4/mem` | 689 |
| `github.com/shirou/gopsutil/v4/common` | 25 |

### github.com/pion/turn/v3 — транзитивный TURN старой версии

| Пакет | строк |
|---|---:|
| `github.com/pion/turn/v3/internal/client` | 1657 |
| `github.com/pion/turn/v3` | 1482 |
| `github.com/pion/turn/v3/internal/proto` | 811 |
| `github.com/pion/turn/v3/internal/server` | 691 |
| `github.com/pion/turn/v3/internal/allocation` | 654 |
| `github.com/pion/turn/v3/internal/ipnet` | 55 |

### github.com/grpc-ecosystem/grpc-gateway/v2 — REST-шлюз поверх gRPC (daemon API)

| Пакет | строк |
|---|---:|
| `github.com/grpc-ecosystem/grpc-gateway/v2/runtime` | 3405 |
| `github.com/grpc-ecosystem/grpc-gateway/v2/internal/httprule` | 549 |
| `github.com/grpc-ecosystem/grpc-gateway/v2/utilities` | 250 |

### github.com/mholt/acmez/v2 — ACME

| Пакет | строк |
|---|---:|
| `github.com/mholt/acmez/v2/acme` | 2505 |
| `github.com/mholt/acmez/v2` | 1286 |

### github.com/pion/stun/v3 — STUN-протокол (пробы, binding)

| Пакет | строк |
|---|---:|
| `github.com/pion/stun/v3` | 3382 |
| `github.com/pion/stun/v3/internal/hmac` | 254 |

### github.com/pion/stun/v2 — транзитивный STUN старой версии

| Пакет | строк |
|---|---:|
| `github.com/pion/stun/v2` | 3239 |
| `github.com/pion/stun/v2/internal/hmac` | 248 |

### github.com/coder/websocket — WebSocket-клиент — транспорт relay

| Пакет | строк |
|---|---:|
| `github.com/coder/websocket` | 3268 |
| `github.com/coder/websocket/internal/util` | 15 |
| `github.com/coder/websocket/internal/errd` | 14 |

### github.com/golang/protobuf — старый protobuf-рантайм (транзитивный)

| Пакет | строк |
|---|---:|
| `github.com/golang/protobuf/proto` | 3177 |

### github.com/ti-mo/conntrack — conntrack (netflow)

| Пакет | строк |
|---|---:|
| `github.com/ti-mo/conntrack` | 2938 |

### cunicu.li/go-rosenpass — Rosenpass (post-quantum PSK)

| Пакет | строк |
|---|---:|
| `cunicu.li/go-rosenpass` | 2297 |
| `cunicu.li/go-rosenpass/internal/net` | 269 |
| `cunicu.li/go-rosenpass/internal/ebpf` | 54 |

### github.com/mdlayher/netlink — netlink-библиотека

| Пакет | строк |
|---|---:|
| `github.com/mdlayher/netlink` | 2174 |
| `github.com/mdlayher/netlink/nltest` | 218 |
| `github.com/mdlayher/netlink/nlenc` | 181 |

### github.com/jmespath/go-jmespath — JSON-запросы (AWS)

| Пакет | строк |
|---|---:|
| `github.com/jmespath/go-jmespath` | 2549 |

### github.com/aws/aws-sdk-go-v2/credentials — AWS credentials

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/credentials/ssocreds` | 626 |
| `github.com/aws/aws-sdk-go-v2/credentials/stscreds` | 519 |
| `github.com/aws/aws-sdk-go-v2/credentials/endpointcreds/internal/client` | 397 |
| `github.com/aws/aws-sdk-go-v2/credentials/processcreds` | 388 |
| `github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds` | 299 |
| `github.com/aws/aws-sdk-go-v2/credentials/endpointcreds` | 207 |
| `github.com/aws/aws-sdk-go-v2/credentials` | 73 |

### github.com/netbirdio/go-nat — NAT-PMP/UPnP проброс порта

| Пакет | строк |
|---|---:|
| `github.com/netbirdio/go-nat` | 1288 |
| `github.com/netbirdio/go-nat/pcp` | 1189 |

### github.com/klauspost/cpuid/v2 — CPU-детект (compress)

| Пакет | строк |
|---|---:|
| `github.com/klauspost/cpuid/v2` | 2456 |

### github.com/sirupsen/logrus — логирование

| Пакет | строк |
|---|---:|
| `github.com/sirupsen/logrus` | 2181 |
| `github.com/sirupsen/logrus/hooks/syslog` | 55 |

### github.com/golang-jwt/jwt/v5 — JWT (SSO)

| Пакет | строк |
|---|---:|
| `github.com/golang-jwt/jwt/v5` | 2169 |

### github.com/awnumar/memguard — защита ключей в памяти

| Пакет | строк |
|---|---:|
| `github.com/awnumar/memguard` | 1108 |
| `github.com/awnumar/memguard/core` | 887 |

### golang.zx2c4.com/wireguard/wgctrl — UAPI/netlink конфигурация WG-устройства

| Пакет | строк |
|---|---:|
| `golang.zx2c4.com/wireguard/wgctrl/internal/wglinux` | 874 |
| `golang.zx2c4.com/wireguard/wgctrl/internal/wguser` | 520 |
| `golang.zx2c4.com/wireguard/wgctrl/wgtypes` | 288 |
| `golang.zx2c4.com/wireguard/wgctrl` | 146 |
| `golang.zx2c4.com/wireguard/wgctrl/internal/wginternal` | 26 |

### github.com/aws/aws-sdk-go-v2/feature/ec2/imds — AWS EC2 IMDS

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | 1638 |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds/internal/config` | 114 |

### github.com/gliderlabs/ssh — SSH-сервер

| Пакет | строк |
|---|---:|
| `github.com/gliderlabs/ssh` | 1709 |

### google.golang.org/genproto/googleapis/rpc — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `google.golang.org/genproto/googleapis/rpc/errdetails` | 1473 |
| `google.golang.org/genproto/googleapis/rpc/status` | 202 |

### rsc.io/qr — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `rsc.io/qr/coding` | 815 |
| `rsc.io/qr` | 516 |
| `rsc.io/qr/gf256` | 241 |

### github.com/things-go/go-socks5 — SOCKS5 (netstack proxy)

| Пакет | строк |
|---|---:|
| `github.com/things-go/go-socks5` | 831 |
| `github.com/things-go/go-socks5/statute` | 630 |
| `github.com/things-go/go-socks5/bufferpool` | 40 |

### github.com/pion/transport/v2 — транспортные помощники pion (стар.)

| Пакет | строк |
|---|---:|
| `github.com/pion/transport/v2/udp` | 559 |
| `github.com/pion/transport/v2/packetio` | 390 |
| `github.com/pion/transport/v2/replaydetector` | 200 |
| `github.com/pion/transport/v2/connctx` | 191 |
| `github.com/pion/transport/v2/deadline` | 117 |

### golang.org/x/oauth2 — OAuth2 для SSO

| Пакет | строк |
|---|---:|
| `golang.org/x/oauth2` | 1007 |
| `golang.org/x/oauth2/internal` | 427 |

### github.com/DeRuina/timberjack — ротация логов

| Пакет | строк |
|---|---:|
| `github.com/DeRuina/timberjack` | 1414 |

### github.com/prometheus/client_model — метрики

| Пакет | строк |
|---|---:|
| `github.com/prometheus/client_model/go` | 1399 |

### github.com/google/uuid — UUID

| Пакет | строк |
|---|---:|
| `github.com/google/uuid` | 1311 |

### github.com/pion/mdns/v2 — mDNS-кандидаты ICE

| Пакет | строк |
|---|---:|
| `github.com/pion/mdns/v2` | 1288 |

### github.com/lrh3321/ipset-go — ipset (firewall)

| Пакет | строк |
|---|---:|
| `github.com/lrh3321/ipset-go` | 1239 |

### github.com/fsnotify/fsnotify — файловые события

| Пакет | строк |
|---|---:|
| `github.com/fsnotify/fsnotify` | 1143 |
| `github.com/fsnotify/fsnotify/internal` | 96 |

### golang.org/x/term — терминал (CLI)

| Пакет | строк |
|---|---:|
| `golang.org/x/term` | 1237 |

### github.com/mdlayher/socket — дубликат роли netlink-сокет

| Пакет | строк |
|---|---:|
| `github.com/mdlayher/socket` | 1226 |

### github.com/google/btree — btree (nftables/conntrack)

| Пакет | строк |
|---|---:|
| `github.com/google/btree` | 1083 |

### github.com/koron/go-ssdp — SSDP-поиск UPnP

| Пакет | строк |
|---|---:|
| `github.com/koron/go-ssdp` | 744 |
| `github.com/koron/go-ssdp/internal/multicast` | 289 |
| `github.com/koron/go-ssdp/internal/ssdplog` | 16 |

### github.com/zcalusic/sysinfo — system info

| Пакет | строк |
|---|---:|
| `github.com/zcalusic/sysinfo` | 963 |
| `github.com/zcalusic/sysinfo/cpuid` | 9 |

### github.com/zeebo/blake3 — blake3 (где применяется — выяснить)

| Пакет | строк |
|---|---:|
| `github.com/zeebo/blake3` | 550 |
| `github.com/zeebo/blake3/internal/alg/compress/compress_pure` | 135 |
| `github.com/zeebo/blake3/internal/alg/hash/hash_pure` | 94 |
| `github.com/zeebo/blake3/internal/utils` | 60 |
| `github.com/zeebo/blake3/internal/consts` | 52 |
| `github.com/zeebo/blake3/internal/alg/hash` | 23 |
| `github.com/zeebo/blake3/internal/alg` | 18 |
| `github.com/zeebo/blake3/internal/alg/compress` | 15 |
| `github.com/zeebo/blake3/internal/alg/hash/hash_avx2` | 14 |
| `github.com/zeebo/blake3/internal/alg/compress/compress_sse41` | 10 |

### github.com/coreos/go-iptables — iptables-клиент (firewall)

| Пакет | строк |
|---|---:|
| `github.com/coreos/go-iptables/iptables` | 803 |

### github.com/ti-mo/netfilter — netfilter netlink

| Пакет | строк |
|---|---:|
| `github.com/ti-mo/netfilter` | 766 |

### github.com/tklauser/go-sysconf — sysconf

| Пакет | строк |
|---|---:|
| `github.com/tklauser/go-sysconf` | 760 |

### github.com/hashicorp/go-version — сравнение версий (updater)

| Пакет | строк |
|---|---:|
| `github.com/hashicorp/go-version` | 759 |

### go.uber.org/multierr — транзитивное zap

| Пакет | строк |
|---|---:|
| `go.uber.org/multierr` | 694 |

### github.com/cenkalti/backoff/v4 — retry backoff

| Пакет | строк |
|---|---:|
| `github.com/cenkalti/backoff/v4` | 660 |

### github.com/libdns/route53 — Route53 provider

| Пакет | строк |
|---|---:|
| `github.com/libdns/route53` | 657 |

### github.com/aws/aws-sdk-go-v2/internal/ini — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/internal/ini` | 656 |

### github.com/caddyserver/zerossl — ZeroSSL ACME

| Пакет | строк |
|---|---:|
| `github.com/caddyserver/zerossl` | 598 |

### github.com/mitchellh/hashstructure/v2 — хеш структур (конфиги)

| Пакет | строк |
|---|---:|
| `github.com/mitchellh/hashstructure/v2` | 526 |

### github.com/pkg/errors — ошибки (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/pkg/errors` | 503 |

### github.com/libp2p/go-netroute — выбор исходящего интерфейса

| Пакет | строк |
|---|---:|
| `github.com/libp2p/go-netroute` | 499 |

### golang.org/x/time — rate/timeout

| Пакет | строк |
|---|---:|
| `golang.org/x/time/rate` | 496 |

### github.com/mdlayher/genetlink — generic netlink

| Пакет | строк |
|---|---:|
| `github.com/mdlayher/genetlink` | 454 |

### github.com/vishvananda/netns — netns (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/vishvananda/netns` | 370 |

### golang.org/x/sync — errgroup/semaphore

| Пакет | строк |
|---|---:|
| `golang.org/x/sync/singleflight` | 214 |
| `golang.org/x/sync/errgroup` | 151 |

### github.com/pion/logging — лог-адаптер pion

| Пакет | строк |
|---|---:|
| `github.com/pion/logging` | 319 |

### github.com/beorn7/perks — метрики (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/beorn7/perks/quantile` | 316 |

### github.com/cespare/xxhash/v2 — хеш (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/cespare/xxhash/v2` | 316 |

### github.com/hashicorp/go-multierror — мультиошибки

| Пакет | строк |
|---|---:|
| `github.com/hashicorp/go-multierror` | 308 |

### github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | 308 |

### github.com/tklauser/numcpus — numcpus

| Пакет | строк |
|---|---:|
| `github.com/tklauser/numcpus` | 286 |

### github.com/creack/pty — PTY для SSH

| Пакет | строк |
|---|---:|
| `github.com/creack/pty` | 271 |

### github.com/jackpal/go-nat-pmp — NAT-PMP

| Пакет | строк |
|---|---:|
| `github.com/jackpal/go-nat-pmp` | 265 |

### github.com/mdp/qrterminal/v3 — QR в терминале

| Пакет | строк |
|---|---:|
| `github.com/mdp/qrterminal/v3` | 264 |

### google.golang.org/genproto/googleapis/api — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `google.golang.org/genproto/googleapis/api/httpbody` | 235 |

### github.com/libdns/libdns — абстракция DNS-провайдера

| Пакет | строк |
|---|---:|
| `github.com/libdns/libdns` | 225 |

### github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | 204 |

### github.com/anmitsu/go-shlex — shlex (ssh-тесты)

| Пакет | строк |
|---|---:|
| `github.com/anmitsu/go-shlex` | 193 |

### github.com/munnerz/goautoneg — content-negotiation (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/munnerz/goautoneg` | 189 |

### github.com/hashicorp/errwrap — транзитивное multierror

| Пакет | строк |
|---|---:|
| `github.com/hashicorp/errwrap` | 178 |

### github.com/aws/aws-sdk-go-v2/service/internal/presigned-url — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | 175 |

### github.com/awnumar/memcall — memcall (транзитивное memguard)

| Пакет | строк |
|---|---:|
| `github.com/awnumar/memcall` | 159 |

### golang.org/x/exp — экспериментальное (транзитивное)

| Пакет | строк |
|---|---:|
| `golang.org/x/exp/maps` | 86 |
| `golang.org/x/exp/constraints` | 54 |

### github.com/kr/fs — sftp (транзитивное)

| Пакет | строк |
|---|---:|
| `github.com/kr/fs` | 131 |

### github.com/aws/aws-sdk-go-v2/internal/configsources — транзитивная зависимость; в Zig-порт напрямую не переносится

| Пакет | строк |
|---|---:|
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | 128 |

### github.com/pion/randutil — рандом для pion

| Пакет | строк |
|---|---:|
| `github.com/pion/randutil` | 102 |

### github.com/skratchdot/open-golang — открыть браузер (SSO)

| Пакет | строк |
|---|---:|
| `github.com/skratchdot/open-golang/open` | 68 |

### github.com/wlynxg/anet — net iface (Android)

| Пакет | строк |
|---|---:|
| `github.com/wlynxg/anet` | 37 |
