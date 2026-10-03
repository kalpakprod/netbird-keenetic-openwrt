# Council r1 — план порта NetBird-клиента (v0.79.0) на Zig 0.17: GLM

Автор: GLM-5.3-Flash (Droid). Все числа — из команд, приведённых рядом (метод в
`docs/inventory.md`, данные в `~/.cache/netbird-zig-context/`). Пути — от корня
`upstream/netbird`, если не указано иное. Догадки помечены «(предположение)».

## 1. Рантайм-путь клиента

Проверено чтением кода (цитирую файлы и строки):

1. **Вход**: `client/main.go` → `cmd.Execute()` (`client/cmd/root.go`).
2. **Два режима запуска**: демон (`netbird service run`, gRPC над unix-сокетом,
   протокол `client/proto`, dialer `client/grpc/dialer.go`, сервер `client/server/`)
   и foreground (`netbird up -F`). CLI `up`/`login` в обычном режиме ходят в демон
   (`client/cmd/login.go:100-140`: `proto.NewDaemonServiceClient(conn).Login`).
3. **Foreground-подключение**: `client/cmd/up.go` (`upFunc`) →
   `internal.ConnectClient.Run` (`client/internal/connect.go:117` → `run()` :174):
   загрузка/создание приватного ключа, `loginToManagement` (connect.go:734),
   `createEngineConfig` (connect.go:625), `engine.Start`.
4. **Login с setup key**: setup key уходит в management gRPC `Login`
   (`shared/management/client`), ответ `LoginResponse` несёт PeerConfig
   (IP интерфейса), NetbirdConfig (адреса management/signal/relay, STUN/TURN).
5. **Engine.Start** (`client/internal/engine.go:544`) — порядок инициализации:
   `newWgIface` (userspace: `client/iface/device/device_usp_unix.go:33` `NewTunDevice`
   — TUN `/dev/net/tun` + wireguard-go device), flowManager, rosenpass (опц.),
   DNS-сервер (`client/internal/dns`), routeManager (`client/internal/routemanager`),
   `wgInterfaceCreate`/`Up` (udpmux `client/iface/udpmux`), firewall
   (`client/firewall/create_linux.go`), connMgr (`client/internal/conn_mgr.go`),
   `SRWatcher` (guard signal/relay), `receiveSignalEvents`,
   `receiveManagementEvents`, network monitor, wgIfaceMonitor.
6. **Management sync**: gRPC-стрим Sync (`shared/management/client`) →
   `SyncResponse` → `shared/management/networkmap` → обновление пиров, маршрутов,
   DNS, ACL.
7. **Signal**: `connectToSignal` (connect.go:715) → `shared/signal/client/grpc.go:105`
   `NewClient`, стрим `SignalExchange.ConnectStream`; сообщения зашифрованы
   (`encryptMessage`/`decryptMessage` grpc.go:414/434, пакет `encryption` — NaCl box:
   Curve25519 + XSalsa20 + Poly1305, `encryption/encryption.go:18` `box.Seal`; исправлено
   по итогам r2 — изначально ошибочно указал ChaCha20Poly1305).
8. **Соединение пира**: `client/internal/peer/conn.go:230` `open()`:
   ICE-агент (fork `github.com/netbirdio/ice/v4`) или relay
   (`shared/relay/client`, транспорт WS (`dialer/ws`, `coder/websocket`) или QUIC
   (`dialer/quic`, `quic-go`), HMAC-аутентификация `shared/relay/auth/hmac`);
   пробы STUN/TURN (`client/internal/relay/relay.go` `StunTurnProbe`, pion/stun+turn);
   проброс порта NAT-PMP/UPnP (`github.com/netbirdio/go-nat`, `huin/goupnp`);
   WG-хендшейк настраивается через UAPI-конфигуратор (`client/iface/configurer/usp.go`);
   routed-трафик идёт через `client/iface/wgproxy/udp` (userspace forwarder).
9. **Плоскость данных**: wireguard-go (fork netbirdio) ↔ TUN ↔ маршруты
   (`routemanager/systemops`, netlink) + firewall (nftables/iptables/uspfilter) +
   DNS (`internal/dns`: хендлеры, resolvconf, локальный резолвер, dnsfwd).
10. **Состояние**: профили и конфиг (`client/internal/profilemanager`),
    `statemanager` (state.json), `syncstore`.

В режиме роутера (по контексту карточки): userspace WG (`NB_WG_KERNEL_DISABLED=true`),
уровень логов warning, NetBird cloud. Значит критичный путь: TLS+gRPC →
management/signal → ICE/relay → wireguard-go ↔ TUN ↔ маршруты/фаервол/DNS.

## 2. Протоколы на проводе и покрытие Zig std 0.17.0

Замер: 736 нестандартных пакетов, 1 031 228 строк, из них свой код 141 301
(`docs/inventory.md`). Протоколы:

| Протокол | Реализация в Go (строк, замер) | Zig std 0.17 | Вывод |
|---|---|---|---|
| protobuf wire | `google.golang.org/protobuf` (48 662; сам wire-формат `encoding/protowire` — 571) | нет | свой кодек `src/proto` |
| gRPC | `google.golang.org/grpc` (35 669) | нет | минимальный свой gRPC-клиент |
| HTTP/2 | `golang.org/x/net` (29 098, http2 внутри) | нет (std/http — HTTP/1.1, `lib/std/http/Client.zig`) | свой h2-клиент |
| TLS 1.3 | `crypto/tls` Go | есть: `lib/std/crypto/tls/Client.zig` | использовать; проверить ALPN «h2» |
| WebSocket | `github.com/coder/websocket` (3 297) | нет | свой WS-клиент для relay |
| QUIC | `github.com/quic-go/quic-go` (27 864) | нет | по возможности исключить (WS-транспорт relay) — вопрос №2 |
| STUN/TURN | `pion/stun/v3` (3 636), `pion/turn/v4` (5 960) | нет | свой минимум (binding, allocate) |
| ICE | fork `github.com/netbirdio/ice/v4` (9 315) | нет | самая большая самописная часть после gRPC |
| WireGuard Noise | fork `github.com/netbirdio/wireguard-go`: device+conn 7 743 | крипта есть: `crypto/25519/x25519.zig`, `crypto/chacha20.zig:54` (ChaCha20Poly1305), `crypto/blake2.zig:30-33` (Blake2s256) | порт device/conn, крипта из std |
| DNS-провод | `miekg/dns` (21 253) + свой dnsfwd | нет DNS-кодека | свой минимал-кодек DNS-сообщений |
| netlink (маршруты) | `vishvananda/netlink` (21 813+2 573) | нет | сырой netlink через std.posix |
| nftables/iptables | `google/nftables` (9 024), `coreos/go-iptables` (803) | нет | на старте — userspace-фильтр (`uspfilter`, 3 959), вопрос №3 |
| TUN | `/dev/net/tun` ioctl | нет обёртки | сырой ioctl через std.os.linux |
| netstack (gVisor) | `gvisor.dev/gvisor` (95 029) | нет | **не портировать** (нужен только netstack-режиму) |

Итого принципиально нового руками: protobuf-кодек, TLS/h2/gRPC-клиент, WS, ICE,
STUN/TURN, WG device, TUN, netlink, DNS-кодек. Это согласовывается с инвентаризацией:
внешних строк 889 927, но в порт живёт лишь малая часть (см. таблицу выше).

## 3. Структура Zig-кода

```
src/proto/      protobuf wire + кодеки management/signal/daemon сообщений (M1)
src/crypto/     ключи wgtypes, encryption: NaCl box (X25519+XSalsa20Poly1305) (M2)
src/wireguard/  port wireguard-go device/conn/noise/cookie/replay (M3)
src/tun/        TUN-девайс /dev/net/tun, ioctl (M4)
src/iface/      udpmux, wgproxy (UDP forwarder), конфигуратор UAPI (M4)
src/net/        TLS/h2/gRPC-клиент, WebSocket (M5)
src/mgmt/       management-клиент (Login/Sync) + кодек сообщений (M5)
src/signal/     signal-клиент (M5)
src/relay/      relay-клиент (WS), HMAC (M6)
src/ice/        ICE/STUN/TURN агент, NAT-проброс (M7)
src/dns/        DNS-менеджер, локальный резолвер, кодек DNS (M8)
src/routes/     netlink-маршруты (M9)
src/firewall/   userspace-фильтр, затем nftables (M9)
src/engine/     Engine, мониторы, ACL (M10)
src/daemon/     демон + IPC (client/proto) (M10)
cmd/netbird.zig CLI
```

Без C, без -lc; статическая сборка `zig build-exe -target aarch64-linux-musl`.

## 4. Майлстоуны (порядок, тест, размер)

Размер «источника» — измеренные строки Go (wc -l, без тестов; команда в
инвентаризации). Размер на Zig — оценка (предположение), не факт.

| # | Майлстоун | Источник (строк Go) | Тест (что доказывает) |
|---|---|---|---|
| M1 | protobuf wire runtime `src/proto` | protowire 571 | round-trip всех типов, max varint, усечённые входы; байт-векторы от Go-программы с protowire; `zig test` |
| M2 | ключи + encryption (NaCl box) | `encryption` 245 + wgtypes 288 (ref) | box.Seal/box.Open-векторы от Go (X25519+XSalsa20Poly1305); шифрование signal-сообщения совпадает с Go |
| M3 | WG device: noise, cookie, send/recv, replay | device+conn 7 743 | interop-хендшейк с wireguard-go локально (UDP), noise-векторы из spec-тестов; `zig test` |
| M4 | TUN + iface: tun, udpmux, wgproxy/udp | `client/iface` 8 967 (частично) | локальный WG-туннель zig↔wireguard-go: ping по TUN |
| M5 | TLS/h2/gRPC + mgmt/signal клиенты | grpc 35 669 (не портится целиком; свой минимум), mgmt client+proto 1250+14 778, signal client+proto 881+837 | Login+Sync против локального management/signal из upstream (стек лидa) |
| M6 | relay-клиент (WS+HMAC) | `shared/relay/client` 2 488 + messages 399 | локальный relay-сервер: коннект и трафик через relay |
| M7 | ICE/STUN/TURN + NAT | peer 6 090 + ice 9 315 + stun/turn 9 596 + go-nat 2 477 | два клиента обмениваются кандидатами через локальный STUN-заглушку; прямой P2P ping |
| M8 | DNS | `internal/dns` 6 413 + `dns` 340 | локальный dig-запрос к нашему резолверу; перехват DNS-маршрутов |
| M9 | маршруты + firewall | routes 8 684 + firewall 15 740 (сначала systemops+uspfilter) | netns-тест: маршрут добавлен, трафик фильтруется |
| M10 | engine + демон + CLI | internal core 5 567 + server 5 379 + cmd 7 242 | e2e против локального стека: up/login/передача данных |

Порядок M5→M6→M7 выбран так, чтобы каждый шаг имел автономный тест; ICE (M7)
сознательно после relay (M6): relay-путь проще и даёт рабочий канал для отладки ICE.

## 5. Риски

1. **Ядро 4.9**: нет statx (4.11), io_uring, clone3/pidfd_* (5.3), openat2 (5.6),
   faccessat2 (5.8), close_range (5.9), epoll_pwait2 (5.11) (AGENTS.md, проверено
   2026-10-03). Zig std вызывает statx из File.stat/File.Reader.getSize — обход
   lseek уже описан в AGENTS.md. Контроль: `qemu-aarch64-static -strace` на каждый
   билд; риск новых несовместимых вызовов в std 0.17 — высокий, проверять каждый релиз std.
2. **Память**: база Go — RSS 24.1 МБ + 6.7 подкачки, свободно ~44 МБ. Наш минимум:
   без gVisor, без eBPF, без Prometheus/AWS — по сути TLS-сессии + ICE-буферы.
   Цель сильно ниже Go, но замер надо сделать рано (после M4/M5).
3. **Зиг std-дыры** (таблица выше): h2/gRPC и ICE — два самых дорогих самописных
   блока; у TLS-клиента std нужно проверить ALPN и версии (вопрос №1).
4. **QUIC для relay** — если cloud-сервер потребует QUIC-транспорт, это +27 864
   строки Go эквивалента (вопрос №2).
5. **Локальный стек для тестов**: management/signal/relay из upstream — нужны
   локальные серверы (владелец/лид даёт compose); без них M5-M10 не верифицируются.
6. **Кодогенерация protobuf**: .proto upstream (`shared/management/proto/*.proto`)
   надо превратить в Zig-кодеки; hand-written для M1, генератор — отдельное решение.
7. **nftables на Keenetic**: какой бэкенд доступен на прошивке — выяснить до M9 (вопрос №3).

## 6. Открытые вопросы

1. Хватит ли `std.crypto.tls.Client` (версии TLS, ALPN h2) для NetBird cloud —
   проверить hands-on в M5 (подозреваю TLS 1.3 + ALPN обязателен).
2. Обязателен ли QUIC-транспорт relay или WS достаточно (иначе объём растёт).
3. Firewall на Keenetic: nftables или userspace-фильтр первым.
4. Нужен ли rosenpass (582+2 620 строк) — по умолчанию выключен (предположение).
5. eBPF-прокси (wgproxy/ebpf) на ядре 4.9 — считаю неприменимым, подтвердить.
6. Нужен ли демон/IPC (client/proto, 13 006) на роутере или достаточно foreground-режима.

## Источник чисел

```
cd upstream/netbird && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go list -mod=vendor -deps \
  -f '{{if not .Standard}}{{.ImportPath}}	{{.Dir}}	{{join .GoFiles " "}}{{end}}' ./client
# 736 пакетов; wc -l по 3974 файлам → 1 031 228 строк; свой код 171 пакет / 141 301
```

Детализация по пакетам — `docs/inventory.md`.
