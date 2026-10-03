# Council r2 — GLM о предложении Muse (r1-muse)

Автор: GLM-5.3-Flash (Droid). Ревью `council/r1-muse.md` с проверкой утверждений по
`upstream/netbird` и Zig std 0.17.0. Своё предложение — `council/r1-glm.md`, инвентарь —
`docs/inventory.md`. Каждая проверка — с командой. Догадки помечены.

## 1. Согласия (проверено по исходникам)

Цитаты Muse из рантайм-пути подтверждаются дословно (проверено `sed -n`):

| Утверждение Muse | Проверка | Результат |
|---|---|---|
| демон на `unix:///var/run/netbird.sock`, `client/cmd/root.go:151` | `sed -n '151p' client/cmd/root.go` → `defaultDaemonAddr := "unix:///var/run/netbird.sock"` | ✅ |
| CLI через `DialClientGRPCServer`, root.go:278 | та же команда | ✅ (func объявлена на :278) |
| `Server.Up` server.go:989, `connectWithRetryRuns` :343 | `sed -n '343p;989p' client/server/server.go` | ✅ обе |
| mgmt `NewClient` grpc.go:128, `handleSyncStream` :427 | `sed -n '128p;427p' shared/management/client/grpc.go` | ✅ обе |
| `handleSync` engine.go:1006, `updateSTUNs` :1525, `updateTURNs` :1543, `newWgIface` :2197 | `sed -n` по engine.go | ✅ все четыре |
| signal bidi-стрим `ConnectStream`, signalexchange.proto:13 | `sed -n '13p'` | ✅ |
| `NB_WG_KERNEL_DISABLED` форсирует userspace | `sed -n '85,95p' client/iface/device/kernel_module_linux.go` | ✅ |
| go.mod: wireguard :26, pion/ice/v4 :95 (замена-00010101), quic-go v0.62.0 :106 | grep go.mod | ✅ |

Также подтверждаю independently (мои замеры, `docs/inventory.md`):
- Zig std НЕ содержит protobuf, gRPC, HTTP/2, QUIC, WebSocket, ICE, STUN, TURN,
  DNS-кодек, netlink, TUN; содержит TLS-клиент (`crypto/tls/Client.zig`),
  крипто-примитивы (`crypto/25519/x25519.zig`, `crypto/chacha20.zig:54`,
  `crypto/blake2.zig:30-33`, hkdf) и HTTP/1.1 (`http/Client.zig`).
- Порядок рисков (gRPC/h2 → ICE → QUIC → WG device → protobuf) согласен.
- Подход «каждый майлстоун тестируется сам» и router-first скоуп — согласен.
- Deferred-список (SSO/OIDC, SSH, updater, Rosenpass, flow) — согласен; на роутере
  это лишнее. Предлагаю также явно записать в deferred: eBPF-прокси (ядро 4.9),
  Prometheus/AWS-ветки (в arm64-клиент они компилируются, но в Zig-порте не нужны),
  gVisor netstack.
- Риск №1 Muse (std `Io`: `Uring.zig`/`Threaded.zig`) проверен: `ls lib/std/Io/`
  показывает оба файла; опасение валидно, митигация (Threaded-бэкенд или сырой
  posix) — принять, добавить qemu-strace-проверку в acceptance первого сетевого
  майлстоуна.

## 2. Несогласия / поправки (с доказательствами)

1. **Шифрование mgmt/signal — NaCl box, а не «Curve25519+ChaCha20Poly1305»
   (моя ошибка в r1-glm.md, Muse права).** Доказательство: `encryption/encryption.go`
   импортирует `golang.org/x/crypto/nacl/box`, комментарий «Curve25519, XSalsa20 and
   Poly1305», `Encrypt` = `box.Seal(...)` (:18). В r1-glm.md исправлено.
   Следствие для Zig: в std нет `crypto/nacl`, но есть `crypto/salsa20.zig:368
   XSalsa20Poly1305` и X25519 — box собирается вручную (HSalsa20 для key derivation).
   На тесты M2 это не влияет (векторы от Go).

2. **Методика размеров: find-числа Muse — «все не-тестовые файлы каталога», это
   верхняя граница, а не arm64-сборка.** `go list .GoFiles` (мой метод) даёт точный
   набор файлов, компилируемых в arm64-клиент. Расхождения (проверено):
   - `client/ssh`: find 8600 против 5851 в arm64-сборке (разница — платформенно
     запертые файлы: pty/windows и пр.).
   - `client/internal/updater`: find 3509 против 1009 в сборке.
   - `encryption`: find 387 против 245 в сборке — у Muse в 387 попал
     `encryption/testprotos/testproto.pb.go` (142, тестовый генерат) и `route53.go` (89).
   - `client/server`: 5475 против 5379 (один платформенный файл).
   Оба числа полезны: find — объём чтения при порте, GoFiles — что реально работает
   в arm64-бинарнике. В сводных документах нужно указывать метод. На выводы Muse
   существенного влияния нет (подмножества оценены как «subset — guess» честно).

3. **«Pion subset of 60048» двойно-считает мажоры.** В arm64-сборке действительно
   есть и старые, и новые мажоры (stun v2 3487 + v3 3636, turn v3 5350 + v4 5960,
   dtls v2 10079 + v3 12613, transport v2 1457 + v3 5622 — `modsum3.txt`), но
   портировать нужно только один API-мажор на протокол (stun v3, turn v4, dtls v3
   при нужде, transport v3). 60048 — не цель порта.

4. **M1 «upper bound 25634 генерированных строк»** — корректно как граница, но
   рукописный кодек это не заменяет один-в-один: реальный объём определяется числом
   используемых сообщений (Login/LoginResponse/SyncResponse/NetworkMap + signal
   EncryptedMessage + daemon-подмножество). Оценка: 1-2 тыс. строк Zig
   (предположение). Спор нет, уточнение.

## 3. Что Muse упустила

1. **wgproxy/udp — userspace-форвардер routed-трафика** (`client/iface/wgproxy/udp`,
   430 строк + bind). В userspace-режиме (`NB_WG_KERNEL_DISABLED=true`) трафик
   сетей/exit-node идёт через него (описание режимов в upstream `AGENTS.md`).
   Без него M5 даст туннель без маршрутизируемого трафика. Включить в M5.
2. **lazyconn** (`client/internal/lazyconn*`, ~1.6 тыс. строк) — ленивые соединения
   пиров (влияют на трафик-активность и память). Явно записать в deferred или в M10.
3. **statx-обход** из AGENTS.md — Muse упомянула syscalls в целом, но не конкретный
   известный workaround (lseek вместо File.stat/File.Reader.getSize). Записать в
   правила порта: любые файловые операции через std проверять strace'ом на 4.9.
4. **Граница привилегий демона**: если на роутере будет демон-режим, IPC —
   привилегированная граница (SO_PEERCRED, `client/internal/ipcauth`). Либо
   решение «демона на роутере нет» (мой открытый вопрос №6 в r1) — тогда
   client/proto (13 006) уходит из критического пути.
5. **Замер памяти как явный acceptance**: после майлстоуна с TLS+h2+mgmt — замер
   RSS в qemu-aarch64, бюджет против свободных ~44 МБ (база Go 24.1 МБ RSS).

## 4. Сводное предложение по майлстоунам 1-3 (GLM+Muse)

Общая база: структура src/ Muse (16 модулей) принимается с дополнениями
`src/proto` (моё) = её `proto`; спорных расхождений по структуре нет.

- **M1 — protobuf wire + кодеки signal/daemon.**
  Референсы: protowire 571 (build-exact) / генерат ≤25634 (find, Muse).
  Тесты: байт-векторы от Go-программы с protowire (round-trip всех wire-типов,
  max varint, усечения, skip unknown) + декодирование реального SyncResponse,
  снятого с Go-клиента. Acceptance: `zig test` + побайтное совпадение с векторами.
- **M2 — крипто: ключи (X25519), NaCl box для EncryptedMessage, WG-примитивы.**
  Референсы: encryption 245 (build-exact) / 387 (find), wgtypes 288.
  Тесты: векторы box.Seal/box.Open от Go; interop: расшифровать сообщение,
  зашифрованное Go-клиентом; JSON round-trip профиля/стейта (её M0 сюда же).
  Acceptance: interop с Go-шифрованием в обе стороны.
- **M3 — TLS + HTTP/2 + gRPC-клиент + mgmt Login/Sync против локальной заглушки.**
  Референсы: grpc-go 36678 (НЕ портируем, свой минимум), mgmt client 1250,
  handleSyncStream как поведенческий реф. Тесты (Muse): fake ManagementService в Go,
  реплеящий Login/Sync; далее локальный upstream-стек от лида.
  Acceptance: Login успешен, SyncResponse декодирован кодеком M1; плюс strace-прогон
  на 4.9 (нет io_uring/statx). Замер RSS — сюда же.

Что решает лид (не совет): QUIC vs WS для relay (M4+), демона на роутере (M7+),
nftables vs uspfilter (M6+), protoc-плагин vs рукописные кодеки (M1).
