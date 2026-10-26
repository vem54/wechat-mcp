# Third-party notices

The native WeChat interoperability research uses address naming, protocol definitions and transport analysis from [yincongcyincong/wechat_chatter](https://github.com/yincongcyincong/wechat_chatter), copyright2026 yincongcyincong and contributors, licensed under the GNU General Public License version3. The full license is included as LICENSE.

The initial native sender adaptation was discarded after static analysis identified unsafe map-root mutation and shallow copying of C++ callback objects. The passive probes and experimental prepared-task sender are new exact-build implementations, using native constructors, deep copying, account framing and bounded completion routing. They do not reuse the old map mutation or captured-object snapshots. The text wire schema retains the upstream GPL attribution in protocol.py. No sending capability should be inferred from static address matches or a successful MCP handshake.

This project is unofficial. Tencent did not create or endorse it. The downloaded Tencent application used for local static comparison is not redistributed with this package.
