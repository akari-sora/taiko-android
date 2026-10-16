"""Declarative build profiles shared by Apple tooling and Android catalog generation.

The historical Apple key is a 16-byte prefix, deliberately NOT an approved
Android production identity. Full identity and source digest are mandatory.
This module performs no input reads or executable patching on import.
"""
from dataclasses import asdict, dataclass
import hashlib
import json

APPLE_BUILD_PREFIX = 'db0507f36b84200ac05f75d76ed5026f'


@dataclass(frozen=True)
class Observation:
    offset: int
    id: int
    word: int


@dataclass(frozen=True)
class Parameter:
    a: int
    b: int
    word_a: int
    word_b: int
    destination: int
    slot: int
    flags: int


@dataclass(frozen=True)
class Profile:
    target: str
    module: str
    variant: str
    ruleset: str
    build_id: bytes
    source_sha256: bytes
    identity_class: int
    observations: tuple
    parameters: tuple

    def __post_init__(self):
        if (self.target != 'android-arm64' or not self.module or not self.variant or not self.ruleset or
                len(self.build_id) != 32 or len(self.source_sha256) != 32 or
                self.identity_class not in (1, 2)):
            raise ValueError('profile requires full 32-byte identity/source and declared class')

    def canonical_bytes(self):
        values = asdict(self)
        values['build_id'] = self.build_id.hex()
        values['source_sha256'] = self.source_sha256.hex()
        return json.dumps(values, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

    @property
    def digest(self):
        return hashlib.sha256(self.canonical_bytes()).digest()


# Populated only by independently pinned, self-authored full identities below.
# The Apple prefix tables remain an unresolved production template.
SYNTHETIC_OBSERVATION = Profile(
    'android-arm64', 'main', 'synthetic-observation-v1', 'public-observation-params-v1',
    bytes.fromhex('4cb4641eef3bbca4a988f4b6295e8ff09dc5eb9a50d0207d3922644d146a8bd0'),
    bytes.fromhex('7c6d0e794b729082ec469823740d47c0a93469a3b68a32acb07b6401c3f23ff9'), 1,
    (Observation(0x100, 2, 0x91000400), Observation(0x120, 1, 0x91000400), Observation(0x14c, 6, 0x91000400)),
    (Parameter(0x200, 0x204, 0xd2800228, 0xf2a00448, 8, 0, 0),
     Parameter(0x240, 0x24c, 0xd2800228, 0xf2a00668, 8, 0, 0),
     Parameter(0x244, 0x250, 0xd2800449, 0xf2a00889, 9, 1, 0),
     Parameter(0x280, 0x284, 0x52800228, 0x72a00448, 8, 2, 1),
     Parameter(0x2a0, 0x2a4, 0x52800668, 0x72a00888, 8, 3, 1)))
PROFILES = (SYNTHETIC_OBSERVATION,)


def resolve_profile(name, build_id, source_sha256, requested=None):
    candidates = [p for p in PROFILES if (p.module, p.build_id, p.source_sha256) ==
                  (name, build_id, source_sha256) and (requested is None or p.variant == requested)]
    if requested is not None and not candidates:
        raise ValueError('requested profile has no registered full identity/source match')
    if len(candidates) > 1:
        raise ValueError('ambiguous registered profile; select variant explicitly')
    return candidates[0] if candidates else None

APPLE_OBS = {'db0507f36b84200ac05f75d76ed5026f': [
    (0xb1dc60, 1, 'd10603ff', 'UI 消息总线虚函数实现入口（x1 = 消息 {u64 类型哈希, u64 动作哈希, char* 面板名, …}）：'
     'DM_UIMSG 消息流与 DM_BOOTPROF 启动分段的唯一来源；原指令 sub sp, sp, #0x180'),
    (0x5d3bc0, 2, 'd10503ff', '服务端拍入口（x0 = 游戏对象 G）：DM_TICKS 逐拍 6 格状态哈希（dm/verify/tick_state_format.md，与真值 swtick.py 同一采集点）；'
     '原指令 sub sp, sp, #0x140'),
    (0x6e5b40, 3, 'd10103ff', '客户端命令分派入口 (G, 单位, 包, 长度)：DM_C2S_LOG 命令包序列（dm/verify/command_packet_format.md，与真值同一采集点）；'
     '原指令 sub sp, sp, #0x40'),
    (0x6310b0, 4, 'a9bb67fc', '系统类客户端消息处理入口 (buf = u32 客户端号 + 包, 包长)：包号 ≥ 0x67（加入 / 心跳 0x6d / 0x6f 等），收包泵先抽干此队列；'
     'DM_C2S_LOG 记为 "q":"sys"；原指令 stp x28, x25, [sp, #-0x50]!'),
    (0x317298, 5, 'd10183ff', 'SetLanguage 入口（x1 → u32 新语言号，语言名表 main+0x20ae478）：配合上方语言重载剪口，宿主断言新语言为 zhCN；'
     '原指令 sub sp, sp, #0x60'),
]}

APPLE_PARAMS = {'db0507f36b84200ac05f75d76ed5026f': [
    (0xe12d8c, 'd280c813', 0xe12d90, 'f2c07093', 19, 'KRES1', '启动初始化：主机模式输出分辨率 1600x900（{u32 宽, u32 高} 打包）'),
    (0xe12e1c, 'd280a008', 0xe12e20, 'f2c05a08', 8, 'KRES0', '启动初始化：掌机模式输出分辨率 1280x720'),
    (0xe10d60, 'd280c818', 0xe10d80, 'f2c07098', 24, 'KRES1', '运行模式变化通知（0x1f）处理：主机模式 1600x900'),
    (0xe10d5c, 'd280a016', 0xe10d74, 'f2c05a16', 22, 'KRES0', '运行模式变化通知（0x1f）处理：掌机模式 1280x720'),
    # 宽高比上限 19:9（float 0x40071c72）：宽于 19:9 的屏幕两侧留黑柱。宿主给 max(19/9, 输出宽 / 高) 的浮点位模式（低 32 位）；
    # 原版输出 16:9（1600x900 / 1280x720）⇒ 仍为 19/9，行为不变；iPhone 1952x900（2.17:1）⇒ 2.169，黑柱宽 0
    # Aspect ratio cap 19:9 (float 0x40071c72): screens wider than 19:9 get black bars on both sides. The host supplies the float bit pattern (low 32 bits) of max(19/9, output width / height);
    # the original game outputs 16:9 (1600x900 / 1280x720) ⇒ still 19/9, behavior unchanged; iPhone 1952x900 (2.17:1) ⇒ 2.169, black bar width 0
    (0x1663ee8, '52838e49', 0x1663eec, '72a800e9', 9, 'KASPECTUI', '界面常量缓冲 0x15 号槽 [屏宽, 屏高, 宽高比上限]：界面精灵着色器按它在上限以外画两侧黑柱（带约 20–30 像素向内的柔边，宿主另加余量把柔边推出屏幕）'),
    (0xb152bc, '52838e48', 0xb152c0, '72a800e8', 8, 'KASPECT', '新画面模式视口：边距 = (屏宽 − 屏高 × 上限) / 2，经 0x85bc90 设居中视口'),
    (0x23e888, '52838e48', 0x23e88c, '72a800e8', 8, 'KASPECT', '新画面模式坐标钳制（0x23e760）：x 夹进 [边距, 边距 + 屏高 × 上限]，宽屏两侧的指针 / 触摸不再被夹回中间'),
]}
