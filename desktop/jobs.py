"""Desktop orchestration, with the existing cryptographic core unchanged."""
import os
from pathlib import Path
from dataclasses import dataclass
from core import hdt


@dataclass(frozen=True)
class Result:
    status: str
    message: str


def prepare(mode, source, output, keyfile, parts, confirmation, setting):
    if mode not in ("encrypt", "decrypt"):
        raise ValueError("Invalid operation")
    if not all(isinstance(p, str) and p.strip() for p in (source, output, keyfile)):
        raise ValueError("Choose all three file paths / 请选择全部文件路径")
    src, dst, key = (Path(p).expanduser().absolute() for p in (source, output, keyfile))
    if len({p.resolve() for p in (src, dst, key)}) != 3:
        raise ValueError("Paths must be different / 文件路径必须不同")
    hdt.regular_source(src)
    if os.path.lexists(dst):
        raise FileExistsError("Output already exists / 输出文件已存在")
    if not dst.parent.is_dir():
        raise ValueError("Output directory does not exist / 输出目录不存在")
    if mode == "encrypt":
        hdt.suite_memory(setting)
        hdt.check_new_parameters(parts)
        if hdt.normalized(parts) != hdt.normalized(confirmation):
            raise ValueError("Secret confirmation differs / 两次输入的参数不一致")
        if os.path.lexists(key):
            raise FileExistsError("Keyfile already exists / 密钥文件已存在")
        if not key.parent.is_dir():
            raise ValueError("Keyfile directory does not exist / 密钥目录不存在")
    else:
        hdt.normalized(parts)
        hdt.regular_source(key)
        if setting not in (64, 256, 512, 1024):
            raise ValueError("Invalid memory budget")
    return src, dst, key


def run(mode, source, output, keyfile, parts, confirmation, setting, stage=lambda _: None):
    key_created = False
    phase = "prepare"
    try:
        src, dst, key = prepare(mode, source, output, keyfile, parts, confirmation, setting)
        hdt.self_test()
        if mode == "encrypt":
            phase = "key"
            stage("Generating private keyfile / 正在生成高维密钥文件")
            hdt.generate_keyfile(key)
            key_created = True
            phase = "data"
            stage("Deriving keys and encrypting / 正在派生密钥并加密")
            hdt.encrypt(src, dst, key, parts, suite=setting)
            return Result("ok", f"Encrypted / 加密完成\n{dst}\nKeyfile / 密钥文件\n{key}\nBack up the key separately and retain all three secrets. / 请分开备份密钥并妥善保存全部参数。")
        phase = "data"
        stage("Authenticating and decrypting / 正在认证并解密")
        hdt.decrypt(src, dst, key, parts, max_memory_mib=setting)
        return Result("ok", f"Verified and restored / 认证及恢复完成\n{dst}")
    except hdt.PublishedOutputError:
        if phase == "key":
            return Result("warning", f"Keyfile was published; encryption stopped. / 密钥文件已发布，加密已停止。\n{keyfile}\nInspect cleanup or durability before retrying. / 请检查残留及存储状态后重试。")
        return Result("warning", f"Complete output was published, but cleanup or durability is uncertain. / 完整输出已发布，但清理或持久化状态未确认。\n{output}" + (f"\nKeyfile / 密钥文件: {keyfile}" if key_created else ""))
    except Exception as exc:
        # Do not disclose exception messages, parameter values or stack traces.
        if isinstance(exc, hdt.FormatError):
            detail = "Invalid credentials, container, or memory policy / 凭据、容器或内存策略校验失败"
        elif isinstance(exc, FileExistsError):
            detail = "An output already exists / 输出文件已存在，拒绝覆盖"
        elif isinstance(exc, ValueError):
            detail = "Invalid paths or parameters / 路径或参数不合法，请检查确认值"
        elif isinstance(exc, OSError):
            detail = "File operation failed / 文件读写失败，请检查权限、空间及文件系统"
        else:
            detail = "Operation failed; check dependencies and available memory / 操作失败，请检查依赖和可用内存"
        if key_created:
            detail += f"\nA keyfile was created and retained; do not assume a ciphertext was produced. / 密钥已生成并保留，不代表密文已生成。\n{keyfile}"
        return Result("error", detail)
