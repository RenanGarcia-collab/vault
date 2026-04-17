import os
import time
import hashlib
import re
import socket
from datetime import datetime
from pathlib import Path
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
from config import BACKUP_ROOT
from utils import now_date, now_time

MIN_BACKUP_BYTES = 800
MIN_BACKUP_BYTES_BY_VENDOR = {
    "mikrotik": 200,
}
SHELL_WIDTH = 512
SHELL_HEIGHT = 4000

MIKROTIK_LEGACY_KEX = (
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)
MIKROTIK_LEGACY_KEYS = ("ssh-dss", "ssh-rsa")
MIKROTIK_LEGACY_CIPHERS = (
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
)
MIKROTIK_LEGACY_MACS = ("hmac-sha1", "hmac-md5")

VENDOR_COMMANDS = {
    "huawei": {
        "pre": [],
        "cmd": "display current-configuration",
        "prompt": ">",
        "prompt_after": "#",
        "read_mode": "shell",
        "sleep": 0,
        "prompt_optional": True,
        "idle_timeout": 5,
        "pagination_limit": 500,
        "pagination_key": "\n",
    },
    "cisco": {
        "pre": ["terminal length 0"],
        "cmd": "show running-config",
        "prompt": "#",
        "read_mode": "shell",
        "sleep": 0,
        "pagination_limit": 500,
    },
    "datacom": {
        "pre": ["terminal length 0"],
        "cmd": "show running-config | nomore",
        "prompt": "#",
        "read_mode": "shell",
        "sleep": 6,
        "pagination_limit": 500,
        "pagination_key": " ",
    },
    "juniper": {
        "pre": [],
        "cmd": "show configuration | display set | no-more",
        "prompt": None,
        "read_mode": "exec",
        "sleep": 0,
    },
    "mikrotik": {
        "pre": [],
        "cmd": "/export",
        "cmds": [
            "/export terse show-sensitive",
            "/export terse",
            "/export show-sensitive",
            "/export",
        ],
        "prompt": None,
        "read_mode": "exec",
        "sleep": 0,
    },
}


def _read_until(channel, prompt: str, timeout: int = 120, idle_timeout: int = 3, require_prompt: bool = True):
    buffer = ""
    channel.settimeout(2)
    start = time.time()
    last_data = time.time()
    while True:
        now = time.time()
        if now - start > timeout:
            break
        try:
            if channel.recv_ready():
                data = channel.recv(4096).decode("utf-8", errors="ignore")
                if data:
                    buffer += data
                    last_data = now
                    if prompt and prompt in buffer:
                        if now - last_data >= idle_timeout:
                            break
                else:
                    time.sleep(0.2)
            else:
                if now - last_data >= idle_timeout and (not require_prompt or not prompt or prompt in buffer):
                    break
                time.sleep(0.2)
        except Exception:
            time.sleep(0.2)
    return buffer


ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")
ANSI_SINGLE_RE = re.compile(r"\x1b[@-Z\\-_]")
BARE_CURSOR_RE = re.compile(r"\[[0-9;?]+[A-Za-z]")
OLT_CONFIRM_RE = re.compile(r"\{[^}]*\}:", re.IGNORECASE)
OLT_MORE_PROMPT = "---- More ( Press 'Q' to break ) ----"
PROMPT_LINE_RE = re.compile(r"^[A-Za-z0-9._()/-]+[>#]$")
HUAWEI_TIMESTAMP_RE = re.compile(r"^\d{4}:\d{2}:\d{2}:\d{2}:\d{2}:\d{2}\b")
HUAWEI_NEW_COMMAND_PREFIXES = (
    "aaa",
    "authentication-scheme",
    "authorization-scheme",
    "accounting-scheme",
    "autosave",
    "board ",
    "commit",
    "dba-profile ",
    "description ",
    "domain ",
    "emu ",
    "ftp ",
    "gem ",
    "gpon ",
    "interface ",
    "ip ",
    "link-aggregation ",
    "monitor ",
    "mpls ",
    "ont ",
    "port ",
    "protocol ",
    "quit",
    "return",
    "router ",
    "service-port ",
    "snmp-agent ",
    "speed ",
    "ssh user ",
    "switch ",
    "sysman ",
    "sysmode",
    "sysname ",
    "system ",
    "tcont ",
    "terminal user name ",
    "tr069-management ",
    "user-vlan ",
    "vlan ",
    "voice-spec ",
    "xpon ",
)
HUAWEI_SPLIT_PREFIXES = (
    "terminal user name buildrun_new_password ",
    "terminal user name history_password ",
    "system modify ",
    "system user ",
    "ftp set ",
    "ssh client ",
    "ssh user ",
    "xpon ",
    "dba-profile add ",
    "ont-srvprofile ",
    "ont-lineprofile ",
    "ont-port ",
    "ont add ",
    "ont tr069-server-config ",
    "port vlan ",
    "gem add ",
    "gem mapping ",
    "omcc ",
    "tcont ",
    "commit",
    "quit",
    "monitor ",
    "time ",
    "sysman ",
    "snmp-agent ",
    "auto-neg ",
    "speed ",
)
HUAWEI_SECTION_PATTERNS = {
    "global-config": [
        r"terminal user name buildrun_new_password\b",
        r"terminal user name history_password\b",
        r"system modify\b",
        r"system user\b",
        r"ftp set\b",
        r"ssh client\b",
        r"ssh user\b",
        r"xpon\b",
        r"dba-profile add\b",
        r"ont-srvprofile\b",
        r"ont-port\b",
        r"port vlan\b",
        r"ont-lineprofile\b",
        r"omcc\b",
        r"tcont\b",
        r"gem add\b",
        r"gem mapping\b",
        r"commit\b",
        r"quit\b",
    ],
    "public-config": [
        r"monitor uplink-port traffic port\b",
        r"time date-format\b",
        r"sysman\b",
        r"snmp-agent\b",
    ],
    "mpu": [
        r"interface mpu\b",
        r"auto-neg\b",
        r"speed\b",
    ],
    "gpon": [
        r"interface gpon\b",
        r"port \d+ ont-auto-find enable\b",
        r"ont add\b",
        r"ont port native-vlan\b",
    ],
    "bbs-config": [
        r"link-aggregation\b",
        r"service-port\b",
    ],
}


def _open_shell(client, log_cb=None, label: str = "Shell"):
    channel = client.invoke_shell(width=SHELL_WIDTH, height=SHELL_HEIGHT)
    try:
        channel.resize_pty(width=SHELL_WIDTH, height=SHELL_HEIGHT)
    except Exception:
        pass
    _log(log_cb, f"{label} opened (pty={SHELL_WIDTH}x{SHELL_HEIGHT})")
    return channel


def _mikrotik_legacy_transport_factory(*args, **kwargs):
    transport = paramiko.Transport(*args, **kwargs)
    opts = transport.get_security_options()
    opts.kex = MIKROTIK_LEGACY_KEX
    opts.key_types = MIKROTIK_LEGACY_KEYS
    opts.ciphers = MIKROTIK_LEGACY_CIPHERS
    opts.digests = MIKROTIK_LEGACY_MACS
    return transport


def _is_mikrotik_negotiation_error(exc: Exception) -> bool:
    if isinstance(exc, SSHException):
        return True
    text = str(exc).lower()
    markers = (
        "negotiation failed",
        "incompatible ssh peer",
        "key exchange",
        "no acceptable",
    )
    return any(marker in text for marker in markers)


def _tail_line(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else "(vazio)"


def _read_until_any(channel, prompts, timeout: int = 120, idle_timeout: int = 3):
    buffer = ""
    channel.settimeout(2)
    start = time.time()
    last_data = time.time()
    prompts = [prompt for prompt in prompts if prompt]
    while True:
        now = time.time()
        if now - start > timeout:
            break
        try:
            if channel.recv_ready():
                data = channel.recv(4096).decode("utf-8", errors="ignore")
                if data:
                    buffer += data
                    last_data = now
                    if any(prompt in buffer for prompt in prompts) and now - last_data >= idle_timeout:
                        break
                else:
                    time.sleep(0.2)
            else:
                if now - last_data >= idle_timeout and any(prompt in buffer for prompt in prompts):
                    break
                time.sleep(0.2)
        except Exception:
            time.sleep(0.2)
    matched = next((prompt for prompt in prompts if prompt in buffer), None)
    return buffer, matched


def _clean_terminal_output(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r", "")
    text = text.replace("\x08", "")
    text = ANSI_CSI_RE.sub("", text)
    text = ANSI_OSC_RE.sub("", text)
    text = ANSI_SINGLE_RE.sub("", text)
    text = BARE_CURSOR_RE.sub("", text)
    text = "".join(ch for ch in text if ch in "\n\t" or ch >= " ")
    text = OLT_CONFIRM_RE.sub("", text)
    for marker in (
        OLT_MORE_PROMPT,
        "---- More ----",
        "--More--",
        "<more>",
    ):
        text = text.replace(marker, "")
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if len(line) - len(line.lstrip(" ")) >= 20 and stripped:
            line = stripped
        if "---- More" in line:
            continue
        if stripped in ("--More--", "<more>"):
            continue
        if stripped in (
            "Keyboard-interactive authentication prompts from server:",
            "End of keyboard-interactive prompts from server",
        ):
            continue
        if any(s in line for s in ("MobaXterm", "SSH session to", "X11-forwarding", "DISPLAY")):
            continue
        if stripped.startswith(("┌", "┐", "└", "┘", "│", "─")):
            continue
        if "Huawei Integrated Access Software" in line:
            continue
        if "Copyright(C) Huawei Technologies" in line:
            continue
        if "User last login information" in line:
            continue
        if stripped.startswith("Access Type") or stripped.startswith("IP-Address") or stripped.startswith("Login  Time") or stripped.startswith("Logout Time"):
            continue
        if stripped and set(stripped) == {"-"}:
            continue
        if stripped == "Command:" or stripped == "display current-configuration":
            continue
        if stripped.startswith("{") and "}" in stripped and ":" in stripped:
            continue
        if ">enable" in stripped or "#display current-configuration" in stripped:
            continue
        if PROMPT_LINE_RE.fullmatch(stripped or ""):
            continue
        lines.append(line)
    cleaned = "\n".join(lines)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip() + "\n"


def _looks_like_huawei_new_command(line: str) -> bool:
    stripped = (line or "").strip()
    if not stripped:
        return False
    if stripped.startswith(("#", "[", "<")):
        return True
    return any(stripped.startswith(prefix) for prefix in HUAWEI_NEW_COMMAND_PREFIXES)


def _split_huawei_compound_line(line: str):
    pieces = [line.rstrip()]
    for prefix in HUAWEI_SPLIT_PREFIXES:
        updated = []
        token = f" {prefix}"
        for piece in pieces:
            stripped = piece.lstrip()
            indent = piece[: len(piece) - len(stripped)]
            if not stripped.startswith(prefix) and token not in piece:
                updated.append(piece)
                continue
            segments = []
            if stripped.startswith(prefix):
                segments.append(stripped)
            else:
                first, *rest = piece.split(token)
                segments.append(first.strip())
                segments.extend((prefix + chunk).strip() for chunk in rest if chunk.strip())
            if stripped.startswith(prefix):
                first, *rest = stripped.split(token)
                segments = [first.strip()]
                segments.extend((prefix + chunk).strip() for chunk in rest if chunk.strip())
            updated.extend((indent + segment).rstrip() for segment in segments if segment.strip())
        pieces = updated
    return [piece for piece in pieces if piece.strip()]


def _format_huawei_section_lines(section_name: str, lines):
    patterns = HUAWEI_SECTION_PATTERNS.get(section_name or "")
    if not patterns:
        return [line.rstrip() for line in lines]
    flat = re.sub(r"\s+", " ", " ".join(line.strip() for line in lines if line.strip())).strip()
    if not flat:
        return []
    splitter = re.compile(r"\s+(?=(?:" + "|".join(patterns) + r"))")
    parts = [part.strip() for part in splitter.split(flat) if part.strip()]
    formatted = []
    for part in parts:
        if section_name == "bbs-config" and part.startswith("service-port "):
            part = re.sub(r"\s+tag-transform\s+translate\b", " tag-transform translate", part)
        formatted.append(" " + part)
    return formatted


def _should_join_huawei_line(previous: str, current: str) -> bool:
    prev = (previous or "").rstrip()
    cur = (current or "").strip()
    if not prev or not cur:
        return False
    if prev.strip() in {"#", "quit", "return", "commit"}:
        return False
    if cur.startswith(("#", "[", "<")):
        return False

    prev_body = prev.lstrip()
    if prev_body.startswith("service-port ") and cur.startswith("tag-transform "):
        return True
    if prev_body.startswith("ont add ") and cur.startswith("ont-srvprofile-id "):
        return True
    if prev_body.startswith("terminal user name ") and (
        cur.startswith("first-login-info ")
        or cur.startswith("root ")
        or cur.startswith("admin ")
        or HUAWEI_TIMESTAMP_RE.match(cur)
        or not _looks_like_huawei_new_command(cur)
    ):
        return True
    if prev_body.startswith(("terminal user name history_password ", "ftp set ", "ont tr069-server-profile add ", "snmp-agent community ")):
        if not _looks_like_huawei_new_command(cur):
            return True
    if (
        prev_body.startswith((
            "terminal user name buildrun_new_password ",
            "terminal user name history_password ",
            "ont add ",
            "service-port ",
        ))
        and not _looks_like_huawei_new_command(cur)
    ):
        return True
    if prev.count('"') % 2 == 1:
        return True
    if prev.rstrip().endswith(("[", "(", "{", ",", "$", "%", ":", "-", "/", "\\")):
        return True
    return False


def normalize_huawei_output(text: str) -> str:
    if not text:
        return ""
    output = []
    section_name = None
    buffer = []

    def flush_buffer():
        nonlocal buffer
        if not buffer:
            return
        output.extend(_format_huawei_section_lines(section_name, buffer))
        buffer = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        section_match = re.fullmatch(r"\[([^\]]+)\]", stripped)
        if section_match:
            flush_buffer()
            section_name = section_match.group(1)
            output.append(line)
            continue
        if stripped.startswith("<") and stripped.endswith(">"):
            flush_buffer()
            output.append(line)
            continue
        if stripped == "#" or not stripped:
            flush_buffer()
            output.append(line)
            continue
        buffer.append(line)
    flush_buffer()
    return "\n".join(output).strip() + "\n"


def min_backup_bytes(vendor: str) -> int:
    if not vendor:
        return MIN_BACKUP_BYTES
    return MIN_BACKUP_BYTES_BY_VENDOR.get(vendor.lower(), MIN_BACKUP_BYTES)


def _prompt_at_end(text: str, prompt: str) -> bool:
    if not prompt:
        return False
    tail = text[-200:]
    tail = ANSI_CSI_RE.sub("", tail)
    return tail.rstrip().endswith(prompt)


def _read_olt_output(channel, prompt: str, timeout: int, log_cb=None):
    buffer = ""
    output = ""
    channel.settimeout(2)
    start = time.time()
    last_data = time.time()
    confirmed = False
    page_count = 0
    while True:
        now = time.time()
        if now - start > timeout:
            _log(log_cb, f"OLT: timeout while reading output (prompt={prompt})")
            break
        try:
            if channel.recv_ready():
                data = channel.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    time.sleep(0.1)
                    continue
                buffer += data
                last_data = now
                if (not confirmed) and OLT_CONFIRM_RE.search(buffer):
                    _log(log_cb, "OLT: confirm prompt -> ENTER")
                    buffer = OLT_CONFIRM_RE.sub("", buffer)
                    channel.send("\n")
                    confirmed = True
                if OLT_MORE_PROMPT in buffer:
                    while OLT_MORE_PROMPT in buffer:
                        buffer = buffer.replace(OLT_MORE_PROMPT, "")
                        channel.send(" ")
                        page_count += 1
                    _log(log_cb, f"OLT: pagination -> SPACE ({page_count})")
                if _prompt_at_end(buffer, prompt):
                    output += buffer
                    buffer = ""
                    if now - last_data >= 1.5:
                        break
                elif len(buffer) > 16384:
                    output += buffer
                    buffer = ""
            else:
                if now - last_data >= 2:
                    if _prompt_at_end(output + buffer, prompt):
                        output += buffer
                        buffer = ""
                        break
                time.sleep(0.2)
        except Exception:
            time.sleep(0.2)
    output += buffer
    _log(log_cb, f"OLT: read finished (confirm_sent={'yes' if confirmed else 'no'}, pages={page_count})")
    return output



PAGINATION_PROMPTS = [
    "{ <cr>||<K> }:",
    "{ <cr>",
    "---- More ----",
    "---- More ( Press 'Q' to break ) ----",
    "--More--",
    "<more>",
    "<cr>",
]




def _exec_with_fallback(client, cmds):
    last_output = ""
    for cmd in cmds:
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        combined = (out + "\n" + err).strip()
        last_output = combined
        # Mikrotik error patterns
        if "expected end of command" in combined or "bad command" in combined:
            continue
        if combined:
            return combined
    return last_output

def _log(log_cb, msg):
    if log_cb:
        log_cb(msg)


def _huawei_profile(device, cmd_cfg_override, banner_text: str = ""):
    if cmd_cfg_override and cmd_cfg_override.get("profile"):
        return cmd_cfg_override.get("profile")
    name = None
    if hasattr(device, "get"):
        name = device.get("name")
    else:
        try:
            name = device["name"]
        except Exception:
            name = None
    name_l = (name or "").lower()
    banner_l = (banner_text or "").lower()
    if "olt" in name_l:
        return "olt"
    if "ma5800" in banner_l or "ma5608" in banner_l or "olt" in banner_l:
        return "olt"
    return "switch"


def _run_huawei_olt_backup(client, password: str, log_cb=None, base_timeout: int = 180, channel=None, banner: str = ""):
    if channel is None:
        channel = _open_shell(client, log_cb=log_cb, label="OLT shell")
        banner = ""
    else:
        _log(log_cb, "OLT: using pre-opened shell")
    _log(log_cb, "OLT: waiting for initial prompt ('>' or '#')")
    if not banner or (">" not in banner and "#" not in banner):
        banner, initial_prompt = _read_until_any(
            channel,
            [">", "#"],
            timeout=min(60, base_timeout),
            idle_timeout=2,
        )
    else:
        initial_prompt = "#" if "#" in banner else ">"
    if initial_prompt not in (">", "#"):
        reason = _tail_line(banner)
        _log(log_cb, f"OLT: initial prompt not found ({reason})")
        raise ValueError(f"OLT: prompt inicial não encontrado. Última linha: {reason}")
    _log(log_cb, f"OLT: initial prompt ok ({initial_prompt})")

    en_out = banner
    if initial_prompt != "#":
        _log(log_cb, "OLT: sending enable")
        channel.send("enable\n")
        en_out = _read_until(channel, "#", timeout=20, idle_timeout=2, require_prompt=False)
        if "password" in en_out.lower() or "senha" in en_out.lower():
            _log(log_cb, "OLT: enable password requested")
            channel.send(password + "\n")
            en_out += _read_until(channel, "#", timeout=20, idle_timeout=2, require_prompt=True)
        if "#" not in en_out:
            last_line = _tail_line(en_out)
            _log(log_cb, f"OLT: enable failed ({last_line})")
            raise ValueError(f"Enable falhou. Prompt atual: {last_line}")
    else:
        _log(log_cb, "OLT: already in privileged prompt")
    prompt = None
    for line in reversed(en_out.splitlines()):
        line = line.strip()
        if line.endswith("#") and len(line) > 1:
            prompt = line
            break
    if not prompt:
        prompt = "#"
    _log(log_cb, f"OLT: enable ok (prompt={prompt})")

    cmd = "display current-configuration"
    _log(log_cb, f"OLT: sending command: {cmd}")
    channel.send(cmd + "\n")
    output = _read_olt_output(channel, prompt, timeout=base_timeout, log_cb=log_cb)
    if not _prompt_at_end(output, prompt):
        _log(log_cb, f"OLT: prompt final '{prompt}' não encontrado")
        raise ValueError(f"OLT: prompt final '{prompt}' não encontrado")
    _log(log_cb, f"OLT: output bytes: {len(output)}")
    return output


def _run_huawei_switch_backup(channel, cmd_cfg, password: str, log_cb=None, base_timeout: int = 180, cmd: str = ""):
    current_prompt = cmd_cfg.get("prompt") or ">"
    _log(log_cb, f"Waiting prompt: {current_prompt}")
    banner = _read_until(channel, current_prompt, timeout=min(120, base_timeout), idle_timeout=2, require_prompt=True)
    _log(log_cb, f"Prompt ready (bytes={len(banner)})")
    pre_list = cmd_cfg.get("pre") or []
    if not pre_list:
        _log(log_cb, "Huawei: no pre-commands")
    for pre in pre_list:
        _log(log_cb, f"PRE: {pre}")
        channel.send(pre + "\n")
        pre_out = _read_until(channel, current_prompt, timeout=min(60, base_timeout), idle_timeout=2, require_prompt=True)
        _log(log_cb, f"PRE done (bytes={len(pre_out)})")
    cmd = cmd or "display current-configuration"
    _log(log_cb, f"CMD: {cmd}")
    channel.send(cmd + "\n")
    if cmd_cfg.get("sleep"):
        time.sleep(cmd_cfg["sleep"])
    idle_timeout = cmd_cfg.get("idle_timeout", 3)
    require_prompt = not cmd_cfg.get("prompt_optional", False)
    output = _read_until(
        channel,
        current_prompt,
        timeout=base_timeout,
        idle_timeout=idle_timeout,
        require_prompt=require_prompt,
    )
    _log(log_cb, f"Output bytes: {len(output)}")
    page_limit = cmd_cfg.get("pagination_limit", 500)
    page_key = cmd_cfg.get("pagination_key", " ")
    pages = 0
    last_chunk = output
    for _ in range(page_limit):
        if any(p in last_chunk for p in PAGINATION_PROMPTS):
            channel.send(page_key)
            last_chunk = _read_until(
                channel,
                current_prompt,
                timeout=120,
                idle_timeout=idle_timeout,
                require_prompt=require_prompt,
            )
            output += last_chunk
            pages += 1
        else:
            break
    if pages:
        _log(log_cb, f"Pagination pages: {pages}")
    return output


def _merge_cmd_cfg(base_cfg, override_cfg):
    if not override_cfg:
        return base_cfg
    merged = dict(base_cfg)
    for k, v in override_cfg.items():
        if v is None:
            continue
        if isinstance(v, str) and v == "":
            continue
        if isinstance(v, (list, tuple, dict)) and len(v) == 0:
            continue
        if k == "pre" and isinstance(v, (list, tuple)):
            base_pre = merged.get("pre") or []
            merged[k] = list(v) + list(base_pre)
        else:
            merged[k] = v
    return merged


def _detect_firmware(output: str, vendor: str):
    if not output:
        return None
    for line in output.splitlines():
        if "JUNOS" in line:
            return line.strip()
        if "MA5800" in line or "MA5608" in line:
            return line.strip()
        if "Version" in line or "version" in line:
            return line.strip()
    return None


def _validate_output(output: str, vendor: str):
    text = (output or "").lower()
    if vendor == "huawei":
        if "sysname" in text and "interface" in text:
            return True, None
        return False, "Huawei inválido (faltando sysname/interface)"
    if vendor == "mikrotik":
        if "/interface" in text or "/ip" in text:
            return True, None
        return False, "Mikrotik inválido (faltando /interface ou /ip)"
    if vendor == "cisco":
        if "hostname" in text and "interface" in text:
            return True, None
        return False, "Cisco inválido (faltando hostname/interface)"
    return True, None


def run_backup(device, username: str, password: str, command_override=None, cmd_cfg_override=None, log_cb=None):
    vendor = device["vendor"].lower()
    cmd_cfg = VENDOR_COMMANDS.get(vendor, None)
    if cmd_cfg is None:
        raise ValueError(f"Vendor not supported: {vendor}")

    cmd_cfg = _merge_cmd_cfg(cmd_cfg, cmd_cfg_override)
    cmd = command_override or cmd_cfg["cmd"]
    profile = _huawei_profile(device, cmd_cfg_override) if vendor == "huawei" else None

    def _connect_client():
        def _new_client():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            return client

        def _connect_once(client, use_legacy: bool = False):
            connect_kwargs = {
                "port": int(device["port"]),
                "username": username,
                "password": password,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
            }
            if use_legacy:
                connect_kwargs["transport_factory"] = _mikrotik_legacy_transport_factory
            client.connect(device["ipaddr"], **connect_kwargs)

        _log(log_cb, f"Connecting to {device['ipaddr']}:{device['port']} as {username}")
        for attempt in range(1, 4):
            client = _new_client()
            try:
                _log(log_cb, f"Connect attempt {attempt}/3")
                _connect_once(client)
                transport = client.get_transport()
                if transport:
                    transport.set_keepalive(30)
                _log(log_cb, "Connected")
                return client
            except Exception as exc:
                client.close()
                if vendor == "mikrotik" and _is_mikrotik_negotiation_error(exc):
                    _log(log_cb, f"Standard SSH negotiation failed: {exc}")
                    legacy_client = _new_client()
                    try:
                        _log(log_cb, "Retrying MikroTik with legacy SSH profile")
                        _connect_once(legacy_client, use_legacy=True)
                        transport = legacy_client.get_transport()
                        if transport:
                            transport.set_keepalive(30)
                        _log(log_cb, "Connected with legacy MikroTik SSH profile")
                        return legacy_client
                    except Exception as legacy_exc:
                        legacy_client.close()
                        exc = legacy_exc
                        _log(log_cb, f"Legacy SSH connection error: {exc}")
                if isinstance(exc, AuthenticationException):
                    _log(log_cb, "Authentication failed")
                    raise ValueError("Falha de autenticação: usuário ou senha inválidos")
                _log(log_cb, f"Connection error: {exc}")
                if attempt < 3:
                    time.sleep(15)
                else:
                    raise ValueError(f"Falha de conexão: {exc}")

    output = ""
    meta = {
        "duration_seconds": 0,
        "line_count": 0,
        "content_hash": None,
        "firmware": None,
        "validation_error": None,
    }
    last_exc = None
    for attempt in range(2):
        client = None
        try:
            client = _connect_client()
            start = time.time()
            base_timeout = cmd_cfg.get("timeout") or 180
            if vendor == "huawei":
                channel = _open_shell(client, log_cb=log_cb)
                banner, initial_prompt = _read_until_any(
                    channel,
                    [">", "#"],
                    timeout=min(120, base_timeout),
                    idle_timeout=2,
                )
                _log(log_cb, f"Prompt ready (bytes={len(banner)}, prompt={initial_prompt or 'none'})")
                profile = _huawei_profile(device, cmd_cfg_override, banner_text=banner)
                if profile == "olt":
                    _log(log_cb, "Huawei profile: olt (deterministic flow)")
                    output = _run_huawei_olt_backup(
                        client,
                        password,
                        log_cb=log_cb,
                        base_timeout=base_timeout,
                        channel=channel,
                        banner=banner,
                    )
                else:
                    _log(log_cb, "Huawei profile: switch")
                    output = _run_huawei_switch_backup(
                        channel,
                        cmd_cfg,
                        password,
                        log_cb=log_cb,
                        base_timeout=base_timeout,
                        cmd=cmd,
                    )
            else:
                auto_exec = vendor != "huawei"
                if auto_exec:
                    cmds = cmd_cfg.get("cmds") or [cmd]
                    _log(log_cb, "Auto mode: try exec_command")
                    _log(log_cb, f"Commands: {cmds}")
                    output = _exec_with_fallback(client, cmds)
                if (not auto_exec) or (not output or "Unknown command" in output or "syntax error" in output):
                    if auto_exec:
                        _log(log_cb, "Exec returned empty/invalid. Falling back to shell.")
                    channel = _open_shell(client, log_cb=log_cb)
                    current_prompt = cmd_cfg.get("prompt")
                    prompt_after = cmd_cfg.get("prompt_after")
                    _log(log_cb, f"Waiting prompt: {current_prompt or '(none)'}")
                    banner = _read_until(channel, current_prompt, timeout=min(120, base_timeout), idle_timeout=2, require_prompt=True)
                    _log(log_cb, f"Prompt ready (bytes={len(banner)})")
                    for pre in cmd_cfg["pre"]:
                        _log(log_cb, f"PRE: {pre}")
                        channel.send(pre + "\n")
                        if pre.strip().lower() == "enable" and prompt_after:
                            current_prompt = prompt_after
                            _log(log_cb, f"Prompt switched to: {current_prompt}")
                        pre_out = _read_until(channel, current_prompt, timeout=min(60, base_timeout), idle_timeout=2, require_prompt=True)
                        if pre.strip().lower() == "enable":
                            if "password" in pre_out.lower():
                                _log(log_cb, "Enable password requested")
                                channel.send(password + "\n")
                                pre_out += _read_until(channel, current_prompt, timeout=min(60, base_timeout), idle_timeout=2, require_prompt=True)
                            if prompt_after and ("#" not in pre_out):
                                _log(log_cb, "Enable did not reach # prompt")
                        _log(log_cb, f"PRE done (bytes={len(pre_out)})")
                    _log(log_cb, f"CMD: {cmd}")
                    channel.send(cmd + "\n")
                    if cmd_cfg["sleep"]:
                        time.sleep(cmd_cfg["sleep"])
                    idle_timeout = cmd_cfg.get("idle_timeout", 3)
                    require_prompt = not cmd_cfg.get("prompt_optional", False)
                    output = _read_until(
                        channel,
                        current_prompt,
                        timeout=base_timeout,
                        idle_timeout=idle_timeout,
                        require_prompt=require_prompt,
                    )
                    _log(log_cb, f"Output bytes: {len(output)}")
                    page_limit = cmd_cfg.get("pagination_limit", 500)
                    page_key = cmd_cfg.get("pagination_key", " ")
                    pages = 0
                    last_chunk = output
                    for _ in range(page_limit):
                        if any(p in last_chunk for p in PAGINATION_PROMPTS):
                            channel.send(page_key)
                            last_chunk = _read_until(
                                channel,
                                current_prompt,
                                timeout=120,
                                idle_timeout=idle_timeout,
                                require_prompt=require_prompt,
                            )
                            output += last_chunk
                            pages += 1
                        else:
                            break
                    if pages:
                        _log(log_cb, f"Pagination pages: {pages}")
            output = _clean_terminal_output(output)
            meta["duration_seconds"] = int(time.time() - start)
            meta["line_count"] = len((output or "").splitlines())
            if output:
                meta["content_hash"] = hashlib.md5(output.encode("utf-8", errors="ignore")).hexdigest()
            meta["firmware"] = _detect_firmware(output, vendor)
            valid, reason = _validate_output(output, vendor)
            if not valid:
                meta["validation_error"] = reason
                _log(log_cb, f"Validation failed: {reason}")
            return output, meta
        except (OSError, socket.error) as exc:
            last_exc = exc
            msg = str(exc)
            _log(log_cb, f"Socket error: {msg}")
            if attempt == 0 and ("Socket is closed" in msg or "Connection reset by peer" in msg):
                _log(log_cb, "Retrying after socket error...")
                time.sleep(2)
                continue
            raise
        except Exception as exc:
            last_exc = exc
            _log(log_cb, f"Backup failed: {exc}")
            raise
        finally:
            if client:
                client.close()

    if last_exc:
        raise last_exc
    return output, meta


def save_backup(device, content: str):
    vendor = device["vendor"].lower()
    slug = device["slug"]
    base_dir = Path(BACKUP_ROOT) / vendor / slug
    date_dir = base_dir / now_date()
    base_dir.mkdir(parents=True, exist_ok=True)
    time_dir = date_dir / now_time()
    suffix = 0
    while time_dir.exists():
        suffix += 1
        time_dir = date_dir / f"{now_time()}-{suffix:02d}"
    time_dir.mkdir(parents=True, exist_ok=False)

    file_path = time_dir / "config.txt"
    file_path.write_text(content, encoding="utf-8", errors="ignore")

    latest_link = base_dir / "latest.txt"
    previous_link = base_dir / "previous.txt"

    def _replace_symlink(link_path: Path, target: Path):
        tmp_link = link_path.with_name(f".{link_path.name}.tmp-{os.getpid()}-{time.time_ns()}")
        if tmp_link.exists() or tmp_link.is_symlink():
            tmp_link.unlink()
        tmp_link.symlink_to(target)
        os.replace(tmp_link, link_path)

    if latest_link.exists() or latest_link.is_symlink():
        latest_target = None
        try:
            resolved = latest_link.resolve(strict=False)
            if resolved.exists():
                latest_target = resolved
        except Exception:
            latest_target = None
        if previous_link.exists() or previous_link.is_symlink():
            previous_link.unlink()
        if latest_target:
            _replace_symlink(previous_link, latest_target)
    _replace_symlink(latest_link, file_path)

    return str(file_path), file_path.stat().st_size


def prune_backups(device, keep_last: int):
    if not keep_last or keep_last <= 0:
        return []
    vendor = device["vendor"].lower()
    slug = device["slug"]
    base_dir = Path(BACKUP_ROOT) / vendor / slug
    if not base_dir.exists():
        return []

    files = []
    for date_dir in base_dir.glob("*/"):
        if not date_dir.is_dir():
            continue
        for time_dir in date_dir.glob("*/"):
            file_path = time_dir / "config.txt"
            if file_path.exists():
                stat = file_path.stat()
                files.append((stat.st_mtime, file_path))

    files.sort(key=lambda x: x[0], reverse=True)
    to_delete = [p for _, p in files[keep_last:]]
    removed = []
    for path in to_delete:
        try:
            path.unlink()
            removed.append(str(path))
        except Exception:
            continue
        parent = path.parent
        try:
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
        except Exception:
            pass
        try:
            date_dir = parent.parent
            if date_dir.exists() and not any(date_dir.iterdir()):
                date_dir.rmdir()
        except Exception:
            pass

    # refresh latest/previous links after pruning
    remaining = [p for _, p in files[:keep_last] if p.exists()]
    latest_link = base_dir / "latest.txt"
    previous_link = base_dir / "previous.txt"
    for link in (latest_link, previous_link):
        if link.exists() or link.is_symlink():
            try:
                link.unlink()
            except Exception:
                pass
    if remaining:
        latest_link.symlink_to(remaining[0])
    if len(remaining) > 1:
        previous_link.symlink_to(remaining[1])

    return removed


def ensure_device_dir(device):
    vendor = device["vendor"].lower()
    slug = device["slug"]
    base_dir = Path(BACKUP_ROOT) / vendor / slug
    base_dir.mkdir(parents=True, exist_ok=True)
    return str(base_dir)


def list_backups(device):
    vendor = device["vendor"].lower()
    slug = device["slug"]
    base_dir = Path(BACKUP_ROOT) / vendor / slug
    if not base_dir.exists():
        return []

    backups = []
    for date_dir in sorted(base_dir.glob("*/")):
        if not date_dir.is_dir():
            continue
        for time_dir in sorted(date_dir.glob("*/")):
            file_path = time_dir / "config.txt"
            if file_path.exists():
                stat = file_path.stat()
                dt = datetime.fromtimestamp(stat.st_mtime)
                size = stat.st_size
                backups.append({
                    "path": str(file_path),
                    "date": dt.strftime("%Y-%m-%d"),
                    "time": dt.strftime("%H%M%S"),
                    "size": size,
                    "short": size < min_backup_bytes(vendor),
                })

    return sorted(backups, key=lambda x: x["path"], reverse=True)
