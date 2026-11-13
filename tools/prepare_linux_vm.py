"""Boot an owned, headless verification VM without Windows admin or WSL changes."""

import json
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / ".websec-local/linux-verification"


def main():
    VM.mkdir(parents=True, exist_ok=True)
    seed = VM / "seed"
    seed.mkdir(exist_ok=True)
    key = VM / "ssh-key"
    if not key.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
            capture_output=True,
        )
    public = key.with_suffix(".pub").read_text().strip()
    cloud = {
        "hostname": "websec-verification",
        "disable_root": False,
        "users": ["default"],
        "ssh_authorized_keys": [public],
        "packages": ["docker", "docker-cli-compose", "curl", "python3"],
        "runcmd": [
            ["rc-update", "add", "docker", "default"],
            ["rc-service", "docker", "start"],
            ["addgroup", "alpine", "docker"],
        ],
    }
    (seed / "user-data").write_text("#cloud-config\n" + yaml.safe_dump(cloud), encoding="utf-8")
    (seed / "meta-data").write_text(
        "instance-id: websec-owned-verification-v3\nlocal-hostname: websec-verification\n",
        encoding="utf-8",
    )
    qemu = VM / "qemu"
    if not (VM / "alpine.sha512").is_file():
        raise RuntimeError("Wait for the image download and checksum verification to finish")
    overlay = VM / "verification-v3.qcow2"
    if not overlay.exists():
        subprocess.run(
            [
                str(qemu / "qemu-img.exe"),
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                "alpine.qcow2",
                overlay.name,
                "20G",
            ],
            check=True,
            cwd=VM,
        )
    processes = []
    for label, arguments in [
        (
            "vm",
            [
                str(qemu / "qemu-system-x86_64.exe"),
                "-L",
                "qemu/share",
                "-machine",
                "q35,accel=tcg",
                "-smp",
                "2",
                "-m",
                "3072",
                "-drive",
                f"file={overlay.name},if=virtio",
                "-netdev",
                "user,id=n1,hostfwd=tcp:127.0.0.1:2222-:22",
                "-device",
                "virtio-net-pci,netdev=n1",
                "-display",
                "none",
                "-serial",
                "file:serial.log",
                "-monitor",
                "none",
                "-smbios",
                "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:18080/",
            ],
        ),
    ]:
        with (VM / f"{label}.log").open("ab") as log:
            process = subprocess.Popen(
                arguments, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW, cwd=VM
            )
        processes.append({"label": label, "pid": process.pid})
    (VM / "processes.json").write_text(json.dumps(processes, indent=2), encoding="utf-8")
    print(json.dumps(processes))


if __name__ == "__main__":
    main()
