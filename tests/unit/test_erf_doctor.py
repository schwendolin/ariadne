"""``ariadne doctor``: Swap-Prüfung für den Vorlauf im RAM (E95)."""

from __future__ import annotations

from ariadne.cli.doctor import OK, WARN, swap_check

HEAD = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def test_swap_check():
    assert swap_check(HEAD, lambda n: None).level == OK
    assert swap_check(HEAD + "/dev/zram0 partition 4096 0 100\n", lambda n: None).level == OK
    crypt = swap_check(HEAD + "/dev/dm-1 partition 4096 0 -2\n", lambda n: "CRYPT-PLAIN-swap")
    assert crypt.level == OK
    plain = swap_check(HEAD + "/dev/sda5 partition 4096 0 -2\n/dev/dm-2 partition 1 0 -3\n",
                       lambda n: "LVM-abc")
    assert plain.level == WARN and "/dev/sda5" in plain.detail and "/dev/dm-2" in plain.detail


def test_swap_check_follows_lvm_on_luks_and_swap_files():
    """Befund F12: Kali-Standard (LVM auf LUKS) und Swap-Datei auf verschlüsseltem Root."""
    uuids = {"dm-0": "CRYPT-LUKS2-abc-sda5_crypt", "dm-1": "LVM-root", "dm-2": "LVM-swap", "dm-3": "LVM-x"}
    under = {"dm-1": ["dm-0"], "dm-2": ["dm-0"], "dm-3": ["sdb1"]}
    lvm = swap_check(HEAD + "/dev/dm-2 partition 4096 0 -2\n", uuids.get, lambda n: under.get(n, []))
    assert lvm.level == OK
    plain_lvm = swap_check(HEAD + "/dev/dm-3 partition 4096 0 -2\n", uuids.get, lambda n: under.get(n, []))
    assert plain_lvm.level == WARN
    swapfile = HEAD + "/swapfile                               file\t\t4096\t0\t-2\n"
    assert swap_check(swapfile, uuids.get, lambda n: under.get(n, []), lambda p: "dm-1").level == OK
    assert swap_check(swapfile, uuids.get, lambda n: under.get(n, []), lambda p: "sda2").level == WARN
