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
