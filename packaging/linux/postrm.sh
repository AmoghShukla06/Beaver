#!/bin/sh
# Beaver deb post-remove. Only on a real removal (dpkg passes "upgrade" when a newer version replaces this one).
case "$1" in
  remove|purge)
    # Beaver's firewall rules are runtime nftables tables named beaver_<hash>; remove them now
    # instead of leaving them active until the next reboot.
    if command -v nft >/dev/null 2>&1; then
      nft list tables 2>/dev/null | awk '$1 == "table" && $3 ~ /^beaver_/ {print $2, $3}' |
        while read -r family table; do nft delete table "$family" "$table" || true; done
    fi
    # Sign-in autostart entries would point at the removed binary.
    for entry in /home/*/.config/autostart/Beaver.desktop /home/*/.config/autostart/beaver.desktop /root/.config/autostart/Beaver.desktop; do
      [ -f "$entry" ] && rm -f "$entry"
    done
    # User history stays in each user's ~/.config/Beaver (Debian policy: packages don't delete
    # home data). Use Settings > About > Delete data in Beaver before uninstalling to remove it.
    ;;
esac
exit 0
