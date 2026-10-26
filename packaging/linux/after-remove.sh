#!/bin/bash

# Delete the link to the binary
# update-alternatives --remove <name> <path>: 'path' must be the registered alternative binary,
# not the generic symlink — see https://man7.org/linux/man-pages/man1/update-alternatives.1.html
if type update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove '${executable}' '/opt/${sanitizedProductName}/${executable}'
else
    rm -f '/usr/bin/${executable}'
fi

APPARMOR_PROFILE_DEST='/etc/apparmor.d/${executable}'

# Remove and unload apparmor profile.
if [ -f "$APPARMOR_PROFILE_DEST" ]; then
  # Unload the profile from the running kernel before deleting the file so the
  # policy is not left enforced until the next reboot.  Mirror the chroot guard
  # used in the after-install script — live AppArmor operations are not
  # meaningful inside a chroot.
  # https://wiki.debian.org/AppArmor/HowToUse
  if apparmor_status --enabled > /dev/null 2>&1; then
    if ! { [ -x '/usr/bin/ischroot' ] && /usr/bin/ischroot; } && hash apparmor_parser 2>/dev/null; then
      apparmor_parser --remove "$APPARMOR_PROFILE_DEST" || true
    fi
  fi
  rm -f "$APPARMOR_PROFILE_DEST"
fi
# --- Beaver ---------------------------------------------------------------------------------------
# Only on a real removal (dpkg passes "upgrade" when a newer version replaces this one).
case "$1" in
  remove|purge)
    # Beaver's firewall rules are runtime nftables tables named beaver_<hash>; remove them now
    # instead of leaving them active until the next reboot.
    if command -v nft >/dev/null 2>&1; then
      nft list tables 2>/dev/null | awk '$1 == "table" && $3 ~ /^beaver_/ {print $2, $3}' |
        while read -r family table; do nft delete table "$family" "$table" || true; done
    fi
    # Sign-in autostart entries would point at the removed binary.
    for entry in /home/*/.config/autostart/beaver.desktop /root/.config/autostart/beaver.desktop; do
      [ -f "$entry" ] && rm -f "$entry"
    done
    # User history stays in each user's ~/.config folder (Debian policy: packages don't delete
    # home data). Use Settings > About > Delete data in Beaver before uninstalling to remove it.
    ;;
esac
