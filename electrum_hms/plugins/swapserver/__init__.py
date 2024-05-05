from electrum_hms.i18n import _

fullname = _('SwapServer')
description = """
Submarine swap server for an Electrum-HMS daemon.

Example setup:

  electrum-hms -o setconfig enable_plugin_swapserver True
  electrum-hms -o setconfig swapserver_port 5455
  electrum-hms daemon -v

"""

available_for = ['cmdline']
