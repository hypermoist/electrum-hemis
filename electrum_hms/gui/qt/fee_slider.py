import threading

from PyQt5.QtGui import QCursor
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QSlider, QToolTip, QComboBox

from electrum_hms.i18n import _


class FeeComboBox(QComboBox):

    def __init__(self, fee_slider):
        QComboBox.__init__(self)
        self.config = fee_slider.config
        self.fee_slider = fee_slider

        # Add only the 'Static' option to be visible
        self.addItem(_('Static'))
        self.setCurrentIndex(0)  # Ensure 'Static' is selected by default

        # Set help message to include only Static
        self.help_msg = _('Static: the fee slider uses static values')

        # Ensure the configuration defaults to static
        self.config.FEE_EST_USE_MEMPOOL = False
        self.config.FEE_EST_DYNAMIC = False

        # Hide other options, but keep their logic for future use
        self.fee_types = ['Static', 'ETA', 'Mempool']

    def on_fee_type(self, x):
        # Always use Static
        self.config.FEE_EST_USE_MEMPOOL = False
        self.config.FEE_EST_DYNAMIC = False
        self.fee_slider.update()
class FeeSlider(QSlider):

    def __init__(self, window, config, callback):
        QSlider.__init__(self, Qt.Horizontal)
        self.config = config
        self.window = window
        self.callback = callback
        self.lock = threading.RLock()
        self.update()
        self.valueChanged.connect(self.moved)
        self._active = True

    def get_fee_rate(self, pos):
        fee_rate = self.config.static_fee(pos)
        return fee_rate

    def moved(self, pos):
        with self.lock:
            fee_rate = self.get_fee_rate(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            QToolTip.showText(QCursor.pos(), tooltip, self)
            self.setToolTip(tooltip)
            self.callback(False, pos, fee_rate)  # dyn is always False

    def get_tooltip(self, pos, fee_rate):
        target, estimate = self.config.get_fee_text(pos, False, False, fee_rate)
        return _('Fixed rate') + ': ' + target + '\n' + _('Estimate') + ': ' + estimate

    def update(self):
        with self.lock:
            maxp, pos, fee_rate = self.config.get_fee_slider(False, False)
            self.setRange(0, maxp)
            self.setValue(pos)
            tooltip = self.get_tooltip(pos, fee_rate)
            self.setToolTip(tooltip)

    def activate(self):
        self._active = True
        self.setStyleSheet('')

    def deactivate(self):
        self._active = False
        self.setStyleSheet(
            """
            QSlider::groove:horizontal {
                border: 1px solid #999999;
                height: 8px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #B1B1B1, stop:1 #B1B1B1);
                margin: 2px 0;
            }

            QSlider::handle:horizontal {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #b4b4b4, stop:1 #8f8f8f);
                border: 1px solid #5c5c5c;
                width: 12px;
                margin: -2px 0;
                border-radius: 3px;
            }
            """
        )

    def is_active(self):
        return self._active

    def get_dynfee_target(self):
        pass  # Placeholder function to avoid AttributeError
