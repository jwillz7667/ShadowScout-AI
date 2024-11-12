import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from .main_window import MainWindow
import os

def run():
    app = QApplication(sys.argv)
    
    # Set app icon if available
    icon_path = os.path.join(os.path.dirname(__file__), '../docs/assets/images/logo.png')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 