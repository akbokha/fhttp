# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import sys
import webbrowser

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QMessageBox

# Directories (paths)
script_dir = os.path.dirname(os.path.realpath(__file__))
media_dir = script_dir + os.path.sep + 'media'

__authors__ = "\n".join(['Abdel K. Bokharouss',
                         'Adriaan Knapen'])


class Main(QMainWindow):

    def __init__(self):
        super(Main, self).__init__()
        self.initUI()
        self.initMenu()

    def initUI(self):
        screen = app.primaryScreen()
        screen_size = screen.size()
        width = screen_size.width() / 2
        height = screen_size.height() / 2
        x_start = screen_size.width() / 4
        y_start = screen_size.height() / 4
        self.setGeometry(x_start, y_start, width, height)
        self.setWindowTitle('fhttp')
        self.setWindowIcon(QIcon(media_dir + os.path.sep + 'fhttp_logo.png'))

    def initMenu(self):
        main_bar = self.menuBar()
        help_menu = main_bar.addMenu('Help')

        aboutAction = QAction('About', self)
        aboutAction.setShortcut('Ctrl+A')
        aboutAction.triggered.connect(self.aboutCall)
        help_menu.addAction(aboutAction)

        supportAction = QAction('Support and Documentation', self)
        supportAction.setShortcut('Ctrl+S')
        supportAction.triggered.connect(self.SupportDocumentationCall)
        help_menu.addAction(supportAction)

    def aboutCall(self):
        QMessageBox.about(self, "About", "Lorem ipsum dolor sit amet, "
                                         "consectetur adipiscing elit,"
                                         " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n\n"
                                         "Abdel K. Bokharouss and Adriaan Knapen \n")

    def SupportDocumentationCall(self):
        webbrowser.open('https://github.com/akbokha/fhttp')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = Main()
    main.show()
    sys.exit(app.exec_())
