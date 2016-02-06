"""
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.  """


import sys                                                                                                                                                                                                      
import webbrowser                                                                                                                                                                                               
                                                                                                                                                                                                                
from PyQt4 import QtGui                                                                                                                                                                                         
import SOAPpy                                                                                                                                                                                                   
                                                                                                                                                                                                                
class SystemTrayIcon(QtGui.QSystemTrayIcon):                                                                                                                                                                    
    def __init__(self, icon, parent=None):
        QtGui.QSystemTrayIcon.__init__(self, icon, parent)
        self.menu = QtGui.QMenu(parent)
        detailAction = self.menu.addAction("Details")
        statusAction = self.menu.addAction("Firewall")
        exitAction = self.menu.addAction("Exit")

        detailAction.triggered.connect(self.my_detail)
        statusAction.triggered.connect(self.my_status)
        exitAction.triggered.connect(QtGui.qApp.quit)

        self.setContextMenu(self.menu)

    def my_status(position):
        webbrowser.open('http://192.168.254.1:8008')

    def my_detail(position):
        webbrowser.open('http://192.168.254.1:8008')

def main():
    app = QtGui.QApplication(sys.argv)
    style = app.style()
    icon = QtGui.QIcon(style.standardPixmap(QtGui.QStyle.SP_FileIcon))
    trayIcon = SystemTrayIcon(icon)

    trayIcon.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
