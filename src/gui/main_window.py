"""
Main Window Module for Network Sniffer

This module contains the main window class for the Network Sniffer application.

ماژول پنجره اصلی برای برنامه شبکه اسنیفر
این ماژول شامل کلاس پنجره اصلی برای برنامه شبکه اسنیفر می‌باشد.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTabWidget, QLabel, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QStatusBar, QMessageBox, QSplitter, QGroupBox,
    QFormLayout, QLineEdit, QCompleter, QMenuBar, QMenu, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QAction, QIcon, QFont, QPixmap, QColor
import pyqtgraph as pg
import psutil
import platform
import socket
import time
from datetime import datetime
import os

from ..network.sniffer import NetworkSniffer
from ..utils.translator import Translator

class NetworkSnifferApp(QMainWindow):
    """
    Main application window for Network Sniffer
    
    پنجره اصلی برنامه شبکه اسنیفر
    """
    
    def __init__(self):
        """Initialize the main window
        
        مقداردهی اولیه پنجره اصلی
        """
        super().__init__()
        
        # Initialize translator
        self.translator = Translator()
        
        # Network sniffer instance
        self.sniffer = NetworkSniffer()
        
        # UI setup
        self.init_ui()
        
        # Update UI with current language
        self.retranslate_ui()
        
        # Start update timer for real-time data
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(1000)  # Update every second
    
    def init_ui(self):
        """Initialize the user interface
        
        مقداردهی اولیه رابط کاربری
        """
        # Main window properties
        self.setWindowTitle(self.tr("Network Full Sniffer"))
        self.setMinimumSize(1200, 800)
        
        # Set window icon
        self.setWindowIcon(QIcon(":/icons/network.png"))
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create main content area
        content_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Create control panel
        control_panel = self.create_control_panel()
        content_splitter.addWidget(control_panel)
        
        # Create tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.packets_tab = self.create_packets_tab()
        self.stats_tab = self.create_stats_tab()
        self.graph_tab = self.create_graph_tab()
        
        self.tab_widget.addTab(self.packets_tab, self.tr("Packets"))
        self.tab_widget.addTab(self.stats_tab, self.tr("Statistics"))
        self.tab_widget.addTab(self.graph_tab, self.tr("Graphs"))
        
        content_splitter.addWidget(self.tab_widget)
        
        # Add content to main layout
        main_layout.addWidget(content_splitter)
        
        # Set initial status
        self.update_status(False)
    
    def create_menu_bar(self):
        """Create the menu bar
        
        ایجاد نوار منو
        """
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu(self.tr("&File"))
        
        # Language submenu
        language_menu = file_menu.addMenu(self.tr("&Language"))
        
        # Language actions
        self.english_action = QAction("English", self)
        self.english_action.triggered.connect(lambda: self.change_language('en'))
        
        self.persian_action = QAction("فارسی", self)
        self.persian_action.triggered.connect(lambda: self.change_language('fa'))
        
        language_menu.addAction(self.english_action)
        language_menu.addAction(self.persian_action)
        
        # Exit action
        exit_action = QAction(self.tr("E&xit"), self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu(self.tr("&View"))
        
        # Tools menu
        tools_menu = menubar.addMenu(self.tr("&Tools"))
        
        # Help menu
        help_menu = menubar.addMenu(self.tr("&Help"))
        about_action = QAction(self.tr("&About"), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_control_panel(self):
        """Create the control panel
        
        ایجاد پنل کنترل
        """
        panel = QGroupBox()
        layout = QHBoxLayout(panel)
        
        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel(self.tr("Interface:"))
        self.interface_combo = QComboBox()
        self.populate_interfaces()
        
        # Filter input
        filter_label = QLabel(self.tr("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(self.tr("e.g., tcp port 80"))
        
        # Control buttons
        self.start_button = QPushButton()
        self.start_button.clicked.connect(self.toggle_sniffing)
        
        self.stop_button = QPushButton()
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_sniffing)
        
        self.clear_button = QPushButton(self.tr("Clear"))
        self.clear_button.clicked.connect(self.clear_packets)
        
        # Add widgets to layout
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        interface_layout.addWidget(filter_label)
        interface_layout.addWidget(self.filter_edit)
        interface_layout.addWidget(self.start_button)
        interface_layout.addWidget(self.stop_button)
        interface_layout.addWidget(self.clear_button)
        
        layout.addLayout(interface_layout)
        
        return panel
    
    def create_packets_tab(self):
        """Create the packets tab
        
        ایجاد تب بسته‌ها
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            self.tr("No."),
            self.tr("Time"),
            self.tr("Source"),
            self.tr("Destination"),
            self.tr("Protocol"),
            self.tr("Length"),
            self.tr("Info")
        ])
        
        # Configure table properties
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Set column widths
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Length
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)  # Info
        
        # Add table to layout
        layout.addWidget(self.packet_table)
        
        return tab
    
    def create_stats_tab(self):
        """Create the statistics tab
        
        ایجاد تب آمار
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create a splitter for the stats view
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Protocol distribution
        protocol_group = QGroupBox(self.tr("توزیع پروتکل‌ها"))
        protocol_layout = QVBoxLayout(protocol_group)
        
        # Protocol table
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(2)
        self.protocol_table.setHorizontalHeaderLabels([
            self.tr("پروتکل"),
            self.tr("تعداد")
        ])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.protocol_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        protocol_layout.addWidget(self.protocol_table)
        
        # Network interfaces stats
        iface_group = QGroupBox(self.tr("وضعیت رابط‌های شبکه"))
        iface_layout = QVBoxLayout(iface_group)
        
        # Interface stats table
        self.iface_stats_table = QTableWidget()
        self.iface_stats_table.setColumnCount(5)
        self.iface_stats_table.setHorizontalHeaderLabels([
            self.tr("رابط"),
            self.tr("وضعیت"),
            self.tr("آی‌پی"),
            self.tr("آدرس مک"),
            self.tr("سرعت")
        ])
        self.iface_stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.iface_stats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        iface_layout.addWidget(self.iface_stats_table)
        
        # Add widgets to splitter
        splitter.addWidget(protocol_group)
        splitter.addWidget(iface_group)
        
        # Set initial sizes
        splitter.setSizes([int(self.height() * 0.4), int(self.height() * 0.6)])
        
        # Add splitter to main layout
        layout.addWidget(splitter)
        
        # Update stats immediately
        self.update_stats_tables()
        
        return tab
    
    def create_graph_tab(self):
        """Create the graphs tab
        
        ایجاد تب نمودارها
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create a splitter for multiple graphs
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Traffic rate graph
        traffic_group = QGroupBox(self.tr("میزان ترافیک"))
        traffic_layout = QVBoxLayout(traffic_group)
        
        self.traffic_plot = pg.PlotWidget(title=self.tr("میزان ترافیک (بایت بر ثانیه)"))
        self.traffic_plot.setBackground('w')
        self.traffic_plot.showGrid(x=True, y=True)
        self.traffic_plot.setLabel('left', self.tr("بایت بر ثانیه"))
        self.traffic_plot.setLabel('bottom', self.tr("زمان (ثانیه)"))
        
        # Enable right-click menu for the plot
        self.traffic_plot.setMenuEnabled(True)
        
        # Add legend
        self.traffic_plot.addLegend()
        
        # Create plot curves
        self.recv_curve = self.traffic_plot.plot(
            pen=pg.mkPen(color='r', width=2),
            name=self.tr("دریافتی")
        )
        self.send_curve = self.traffic_plot.plot(
            pen=pg.mkPen(color='b', width=2),
            name=self.tr("ارسالی")
        )
        
        # Data for plotting
        self.time_data = []
        self.recv_data = []
        self.send_data = []
        self.max_points = 60  # Show last 60 seconds
        
        traffic_layout.addWidget(self.traffic_plot)
        
        # Protocol distribution bar chart
        protocol_group = QGroupBox(self.tr("توزیع پروتکل‌ها"))
        protocol_layout = QVBoxLayout(protocol_group)
        
        self.protocol_plot = pg.PlotWidget(title=self.tr("توزیع پروتکل‌ها"))
        self.protocol_plot.setBackground('w')
        self.protocol_plot.showGrid(x=True, y=True)
        self.protocol_plot.setLabel('left', self.tr("تعداد بسته‌ها"))
        self.protocol_plot.setLabel('bottom', self.tr("پروتکل"))
        self.protocol_plot.getAxis('bottom').setTicks([[(i, proto) for i, proto in enumerate([])]])  # Will be updated dynamically
        
        # Create a bar graph item
        self.protocol_bars = pg.BarGraphItem(x=[], height=[], width=0.6, brush='b')
        self.protocol_plot.addItem(self.protocol_bars)
        
        protocol_layout.addWidget(self.protocol_plot)
        
        # Add widgets to splitter
        splitter.addWidget(traffic_group)
        splitter.addWidget(protocol_group)
        
        # Set initial sizes
        splitter.setSizes([int(self.height() * 0.6), int(self.height() * 0.4)])
        
        # Add splitter to main layout
        layout.addWidget(splitter)
        
        # Start update timer for graphs
        self.graph_timer = QTimer(self)
        self.graph_timer.timeout.connect(self.update_traffic_graph)
        self.graph_timer.start(1000)  # Update every second
        
        return tab
    
    def populate_interfaces(self):
        """Populate the network interfaces dropdown with friendly names
        
        پر کردن منوی کشویی رابط‌های شبکه با نام‌های خوانا
        """
        self.interface_combo.clear()
        interfaces = self.sniffer.get_network_interfaces()
        
        if not interfaces:
            self.interface_combo.addItem(self.tr("No network interfaces found"), None)
            return
            
        for iface in interfaces:
            # Create display text with status and IP if available
            status_icon = "✓" if iface['status'] == 'Up' else "✗"
            ip_info = f" ({iface['ip']})" if iface['ip'] != 'N/A' else ""
            display_text = f"{status_icon} {iface['friendly_name']}{ip_info}"
            
            # Add to combo box
            self.interface_combo.addItem(display_text, iface['name'])
            
            # Set tooltip with more details
            tooltip = (
                f"Name: {iface['name']}\n"
                f"IP: {iface['ip']}\n"
                f"MAC: {iface['mac']}\n"
                f"Status: {iface['status']}"
            )
            self.interface_combo.setItemData(
                self.interface_combo.count() - 1,
                tooltip,
                Qt.ItemDataRole.ToolTipRole
            )
    
    def toggle_sniffing(self):
        """Toggle packet sniffing
        
        تغییر حالت ضبط بسته‌ها
        """
        if not self.sniffer.is_sniffing():
            self.start_sniffing()
        else:
            self.stop_sniffing()
    
    def start_sniffing(self):
        """Start packet sniffing
        
        شروع ضبط بسته‌ها
        """
        iface_index = self.interface_combo.currentIndex()
        if iface_index < 0:
            QMessageBox.warning(self, self.tr("Error"), self.tr("No network interface selected!"))
            return
        
        filter_text = self.filter_edit.text().strip()
        
        try:
            self.sniffer.start_sniffing(iface_index, filter_text)
            self.update_status(True)
        except Exception as e:
            QMessageBox.critical(self, self.tr("Error"), self.tr(f"Failed to start sniffing: {str(e)}"))
    
    def stop_sniffing(self):
        """Stop packet sniffing
        
        توقف ضبط بسته‌ها
        """
        self.sniffer.stop_sniffing()
        self.update_status(False)
    
    def clear_packets(self):
        """Clear captured packets
        
        پاک کردن بسته‌های ضبط شده
        """
        self.sniffer.clear_packets()
        self.packet_table.setRowCount(0)
    
    def update_status(self, is_sniffing):
        """Update UI status
        
        به‌روزرسانی وضعیت رابط کاربری
        """
        if is_sniffing:
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_bar.showMessage(self.tr("Sniffing..."))
        else:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_bar.showMessage(self.tr("Ready"))
    
    def update_stats(self):
        """Update statistics and graphs
        
        به‌روزرسانی آمار و نمودارها
        """
        try:
            # Update packet table
            self.update_packet_table()
            
            # Update statistics tables
            self.update_stats_tables()
            
            # The traffic graph is updated by its own timer
            # to maintain smooth animation
        except Exception as e:
            print(f"Error in update_stats: {e}")
    
    def update_packet_table(self):
        """Update the packet table with new packets
        
        به‌روزرسانی جدول بسته‌ها با بسته‌های جدید
        """
        new_packets = self.sniffer.get_new_packets()
        if not new_packets:
            return
        
        current_row = self.packet_table.rowCount()
        self.packet_table.setRowCount(current_row + len(new_packets))
        
        for i, packet in enumerate(new_packets):
            row = current_row + i
            self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.packet_table.setItem(row, 1, QTableWidgetItem(packet['time']))
            self.packet_table.setItem(row, 2, QTableWidgetItem(packet['source']))
            self.packet_table.setItem(row, 3, QTableWidgetItem(packet['destination']))
            self.packet_table.setItem(row, 4, QTableWidgetItem(packet['protocol']))
            self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet['length'])))
            self.packet_table.setItem(row, 6, QTableWidgetItem(packet['info']))
        
        # Auto-scroll to the bottom
        self.packet_table.scrollToBottom()
    
    def update_stats_tables(self):
        """Update the statistics tables with current data
        
        به‌روزرسانی جداول آمار با داده‌های فعلی
        """
        try:
            # Update protocol distribution table
            protocol_counts = self.sniffer.get_protocol_counts()
            self.protocol_table.setRowCount(len(protocol_counts))
            
            for row, (protocol, count) in enumerate(protocol_counts.items()):
                self.protocol_table.setItem(row, 0, QTableWidgetItem(protocol))
                self.protocol_table.setItem(row, 1, QTableWidgetItem(str(count)))
            
            # Update interface statistics table
            interfaces = self.sniffer.get_network_interfaces()
            self.iface_stats_table.setRowCount(len(interfaces))
            
            for row, iface in enumerate(interfaces):
                self.iface_stats_table.setItem(row, 0, QTableWidgetItem(iface['friendly_name']))
                self.iface_stats_table.setItem(row, 1, QTableWidgetItem(iface['status']))
                self.iface_stats_table.setItem(row, 2, QTableWidgetItem(iface['ip']))
                self.iface_stats_table.setItem(row, 3, QTableWidgetItem(iface['mac']))
                
                # Get interface speed if available
                speed = "N/A"
                if 'speed' in iface and iface['speed']:
                    speed = f"{iface['speed']} Mbps"
                self.iface_stats_table.setItem(row, 4, QTableWidgetItem(speed))
                
        except Exception as e:
            print(f"Error updating stats tables: {e}")
            
    def update_traffic_graph(self):
        """Update the traffic graph and protocol distribution
        
        به‌روزرسانی نمودار ترافیک و توزیع پروتکل‌ها
        """
        # Update traffic graph
        current_time = time.time()
        
        # Get network I/O stats
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv
        
        # Update time data (x-axis)
        self.time_data.append(current_time)
        
        # Update data points
        self.recv_data.append(bytes_recv)
        self.send_data.append(bytes_sent)
        
        # Keep only the last max_points data points
        if len(self.time_data) > self.max_points:
            self.time_data = self.time_data[-self.max_points:]
            self.recv_data = self.recv_data[-self.max_points:]
            self.send_data = self.send_data[-self.max_points:]
        
        # Calculate time differences for x-axis
        time_diffs = [t - self.time_data[0] for t in self.time_data]
        
        # Update traffic plot
        self.recv_curve.setData(time_diffs, self.recv_data)
        self.send_curve.setData(time_diffs, self.send_data)
        
        # Update protocol distribution
        protocol_counts = self.sniffer.get_protocol_counts()
        if protocol_counts:
            protocols = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            
            # Update x-axis ticks with protocol names
            x_ticks = [[(i, proto) for i, proto in enumerate(protocols)]]
            self.protocol_plot.getAxis('bottom').setTicks(x_ticks)
            
            # Update bar graph
            self.protocol_bars.setOpts(
                x=range(len(protocols)),
                height=counts,
                width=0.6,
                brushes=[pg.mkBrush(color=(i*50 % 255, i*100 % 255, 150)) for i in range(len(protocols))]
            )
            
            # Auto-range the plot to fit all bars
            self.protocol_plot.enableAutoRange()
    
    def change_language(self, lang_code):
        """Change application language
        
        تغییر زبان برنامه
        """
        self.translator.set_language(lang_code)
        self.retranslate_ui()
    
    def retranslate_ui(self):
        """Retranslate the UI elements
        
        ترجمه مجدد عناصر رابط کاربری
        """
        # Update window title
        self.setWindowTitle(self.translator.tr("Network Full Sniffer"))
        
        # Update menu items
        self.menuBar().actions()[0].setText(self.translator.tr("&File"))  # File menu
        self.menuBar().actions()[1].setText(self.translator.tr("&View"))  # View menu
        self.menuBar().actions()[2].setText(self.translator.tr("&Tools"))  # Tools menu
        self.menuBar().actions()[3].setText(self.translator.tr("&Help"))  # Help menu
        
        # Update buttons
        self.start_button.setText(self.translator.tr("Start"))
        self.stop_button.setText(self.translator.tr("Stop"))
        self.clear_button.setText(self.translator.tr("Clear"))
        
        # Update tab names
        self.tab_widget.setTabText(0, self.translator.tr("Packets"))
        self.tab_widget.setTabText(1, self.translator.tr("Statistics"))
        self.tab_widget.setTabText(2, self.translator.tr("Graphs"))
        
        # Update status bar
        if self.sniffer.is_sniffing():
            self.status_bar.showMessage(self.translator.tr("Sniffing..."))
        else:
            self.status_bar.showMessage(self.translator.tr("Ready"))
    
    def show_about(self):
        """Show about dialog
        
        نمایش کادر درباره برنامه
        """
        QMessageBox.about(
            self,
            self.translator.tr("About Network Full Sniffer"),
            self.translator.tr(
                "<h2>Network Full Sniffer</h2>"
                "<p>Version 1.0.0</p>"
                "<p>A professional network packet analyzer with bilingual support.</p>"
                "<p>© 2025 Network Tools. All rights reserved.</p>"
                "<hr>"
                "<h3>شبکه اسنیفر حرفه‌ای</h3>"
                "<p>نسخه ۱.۰.۰</p>"
                "<p>یک تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی دو زبانه.</p>"
                "<p>© ۱۴۰۴ ابزارهای شبکه. تمامی حقوق محفوظ است.</p>"
            )
        )
    
    def closeEvent(self, event):
        """Handle window close event
        
        مدیریت رویداد بسته شدن پنجره
        """
        if self.sniffer.is_sniffing():
            reply = QMessageBox.question(
                self,
                self.translator.tr("Confirm Exit"),
                self.translator.tr("Sniffing is in progress. Are you sure you want to exit?"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.sniffer.stop_sniffing()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
