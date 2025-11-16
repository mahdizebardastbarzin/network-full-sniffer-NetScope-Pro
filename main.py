#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Full Sniffer - Main Application
A professional network packet analyzer with bilingual (English/Persian) support

شبکه اسنیفر حرفه ای - برنامه اصلی
یک تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی دو زبانه (انگلیسی/فارسی)
"""

import sys
import os
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

def setup_logging():
    """Setup logging configuration
    تنظیمات لاگ‌گیری
    """
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"{log_dir}/network_sniffer.log"),
            logging.StreamHandler()
        ]
    )

def main():
    """Main application entry point
    نقطه ورود اصلی برنامه
    """
    # Initialize the application
    app = QApplication(sys.argv)
    
    # Set application metadata
    app.setApplicationName("Network Full Sniffer")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("NetworkTools")
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Import here to catch any import errors
        from src.gui.main_window import NetworkSnifferApp
        
        # Create and show main window
        window = NetworkSnifferApp()
        window.show()
        
        # Start the application event loop
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Application error: {str(e)}", exc_info=True)
        QMessageBox.critical(
            None,
            "خطا در اجرای برنامه",
            f"خطای زیر رخ داد:\n{str(e)}\n\nلطفاً مطمئن شوید تمام کتابخانه‌های مورد نیاز نصب شده‌اند.",
            buttons=QMessageBox.StandardButton.Ok,
            defaultButton=QMessageBox.StandardButton.Ok
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
