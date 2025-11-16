"""
Translation Module

This module provides translation functionality for the Network Sniffer application.
It supports both English and Persian languages.

ماژول ترجمه
این ماژول قابلیت ترجمه را برای برنامه شبکه اسنیفر فراهم می‌کند.
از هر دو زبان انگلیسی و فارسی پشتیبانی می‌کند.
"""

class Translator:
    """
    A simple translation class for handling bilingual (English/Persian) text.
    
    یک کلاس ساده برای مدیریت متن‌های دو زبانه (انگلیسی/فارسی).
    """
    
    def __init__(self, default_lang='en'):
        """
        Initialize the translator with the specified default language.
        
        مقداردهی اولیه مترجم با زبان پیش‌فرض مشخص شده.
        
        Args:
            default_lang (str): The default language code ('en' for English, 'fa' for Persian)
                               کد زبان پیش‌فرض ('en' برای انگلیسی، 'fa' برای فارسی)
        """
        self.current_lang = default_lang
        self.translations = {
            # Main Window
            'Network Full Sniffer': {
                'en': 'Network Full Sniffer',
                'fa': 'شبکه اسنیفر حرفه‌ای'
            },
            'Start': {
                'en': 'Start',
                'fa': 'شروع'
            },
            'Stop': {
                'en': 'Stop',
                'fa': 'توقف'
            },
            'Clear': {
                'en': 'Clear',
                'fa': 'پاک کردن'
            },
            'Interface:': {
                'en': 'Interface:',
                'fa': 'رابط شبکه:'
            },
            'Filter:': {
                'en': 'Filter:',
                'fa': 'فیلتر:'
            },
            'e.g., tcp port 80': {
                'en': 'e.g., tcp port 80',
                'fa': 'مثال: tcp port 80'
            },
            'Packets': {
                'en': 'Packets',
                'fa': 'بسته‌ها'
            },
            'Statistics': {
                'en': 'Statistics',
                'fa': 'آمار'
            },
            'Graphs': {
                'en': 'Graphs',
                'fa': 'نمودارها'
            },
            'Sniffing...': {
                'en': 'Sniffing...',
                'fa': 'در حال ضبط...'
            },
            'Ready': {
                'en': 'Ready',
                'fa': 'آماده'
            },
            
            # Menu Items
            '&File': {
                'en': '&File',
                'fa': '&فایل'
            },
            '&View': {
                'en': '&View',
                'fa': '&نمایش'
            },
            '&Tools': {
                'en': '&Tools',
                'fa': '&ابزارها'
            },
            '&Help': {
                'en': '&Help',
                'fa': '&راهنما'
            },
            '&Language': {
                'en': '&Language',
                'fa': '&زبان'
            },
            'E&xit': {
                'en': 'E&xit',
                'fa': '&خروج'
            },
            '&About': {
                'en': '&About',
                'fa': '&درباره'
            },
            
            # Dialog Titles
            'Error': {
                'en': 'Error',
                'fa': 'خطا'
            },
            'About Network Full Sniffer': {
                'en': 'About Network Full Sniffer',
                'fa': 'درباره شبکه اسنیفر حرفه‌ای'
            },
            'Confirm Exit': {
                'en': 'Confirm Exit',
                'fa': 'تأیید خروج'
            },
            
            # Messages
            'Sniffing is in progress. Are you sure you want to exit?': {
                'en': 'Sniffing is in progress. Are you sure you want to exit?',
                'fa': 'ضبط بسته‌ها در حال انجام است. آیا مطمئنید که می‌خواهید خارج شوید؟'
            },
            'No network interface selected!': {
                'en': 'No network interface selected!',
                'fa': 'هیچ رابط شبکه‌ای انتخاب نشده است!'
            },
            'Failed to start sniffing:': {
                'en': 'Failed to start sniffing:',
                'fa': 'شروع ضبط بسته‌ها ناموفق بود:'
            },
            
            # Packet Table Headers
            'No.': {
                'en': 'No.',
                'fa': 'شماره'
            },
            'Time': {
                'en': 'Time',
                'fa': 'زمان'
            },
            'Source': {
                'en': 'Source',
                'fa': 'مبدأ'
            },
            'Destination': {
                'en': 'Destination',
                'fa': 'مقصد'
            },
            'Protocol': {
                'en': 'Protocol',
                'fa': 'پروتکل'
            },
            'Length': {
                'en': 'Length',
                'fa': 'طول'
            },
            'Info': {
                'en': 'Info',
                'fa': 'اطلاعات'
            },
            
            # Statistics Tab
            'Protocol Distribution': {
                'en': 'Protocol Distribution',
                'fa': 'توزیع پروتکل‌ها'
            },
            'Network Interfaces': {
                'en': 'Network Interfaces',
                'fa': 'رابط‌های شبکه'
            },
            
            # Graphs Tab
            'Network Traffic': {
                'en': 'Network Traffic',
                'fa': 'ترافیک شبکه'
            },
            
            # About Dialog
            'Version 1.0.0': {
                'en': 'Version 1.0.0',
                'fa': 'نسخه ۱.۰.۰'
            },
            'A professional network packet analyzer with bilingual support.': {
                'en': 'A professional network packet analyzer with bilingual support.',
                'fa': 'یک تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی دو زبانه.'
            },
            '© 2025 Network Tools. All rights reserved.': {
                'en': '© 2025 Network Tools. All rights reserved.',
                'fa': '© ۱۴۰۴ ابزارهای شبکه. تمامی حقوق محفوظ است.'
            },
            'شبکه اسنیفر حرفه‌ای': {
                'en': 'Professional Network Sniffer',
                'fa': 'شبکه اسنیفر حرفه‌ای'
            },
            'نسخه ۱.۰.۰': {
                'en': 'Version 1.0.0',
                'fa': 'نسخه ۱.۰.۰'
            },
            'یک تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی دو زبانه.': {
                'en': 'A professional network packet analyzer with bilingual support.',
                'fa': 'یک تحلیل‌گر حرفه‌ای بسته‌های شبکه با پشتیبانی دو زبانه.'
            },
            '© ۱۴۰۴ ابزارهای شبکه. تمامی حقوق محفوظ است.': {
                'en': '© 2025 Network Tools. All rights reserved.',
                'fa': '© ۱۴۰۴ ابزارهای شبکه. تمامی حقوق محفوظ است.'
            }
        }
    
    def set_language(self, lang_code):
        """
        Set the current language.
        
        تنظیم زبان جاری.
        
        Args:
            lang_code (str): Language code ('en' for English, 'fa' for Persian)
                            کد زبان ('en' برای انگلیسی، 'fa' برای فارسی)
        """
        if lang_code in ['en', 'fa']:
            self.current_lang = lang_code
            
            # Set text direction
            if lang_code == 'fa':
                # Right-to-left for Persian
                from PyQt6.QtCore import QCoreApplication, QLocale
                QCoreApplication.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
                QLocale.setDefault(QLocale(QLocale.Language.Persian, QLocale.Country.Iran))
            else:
                # Left-to-right for English and other languages
                from PyQt6.QtCore import QCoreApplication, QLocale
                QCoreApplication.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
                QLocale.setDefault(QLocale(QLocale.Language.English, QLocale.Country.UnitedStates))
    
    def tr(self, text):
        """
        Translate the given text to the current language.
        
        ترجمه متن داده شده به زبان جاری.
        
        Args:
            text (str): The text to translate
                        متنی که باید ترجمه شود
                        
        Returns:
            str: The translated text
                 متن ترجمه شده
        """
        if text in self.translations and self.current_lang in self.translations[text]:
            return self.translations[text][self.current_lang]
        return text
