#!/usr/bin/env python3

import platform
import os
import sys
import time
import psutil
import subprocess
import hashlib
import socket
import threading
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
import tempfile

current_platform = platform.system().lower()

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ProcessAnalyzer:
    
    def __init__(self):
        self.suspicious_processes = []
        self.keylogger_indicators = [
            'keylog', 'keystroke', 'monitor', 'capture', 'stealth',
            'hidden', 'spy', 'surveillance', 'logger', 'recorder'
        ]
        
        self.whitelist = {
            'explorer.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe',
            'services.exe', 'svchost.exe', 'dwm.exe', 'taskhost.exe',
            'python.exe', 'cmd.exe', 'powershell.exe', 'conhost.exe'
        }
    
    def analyze_process_names(self):
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                if proc_name in self.whitelist:
                    continue
                
                for indicator in self.keylogger_indicators:
                    if indicator in proc_name:
                        suspicious.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'reason': f'Suspicious name contains: {indicator}',
                            'create_time': proc_info['create_time']
                        })
                        break
                
                if self._is_disguised_process(proc_info):
                    suspicious.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cmdline': proc_info['cmdline'],
                        'reason': 'Process name obfuscation detected',
                        'create_time': proc_info['create_time']
                    })
        
        except Exception as e:
            pass
        
        return suspicious
    
    def _is_disguised_process(self, proc_info):
        name = proc_info['name'].lower()
        
        if len(name) > 8 and name.count('.') == 1:
            base_name = name.split('.')[0]
            if len(set(base_name)) > len(base_name) * 0.8:
                return True
        
        system_names = ['svchost', 'explorer', 'winlogon', 'csrss']
        for sys_name in system_names:
            if sys_name in name:
                try:
                    proc = psutil.Process(proc_info['pid'])
                    exe_path = proc.exe().lower()
                    if 'system32' not in exe_path and 'windows' not in exe_path:
                        return True
                except:
                    pass
        
        return False
    
    def analyze_process_behavior(self):
        suspicious = []
        
        try:
            initial_processes = {p.pid: p for p in psutil.process_iter()}
            
            time.sleep(10)
            
            current_processes = {p.pid: p for p in psutil.process_iter()}
            
            for pid, proc in current_processes.items():
                try:
                    if self._has_keyboard_hooks(proc):
                        suspicious.append({
                            'pid': pid,
                            'name': proc.name(),
                            'reason': 'Keyboard hook activity detected',
                            'cpu_percent': proc.cpu_percent(),
                            'memory_info': proc.memory_info()._asdict()
                        })
                    
                    connections = proc.net_connections()
                    if self._has_suspicious_network_activity(connections):
                        suspicious.append({
                            'pid': pid,
                            'name': proc.name(),
                            'reason': 'Suspicious network activity',
                            'connections': len(connections)
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            pass
        
        return suspicious
    
    def _has_keyboard_hooks(self, proc):
        if current_platform != "windows":
            return False
        
        try:
            proc_name = proc.name().lower()
            
            try:
                memory_maps = proc.memory_maps()
                input_dlls = ['user32.dll', 'kernel32.dll', 'ntdll.dll']
                dll_count = sum(1 for map_info in memory_maps 
                              if any(dll in map_info.path.lower() for dll in input_dlls))
                
                if dll_count > 10 and proc.cpu_percent() > 5:
                    return True
            except:
                pass
            
            return False
        except:
            return False
    
    def _has_suspicious_network_activity(self, connections):
        if not connections:
            return False
        
        suspicious_ports = [80, 443, 53, 25, 587]
        external_connections = [
            conn for conn in connections 
            if conn.status == 'ESTABLISHED' and 
               conn.raddr and 
               not conn.raddr.ip.startswith('127.') and
               not conn.raddr.ip.startswith('192.168.')
        ]
        
        return len(external_connections) > 5

class FileSystemForensics:
    
    def __init__(self):
        self.suspicious_files = []
        self.temp_dirs = [
            tempfile.gettempdir(),
            os.path.expanduser('~'),
            '/tmp' if current_platform != 'windows' else 'C:\\Temp'
        ]
        
        self.suspicious_patterns = [
            r'.*keylog.*\.(txt|log|dat|tmp)',
            r'.*\.log',
            r'^\..*\.tmp',
            r'.*keystroke.*',
            r'.*captured.*', 
            r'system_log_\d+\.tmp'
        ]
    
    def scan_file_system(self):
        suspicious = []
        
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                suspicious.extend(self._scan_directory(temp_dir))
        
        if current_platform == "windows":
            suspicious.extend(self._scan_ads())
        
        return suspicious
    
    def _scan_directory(self, directory):
        suspicious = []
        
        try:
            for root, dirs, files in os.walk(directory):
                if any(sys_dir in root.lower() for sys_dir in ['system32', 'windows', 'program files']):
                    continue
                
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    for pattern in self.suspicious_patterns:
                        if re.match(pattern, file.lower()):
                            file_info = self._analyze_file(filepath)
                            if file_info:
                                suspicious.append(file_info)
                            break
                    
                    if self._is_recently_modified(filepath):
                        content_analysis = self._analyze_file_content(filepath)
                        if content_analysis['suspicious']:
                            suspicious.append({
                                'path': filepath,
                                'reason': 'Recent file with keylogger content',
                                'size': os.path.getsize(filepath),
                                'modified': os.path.getmtime(filepath),
                                'content_analysis': content_analysis
                            })
        
        except Exception as e:
            pass
        
        return suspicious
    
    def _analyze_file(self, filepath):
        try:
            stat = os.stat(filepath)
            
            return {
                'path': filepath,
                'reason': 'Matches keylogger file pattern',
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'created': stat.st_ctime if hasattr(stat, 'st_ctime') else None,
                'is_hidden': self._is_hidden_file(filepath)
            }
        except Exception as e:
            return None
    
    def _is_recently_modified(self, filepath):
        try:
            mtime = os.path.getmtime(filepath)
            current_time = time.time()
            return (current_time - mtime) < 86400
        except:
            return False
    
    def _analyze_file_content(self, filepath):
        analysis = {'suspicious': False, 'indicators': []}
        
        try:
            if os.path.getsize(filepath) > 10 * 1024 * 1024:
                return analysis
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)
            
            keylogger_indicators = [
                'timestamp', 'keystroke', 'key_press', 'window_title',
                'captured', 'logged', 'monitored', '[CTRL]', '[ALT]',
                'readable_time', 'formatted_key', 'active_window'
            ]
            
            found_indicators = []
            for indicator in keylogger_indicators:
                if indicator.lower() in content.lower():
                    found_indicators.append(indicator)
            
            if len(found_indicators) >= 3:
                analysis['suspicious'] = True
                analysis['indicators'] = found_indicators
            
            if 'timestamp' in content and 'key' in content and '{' in content:
                try:
                    json.loads(content[:1000])
                    analysis['suspicious'] = True
                    analysis['indicators'].append('JSON keylog structure')
                except:
                    pass
        
        except Exception as e:
            pass
        
        return analysis
    
    def _is_hidden_file(self, filepath):
        if current_platform == "windows":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                return attrs != -1 and (attrs & 2)
            except:
                return False
        else:
            return os.path.basename(filepath).startswith('.')
    
    def _scan_ads(self):
        suspicious = []
        
        if current_platform != "windows":
            return suspicious
        
        try:
            result = subprocess.run(['dir', '/r', tempfile.gettempdir()], 
                                  capture_output=True, text=True, shell=True)
            
            if ':' in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line and 'bytes' in line:
                        suspicious.append({
                            'type': 'Alternate Data Stream',
                            'location': line.strip(),
                            'reason': 'ADS detected - possible hidden data'
                        })
        except Exception as e:
            pass
        
        return suspicious

class NetworkMonitor:
    
    def __init__(self):
        self.suspicious_traffic = []
        self.monitoring = False
    
    def monitor_network_traffic(self, duration=30):
        if not SCAPY_AVAILABLE:
            return self._monitor_connections_alternative()
        
        self.monitoring = True
        suspicious = []
        
        def packet_handler(packet):
            if not self.monitoring:
                return
            
            analysis = self._analyze_packet(packet)
            if analysis:
                suspicious.append(analysis)
        
        try:
            scapy.sniff(prn=packet_handler, timeout=duration, store=False)
        except Exception as e:
            pass
        
        self.monitoring = False
        return suspicious
    
    def _analyze_packet(self, packet):
        try:
            if packet.haslayer(scapy.IP):
                if packet.haslayer(scapy.DNS):
                    dns_query = packet[scapy.DNS]
                    if dns_query.qd and dns_query.qd.qname:
                        query_name = dns_query.qd.qname.decode()
                        
                        if self._looks_like_base64_exfiltration(query_name):
                            return {
                                'type': 'DNS Exfiltration',
                                'query': query_name,
                                'src_ip': packet[scapy.IP].src,
                                'timestamp': time.time()
                            }
                
                if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    if 'POST' in payload and self._contains_keylogger_data(payload):
                        return {
                            'type': 'HTTP Exfiltration',
                            'dst_ip': packet[scapy.IP].dst,
                            'dst_port': packet[scapy.TCP].dport,
                            'data_size': len(payload),
                            'timestamp': time.time()
                        }
        
        except Exception:
            pass
        
        return None
    
    def _looks_like_base64_exfiltration(self, query_name):
        subdomain = query_name.split('.')[0]
        
        if len(subdomain) > 20:
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            if len(set(subdomain) - base64_chars) == 0:
                return True
        
        return False
    
    def _contains_keylogger_data(self, payload):
        keylogger_indicators = [
            'timestamp', 'keystroke', 'key', 'window', 'captured',
            'readable_time', 'formatted_key'
        ]
        
        indicator_count = sum(1 for indicator in keylogger_indicators 
                            if indicator in payload.lower())
        
        return indicator_count >= 2
    
    def _monitor_connections_alternative(self):
        suspicious = []
        
        try:
            initial_connections = {}
            
            for proc in psutil.process_iter():
                try:
                    connections = proc.net_connections()
                    if connections:
                        initial_connections[proc.pid] = len(connections)
                except:
                    continue
            
            time.sleep(30)
            
            for proc in psutil.process_iter():
                try:
                    connections = proc.net_connections()
                    current_conn_count = len(connections)
                    initial_count = initial_connections.get(proc.pid, 0)
                    
                    if current_conn_count > initial_count + 5:
                        external_connections = [
                            conn for conn in connections
                            if conn.raddr and not conn.raddr.ip.startswith('127.')
                        ]
                        
                        if external_connections:
                            suspicious.append({
                                'type': 'Suspicious Connection Activity',
                                'process': proc.name(),
                                'pid': proc.pid,
                                'new_connections': current_conn_count - initial_count,
                                'external_connections': len(external_connections)
                            })
                
                except:
                    continue
        
        except Exception as e:
            pass
        
        return suspicious

class MemoryAnalyzer:
    
    def __init__(self):
        self.yara_rules = self._create_yara_rules() if YARA_AVAILABLE else None
    
    def _create_yara_rules(self):
        rules_text = '''
        rule Keylogger_Strings {
            strings:
                $s1 = "GetAsyncKeyState" ascii
                $s2 = "SetWindowsHookEx" ascii
                $s3 = "keylog" ascii nocase
                $s4 = "keystroke" ascii nocase
                $s5 = "GetForegroundWindow" ascii
                $s6 = "capture" ascii nocase
                $s7 = "timestamp" ascii
                $s8 = "window_title" ascii
                $s9 = "formatted_key" ascii
                $s10 = "on_key_press" ascii
            
            condition:
                3 of them
        }
        
        rule Stealth_Techniques {
            strings:
                $s1 = "IsDebuggerPresent" ascii
                $s2 = "CheckRemoteDebuggerPresent" ascii
                $s3 = "NtQueryInformationProcess" ascii
                $s4 = "CreateToolhelp32Snapshot" ascii
                $s5 = "anti" ascii nocase
                $s6 = "stealth" ascii nocase
                $s7 = "hide" ascii nocase
                $s8 = "obfuscat" ascii nocase
            
            condition:
                2 of them
        }
        '''
        
        try:
            return yara.compile(source=rules_text)
        except Exception as e:
            return None
    
    def scan_process_memory(self, max_processes=10):
        suspicious = []
        
        if not YARA_AVAILABLE:
            return self._alternative_memory_scan()
        
        scanned = 0
        for proc in psutil.process_iter(['pid', 'name']):
            if scanned >= max_processes:
                break
            
            try:
                if proc.info['pid'] in [0, 4, os.getpid()]:
                    continue
                
                memory_analysis = self._analyze_process_memory(proc.info['pid'])
                if memory_analysis:
                    suspicious.append(memory_analysis)
                
                scanned += 1
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                continue
        
        return suspicious
    
    def _analyze_process_memory(self, pid):
        try:
            proc = psutil.Process(pid)
            
            memory_maps = proc.memory_maps()
            
            suspicious_indicators = []
            
            for memory_map in memory_maps:
                path = memory_map.path.lower()
                
                if 'temp' in path or 'tmp' in path:
                    suspicious_indicators.append(f"Temporary file execution: {path}")
                
                if memory_map.rss > 50 * 1024 * 1024:
                    suspicious_indicators.append(f"Large memory region: {memory_map.rss // 1024 // 1024}MB")
            
            if suspicious_indicators:
                return {
                    'pid': pid,
                    'name': proc.name(),
                    'indicators': suspicious_indicators,
                    'memory_percent': proc.memory_percent(),
                    'num_threads': proc.num_threads()
                }
        
        except Exception as e:
            pass
        
        return None
    
    def _alternative_memory_scan(self):
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'num_threads']):
                try:
                    memory_info = proc.info['memory_info']
                    
                    if memory_info.rss > 100 * 1024 * 1024:
                        suspicious.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'reason': 'High memory usage',
                            'memory_mb': memory_info.rss // 1024 // 1024,
                            'threads': proc.info['num_threads']
                        })
                    
                    if proc.info['num_threads'] > 20:
                        suspicious.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'reason': 'Excessive thread count',
                            'threads': proc.info['num_threads']
                        })
                
                except:
                    continue
        
        except Exception as e:
            pass
        
        return suspicious

class KeyloggerDetector:
    
    def __init__(self):
        self.process_analyzer = ProcessAnalyzer()
        self.file_forensics = FileSystemForensics()
        self.network_monitor = NetworkMonitor()
        self.memory_analyzer = MemoryAnalyzer()
        
        self.detection_results = {}
    
    def run_full_scan(self):
        print("ADVANCED KEYLOGGER DETECTION TOOLKIT")
        print("="*60)
        print("Starting comprehensive scan...")
        
        print("\nPhase 1: Process Analysis")
        process_results = []
        process_results.extend(self.process_analyzer.analyze_process_names())
        process_results.extend(self.process_analyzer.analyze_process_behavior())
        self.detection_results['processes'] = process_results
        print("Analysis of this phase done.")
        
        print("\nPhase 2: File System Forensics")
        file_results = self.file_forensics.scan_file_system()
        self.detection_results['files'] = file_results
        print("Analysis of this phase done.")
        
        print("\nPhase 3: Network Traffic Monitoring")
        network_results = self.network_monitor.monitor_network_traffic(duration=15)
        self.detection_results['network'] = network_results
        print("Analysis of this phase done.")
        
        print("\nPhase 4: Memory Analysis")
        memory_results = self.memory_analyzer.scan_process_memory()
        self.detection_results['memory'] = memory_results
        print("Analysis of this phase done.")
        
        total_detections = sum(len(results) for results in self.detection_results.values())
        
        if total_detections > 0:
            print("\nPotential keyloggers detected.")
        else:
            print("\nNot detected.")
    
    def save_results(self, filename=None):
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"keylogger_detection_report_{timestamp}.json"
        
        try:
            report_data = {
                'scan_timestamp': datetime.now().isoformat(),
                'platform': current_platform,
                'total_detections': sum(len(results) for results in self.detection_results.values()),
                'results': self.detection_results,
                'system_info': {
                    'hostname': socket.gethostname(),
                    'cpu_count': psutil.cpu_count(),
                    'memory_total': psutil.virtual_memory().total,
                    'disk_usage': {partition.mountpoint: psutil.disk_usage(partition.mountpoint)._asdict() 
                                 for partition in psutil.disk_partitions()[:3]}
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            print(f"\n📄 Detection report saved to: {filename}")
            return filename
        
        except Exception as e:
            return None

def main():
    print("Advanced Keylogger Detection Toolkit - COMP6841 Project")
    
    detector = KeyloggerDetector()
    
    try:
        detector.run_full_scan()
        
        save_choice = input("\nSave detection report? (y/n): ").strip().lower()
        if save_choice == 'y':
            detector.save_results()
    
    except KeyboardInterrupt:
        print("\n\nDetection interrupted by user.")
    except Exception as e:
        print(f"\n[ERROR] Detection failed: {e}")
    
    print("\nDetection toolkit completed.")

if __name__ == "__main__":
    main() 