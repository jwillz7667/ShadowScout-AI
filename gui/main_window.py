from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QPushButton, QLineEdit, QTextEdit, QLabel, 
                            QProgressBar, QComboBox, QFrame, QTabWidget,
                            QCheckBox, QSpinBox, QGroupBox, QScrollArea,
                            QFormLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QPalette, QColor
import asyncio
import sys
import os
from datetime import datetime
import json
from pathlib import Path
from assistants.message_bus import MessageType, Message, MessageBus
from assistants.offensive_tools import OffensiveTools
import html
from assistants.browser_assistant import BrowserAssistant
from assistants.terminal_assistant import TerminalAssistant
from assistants.attack_strategist import AttackStrategist

class OffensiveToolsConfig(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Offensive Tools Configuration", parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Tool categories
        self.categories = {
            "Web Attacks": [
                "SQL Injection", "XSS Scanner", "CSRF Tester",
                "Directory Traversal", "File Inclusion", "Command Injection"
            ],
            "Network Tools": [
                "Port Scanner", "Service Enumeration", "Protocol Fuzzer",
                "Network Sniffer", "Traffic Analyzer"
            ],
            "Authentication Tests": [
                "Password Cracker", "Session Hijacker", "Cookie Manipulator",
                "OAuth Tester", "JWT Analyzer"
            ],
            "Infrastructure": [
                "DNS Enumeration", "Subdomain Scanner", "Cloud Misconfiguration",
                "SSL/TLS Analyzer", "WAF Detector"
            ]
        }
        
        # Create sections for each category
        for category, tools in self.categories.items():
            group = QGroupBox(category)
            group_layout = QVBoxLayout(group)
            
            for tool in tools:
                tool_layout = QHBoxLayout()
                
                # Enable/disable checkbox
                checkbox = QCheckBox(tool)
                checkbox.setChecked(False)
                
                # Intensity slider
                intensity = QSpinBox()
                intensity.setRange(1, 5)
                intensity.setValue(3)
                intensity.setPrefix("Intensity: ")
                
                tool_layout.addWidget(checkbox)
                tool_layout.addWidget(intensity)
                group_layout.addLayout(tool_layout)
            
            layout.addWidget(group)
        
        # Add to main layout
        self.setLayout(layout)

    def get_config(self):
        config = {}
        for category, tools in self.categories.items():
            config[category] = {}
            group = self.findChild(QGroupBox, category)
            if group:
                for tool in tools:
                    checkbox = group.findChild(QCheckBox, tool)
                    intensity = group.findChild(QSpinBox)
                    if checkbox and intensity:
                        config[category][tool] = {
                            "enabled": checkbox.isChecked(),
                            "intensity": intensity.value()
                        }
        return config

class ScanWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    log = pyqtSignal(dict)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, target_url, scan_config, assistant_config, offensive_config):
        super().__init__()
        self.target_url = target_url
        self.scan_config = scan_config
        self.assistant_config = assistant_config
        self.offensive_config = offensive_config
        self.current_progress = 0
        
        # Initialize message bus
        self.message_bus = MessageBus()
        
        # Initialize assistants
        self.browser_assistant = BrowserAssistant(self.message_bus)
        self.terminal_assistant = TerminalAssistant(self.message_bus)
        self.attack_strategist = AttackStrategist(self.message_bus)
        
        # Subscribe to message bus for logging
        self.message_bus.subscribe_all(self._handle_message)

    async def _handle_message(self, message: Message):
        """Handle messages from assistants"""
        self.log.emit({
            'type': message.type.value.upper(),
            'source': message.sender,
            'content': str(message.content)
        })

    async def run_scan(self):
        try:
            # Initialize components
            self.log.emit({
                'type': 'INFO',
                'source': 'Scanner',
                'content': 'Initializing scan environment...'
            })
            
            # Initialize assistants
            await self.browser_assistant.initialize()
            await self.terminal_assistant.initialize()
            await self.attack_strategist.initialize()
            
            # Initialize offensive tools with progress updates
            offensive_tools = OffensiveTools()
            await offensive_tools.initialize()
            self.progress.emit(10)
            
            # Run browser analysis
            self.log.emit({
                'type': 'PROCESS',
                'source': 'Browser Assistant',
                'content': 'Starting browser security analysis...'
            })
            browser_results = await self.browser_assistant.run(
                self.target_url,
                self.scan_config.get('aggressiveness', 5),
                self.scan_config.get('stealth_mode', False)
            )
            self.progress.emit(40)
            
            # Run terminal analysis
            self.log.emit({
                'type': 'PROCESS',
                'source': 'Terminal Assistant',
                'content': 'Starting system-level analysis...'
            })
            terminal_results = await self.terminal_assistant.run(
                self.target_url,
                self.scan_config.get('aggressiveness', 5),
                self.scan_config.get('stealth_mode', False)
            )
            self.progress.emit(70)
            
            # Run attack strategy analysis
            self.log.emit({
                'type': 'PROCESS',
                'source': 'Attack Strategist',
                'content': 'Developing attack strategies...'
            })
            strategy_results = await self.attack_strategist.run(
                self.target_url,
                self.scan_config.get('aggressiveness', 5),
                self.scan_config.get('stealth_mode', False)
            )
            self.progress.emit(90)
            
            # Combine results
            results = {
                'browser_analysis': browser_results,
                'terminal_analysis': terminal_results,
                'attack_strategy': strategy_results,
                'timestamp': datetime.now().isoformat()
            }
            
            # Cleanup
            await self.browser_assistant.shutdown()
            await self.terminal_assistant.shutdown()
            await self.attack_strategist.shutdown()
            
            self.progress.emit(100)
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(f"Scan failed: {str(e)}")
            self.log.emit({
                'type': 'ERROR',
                'source': 'Scanner',
                'content': f'Critical error: {str(e)}'
            })

    def run(self):
        """QThread run method"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_scan())
        finally:
            loop.close()

class AssistantConfig(QGroupBox):
    def __init__(self, name, parent=None):
        super().__init__(name, parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Enable/Disable assistant
        self.enabled = QCheckBox("Enable")
        self.enabled.setChecked(True)
        
        # Aggressiveness level
        aggr_layout = QHBoxLayout()
        aggr_label = QLabel("Aggressiveness:")
        self.aggr_level = QSpinBox()
        self.aggr_level.setRange(1, 10)
        self.aggr_level.setValue(5)
        aggr_layout.addWidget(aggr_label)
        aggr_layout.addWidget(self.aggr_level)
        
        # Stealth mode
        self.stealth_mode = QCheckBox("Stealth Mode")
        
        # Custom options
        self.custom_options = QTextEdit()
        self.custom_options.setPlaceholderText("Custom options (JSON format)")
        self.custom_options.setMaximumHeight(100)
        
        layout.addWidget(self.enabled)
        layout.addLayout(aggr_layout)
        layout.addWidget(self.stealth_mode)
        layout.addWidget(self.custom_options)

    def get_config(self):
        return {
            "enabled": self.enabled.isChecked(),
            "aggressiveness": self.aggr_level.value(),
            "stealth_mode": self.stealth_mode.isChecked(),
            "custom_options": self.custom_options.toPlainText()
        }

class ScanResult:
    def __init__(self, target_url, scan_type, results, timestamp=None):
        self.target_url = target_url
        self.scan_type = scan_type
        self.results = results
        self.timestamp = timestamp or datetime.now()

    def to_dict(self):
        return {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "results": self.results,
            "timestamp": self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data):
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)

class CommunicationsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.message_history = []
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Filter controls
        filter_frame = QFrame()
        filter_layout = QHBoxLayout(filter_frame)
        
        # Message type filter
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "All Messages",
            "Discovery",
            "Vulnerability",
            "Attack Vector",
            "Strategy",
            "Alert",
            "Insight"
        ])
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        
        # Priority filter
        self.priority_filter = QComboBox()
        self.priority_filter.addItems([
            "All Priorities",
            "High Priority (4-5)",
            "Medium Priority (2-3)",
            "Low Priority (1)"
        ])
        self.priority_filter.currentTextChanged.connect(self.apply_filters)
        
        filter_layout.addWidget(QLabel("Message Type:"))
        filter_layout.addWidget(self.type_filter)
        filter_layout.addWidget(QLabel("Priority:"))
        filter_layout.addWidget(self.priority_filter)
        
        layout.addWidget(filter_frame)
        
        # Communications display with fallback fonts
        self.comm_display = QTextEdit()
        self.comm_display.setReadOnly(True)
        self.comm_display.setStyleSheet("""
            QTextEdit {
                font-family: 'Consolas', 'Monaco', 'Menlo', 'DejaVu Sans Mono', 'Courier New', monospace;
                font-size: 10pt;
                line-height: 1.4;
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
        """)
        layout.addWidget(self.comm_display)
        
        # Auto-scroll checkbox
        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)
        layout.addWidget(self.auto_scroll)
        
        # Clear button
        clear_btn = QPushButton("Clear Communications")
        clear_btn.clicked.connect(self.clear_communications)
        layout.addWidget(clear_btn)
        
    def add_message(self, message: Message):
        """Add a new message to the communications view"""
        # Format message with color based on type
        color_map = {
            MessageType.DISCOVERY: "#4EC9B0",      # Teal
            MessageType.VULNERABILITY: "#F44747",   # Red
            MessageType.ATTACK_VECTOR: "#CE9178",   # Orange
            MessageType.STRATEGY: "#569CD6",        # Blue
            MessageType.ALERT: "#D16969",          # Pink
            MessageType.INSIGHT: "#608B4E"         # Green
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = color_map.get(message.type, "#D4D4D4")  # Default to light gray
        
        formatted_message = (
            f'<div style="margin-bottom: 10px;">'
            f'<span style="color: #858585;">[{timestamp}]</span> '
            f'<span style="color: {color};">{message.type.value}</span> '
            f'<span style="color: #858585;">from</span> '
            f'<span style="color: #9CDCFE;">{message.sender}</span> '
            f'<span style="color: #858585;">(Priority: {message.priority})</span><br>'
            f'<span style="color: #D4D4D4; margin-left: 20px;">'
            f'{json.dumps(message.content, indent=2)}</span>'
            f'</div>'
        )
        
        self.message_history.append({
            'type': message.type,
            'priority': message.priority,
            'html': formatted_message
        })
        
        self.apply_filters()
        
    def apply_filters(self):
        """Apply filters and update display"""
        type_filter = self.type_filter.currentText()
        priority_filter = self.priority_filter.currentText()
        
        filtered_messages = []
        for msg in self.message_history:
            # Apply type filter
            if type_filter != "All Messages" and msg['type'].value != type_filter:
                continue
                
            # Apply priority filter
            if priority_filter == "High Priority (4-5)" and msg['priority'] < 4:
                continue
            elif priority_filter == "Medium Priority (2-3)" and (msg['priority'] < 2 or msg['priority'] > 3):
                continue
            elif priority_filter == "Low Priority (1)" and msg['priority'] != 1:
                continue
                
            filtered_messages.append(msg['html'])
        
        # Update display
        self.comm_display.clear()
        self.comm_display.setHtml("".join(filtered_messages))
        
        # Auto-scroll if enabled
        if self.auto_scroll.isChecked():
            scrollbar = self.comm_display.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            
    def clear_communications(self):
        """Clear all communications"""
        self.message_history.clear()
        self.comm_display.clear()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowScout AI")
        self.setMinimumSize(1000, 800)
        
        # Initialize message bus
        self.message_bus = MessageBus()
        
        # Initialize assistants
        self.browser_assistant = BrowserAssistant(self.message_bus)
        self.terminal_assistant = TerminalAssistant(self.message_bus)
        self.attack_strategist = AttackStrategist(self.message_bus)
        
        # Initialize communications view
        self.communications_view = CommunicationsView()
        
        # Initialize scan history
        self.scan_history = []
        
        # Subscribe to message bus
        self.message_bus.subscribe_all(self._handle_message)
        
        self.setup_ui()

    async def initialize_assistants(self):
        """Initialize all assistants"""
        await self.browser_assistant.initialize()
        await self.terminal_assistant.initialize()
        await self.attack_strategist.initialize()

    async def shutdown_assistants(self):
        """Shutdown all assistants"""
        await self.browser_assistant.shutdown()
        await self.terminal_assistant.shutdown()
        await self.attack_strategist.shutdown()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("ShadowScout AI")
        header.setFont(QFont('Arial', 24, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Create tab widget
        tabs = QTabWidget()
        tabs.addTab(self.create_scan_tab(), "Active Scan")
        tabs.addTab(self.create_history_tab(), "Scan History")
        tabs.addTab(self.create_assistants_tab(), "Assistants")
        tabs.addTab(self.communications_view, "Communications")
        tabs.addTab(self.create_settings_tab(), "Settings")
        layout.addWidget(tabs)

    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Offensive Tools Configuration
        offensive_tools_group = QGroupBox("Offensive Tools Configuration")
        offensive_tools_layout = QFormLayout(offensive_tools_group)
        
        # Example configuration options
        self.xss_intensity = QSpinBox()
        self.xss_intensity.setRange(1, 5)
        self.xss_intensity.setValue(3)
        offensive_tools_layout.addRow("XSS Intensity:", self.xss_intensity)
        
        self.sqli_intensity = QSpinBox()
        self.sqli_intensity.setRange(1, 5)
        self.sqli_intensity.setValue(3)
        offensive_tools_layout.addRow("SQLi Intensity:", self.sqli_intensity)
        
        self.jwt_enabled = QCheckBox("Enable JWT Attacks")
        self.jwt_enabled.setChecked(True)
        offensive_tools_layout.addRow(self.jwt_enabled)
        
        layout.addWidget(offensive_tools_group)
        
        return widget

    def create_scan_tab(self):
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)

        # Target input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        input_layout = QHBoxLayout(input_frame)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g., https://example.com)")
        
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Stealth", "Standard", "Aggressive"])
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        
        input_layout.addWidget(self.url_input, stretch=7)
        input_layout.addWidget(self.scan_type, stretch=2)
        input_layout.addWidget(self.scan_button, stretch=1)
        layout.addWidget(input_frame)

        # Add offensive tools configuration
        self.offensive_tools = OffensiveToolsConfig()
        layout.addWidget(self.offensive_tools)

        # Progress section
        progress_frame = QFrame()
        progress_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        progress_layout = QVBoxLayout(progress_frame)
        
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addWidget(progress_frame)

        # Output section with real-time logging
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Scan results will appear here...")
        self.output_text.setStyleSheet("""
            QTextEdit {
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
                line-height: 1.4;
            }
        """)
        layout.addWidget(self.output_text, stretch=1)

        return scan_widget

    def create_assistants_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create configuration sections for each assistant
        self.assistant_configs = {}
        assistants = [
            "Browser Assistant", "Terminal Assistant", "Langchain Assistant",
            "Security Tools", "Attack Strategist", "Offensive Assistant"
        ]
        
        for assistant in assistants:
            config = AssistantConfig(assistant)
            self.assistant_configs[assistant] = config
            layout.addWidget(config)
        
        # Add save button
        save_btn = QPushButton("Save Assistant Configurations")
        save_btn.clicked.connect(self.save_assistant_configs)
        layout.addWidget(save_btn)
        
        scroll.setWidget(container)
        return scroll

    def create_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Create scrollable area for scan history
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        history_container = QWidget()
        self.history_layout = QVBoxLayout(history_container)
        
        # Add clear history button
        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self.clear_history)
        layout.addWidget(clear_btn)
        
        # Populate with existing scan history
        self.refresh_history_view()
        
        scroll.setWidget(history_container)
        layout.addWidget(scroll)
        
        return widget

    def create_scan_result_widget(self, scan_result):
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(frame)
        
        # Header with timestamp and target
        header = QLabel(f"Scan of {scan_result.target_url}")
        header.setFont(QFont('Arial', 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Timestamp and scan type
        info = QLabel(f"Time: {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | Type: {scan_result.scan_type}")
        layout.addWidget(info)
        
        # Detailed results
        results_text = QTextEdit()
        results_text.setReadOnly(True)
        results_text.setMaximumHeight(200)
        
        # Format results nicely
        formatted_results = json.dumps(scan_result.results, indent=2)
        results_text.setText(formatted_results)
        
        layout.addWidget(results_text)
        
        return frame

    def refresh_history_view(self):
        """Refresh the scan history view"""
        # Clear existing items
        for i in reversed(range(self.history_layout.count())):
            self.history_layout.itemAt(i).widget().setParent(None)
        
        # Add scan history items in reverse chronological order
        for scan_result in reversed(self.scan_history):
            widget = self.create_scan_result_widget(scan_result)
            self.history_layout.addWidget(widget)

    def clear_history(self):
        """Clear the scan history"""
        self.scan_history.clear()
        self.refresh_history_view()

    def load_scan_history(self):
        try:
            history_file = Path.home() / '.shadowscout' / 'scan_history.json'
            if history_file.exists():
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    self.scan_history = [ScanResult.from_dict(item) for item in data]
        except Exception as e:
            print(f"Error loading scan history: {e}")

    def save_scan_history(self):
        try:
            history_file = Path.home() / '.shadowscout' / 'scan_history.json'
            history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(history_file, 'w') as f:
                json.dump([scan.to_dict() for scan in self.scan_history], f)
        except Exception as e:
            print(f"Error saving scan history: {e}")

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QFrame, QGroupBox {
                background-color: #2d2d2d;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton {
                background-color: #0d47a1;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:disabled {
                background-color: #263238;
            }
            QLineEdit, QComboBox, QTextEdit, QSpinBox {
                background-color: #424242;
                color: white;
                padding: 8px;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
                color: white;
                background-color: #424242;
            }
            QProgressBar::chunk {
                background-color: #0d47a1;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2d2d2d;
            }
            QTabBar::tab {
                background-color: #424242;
                color: white;
                padding: 8px 20px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0d47a1;
            }
            QScrollArea {
                border: none;
            }
            QCheckBox {
                color: white;
            }
            QLabel {
                color: white;
            }
        """)

    def save_assistant_configs(self):
        configs = {name: config.get_config() 
                  for name, config in self.assistant_configs.items()}
        self.output_text.append("Assistant configurations saved:")
        self.output_text.append(str(configs))

    def start_scan(self):
        target_url = self.url_input.text().strip()
        if not target_url:
            self.output_text.setText("Please enter a target URL")
            return

        self.scan_button.setEnabled(False)
        self.output_text.clear()
        self.progress_bar.setValue(0)
        
        # Create scan configuration dictionary
        scan_config = {
            'type': self.scan_type.currentText(),
            'aggressiveness': 5,  # Default value
            'stealth_mode': False
        }
        
        # Get configurations
        assistant_configs = {name: config.get_config() 
                            for name, config in self.assistant_configs.items()}
        offensive_config = self.offensive_tools.get_config()
        
        # Update scan config based on assistant configs
        for config in assistant_configs.values():
            if config.get('enabled', True):
                scan_config['aggressiveness'] = max(scan_config['aggressiveness'], 
                                                  config.get('aggressiveness', 5))
                scan_config['stealth_mode'] = scan_config['stealth_mode'] or \
                                            config.get('stealth_mode', False)
        
        # Initialize assistants before starting scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.initialize_assistants())
        
        # Create and start worker thread
        self.worker = ScanWorker(target_url, scan_config,
                                assistant_configs, offensive_config)
        self.worker.progress.connect(self.update_progress)
        self.worker.status.connect(self.update_status)
        self.worker.log.connect(self.update_log)
        self.worker.finished.connect(self.scan_completed)
        self.worker.error.connect(self.scan_error)
        self.worker.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_status(self, status):
        self.status_label.setText(status)
        self.output_text.append(status)

    def scan_completed(self, results):
        """Enhanced scan completion handler with better logging"""
        self.scan_button.setEnabled(True)
        self.status_label.setText("Scan completed")
        self.progress_bar.setValue(100)
        
        # Log completion header
        self.update_log({
            'type': 'SUCCESS',
            'source': 'Scanner',
            'content': f'Scan completed for {self.url_input.text()}'
        })
        
        # Log results by category
        for category, findings in results.items():
            if isinstance(findings, dict) and findings.get('findings'):
                # Log category header
                self.update_log({
                    'type': 'INFO',
                    'source': category,
                    'content': f'Found {len(findings["findings"])} issues'
                })
                
                # Log individual findings
                for finding in findings['findings']:
                    self.update_log({
                        'type': finding.get('severity', 'INFO'),
                        'source': category,
                        'content': finding.get('description', 'No description provided')
                    })
        
        # Save to history
        scan_result = ScanResult(
            self.url_input.text(),
            self.scan_type.currentText(),
            results
        )
        self.scan_history.append(scan_result)
        self.save_scan_history()
        self.refresh_history_view()

    def scan_error(self, error_msg):
        """Enhanced error logging"""
        self.scan_button.setEnabled(True)
        self.status_label.setText("Error occurred")
        self.update_log({
            'type': 'ERROR',
            'source': 'Scanner',
            'content': error_msg
        })

    def update_log(self, message):
        """Enhanced logging with better formatting and assistant communications"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Format based on message type
        if isinstance(message, dict):
            # Handle structured log messages
            msg_type = message.get('type', 'INFO')
            source = message.get('source', 'System')
            content = message.get('content', '')
            
            formatted_msg = f"""<div style='margin: 2px 0;'>
                <span style='color: #666666'>[{timestamp}]</span> 
                <span style='color: {self._get_type_color(msg_type)}'>{msg_type}</span> 
                <span style='color: #4EC9B0'>{source}</span>: 
                <span style='color: #D4D4D4'>{html.escape(str(content))}</span>
            </div>"""
            
        elif " -> " in message:  # Assistant communication
            source, target = message.split(" -> ", 1)
            formatted_msg = f"""<div style='margin: 2px 0; padding-left: 20px;'>
                <span style='color: #666666'>[{timestamp}]</span> 
                <span style='color: #4EC9B0'>{source}</span> 
                <span style='color: #666666'>→</span> 
                <span style='color: #4EC9B0'>{target}</span>
            </div>"""
            
        else:  # Regular log message
            formatted_msg = f"""<div style='margin: 2px 0;'>
                <span style='color: #666666'>[{timestamp}]</span> 
                <span style='color: #D4D4D4'>{html.escape(message)}</span>
            </div>"""

        self.output_text.insertHtml(formatted_msg)
        
        # Auto-scroll to bottom
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _get_type_color(self, msg_type):
        """Get color for different message types"""
        colors = {
            'INFO': '#569CD6',      # Blue
            'WARNING': '#CE9178',    # Orange
            'ERROR': '#F44747',      # Red
            'SUCCESS': '#608B4E',    # Green
            'PROCESS': '#9CDCFE',    # Light Blue
            'ALERT': '#D16969',      # Pink
            'COMM': '#4EC9B0'        # Teal
        }
        return colors.get(msg_type.upper(), '#D4D4D4')  # Default to light gray

    def _handle_message(self, message: Message):
        """Handle incoming messages from the message bus - non-async version"""
        try:
            self.communications_view.add_message(message)
        except Exception as e:
            print(f"Error handling message: {e}")

    def closeEvent(self, event):
        """Handle application shutdown"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.shutdown_assistants())
        event.accept()