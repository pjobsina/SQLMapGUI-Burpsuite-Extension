# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab
from java.util import ArrayList

from javax.swing import (
    JPanel, JButton, JCheckBox, JScrollPane, JTextPane,
    JTable, JMenuItem, ListSelectionModel, JSplitPane,
    JTextField, JComboBox, BoxLayout, JTextArea,
    BorderFactory, JSeparator, JLabel, JFileChooser
)
from javax.swing.table import DefaultTableModel
from javax.swing.text import SimpleAttributeSet, StyleConstants
from javax.swing import UIManager

from java.awt import Color, Font, BorderLayout, FlowLayout, Dimension, Toolkit
from java.awt.datatransfer import StringSelection

import subprocess
import threading
import time
import os
import tempfile
import codecs
import re

# ===================== WINDOWS 11 CONFIG =====================
PYTHON_EXE = r"C:\Security-Tools\python.exe"
SQLMAP_PY  = r"C:\Security-Tools\sqlmap\sqlmap.py"
REQ_DIR = os.path.join(tempfile.gettempdir(), "burp-sqlmap-reqs")
# =============================================================

try:
    if not os.path.isdir(REQ_DIR):
        os.makedirs(REQ_DIR)
except:
    pass


class WrapTextPane(JTextPane):
    def getScrollableTracksViewportWidth(self):
        return True


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLMap GUI")

        self.saved_requests = []
        self.proc = None

        self.panel = JPanel(BorderLayout())

        # ===== Output (LEFT) with wrapping =====
        self.output_pane = WrapTextPane()
        self.output_pane.setEditable(False)
        self.output_pane.setFont(Font("Consolas", Font.PLAIN, 13))

        output_scroll = JScrollPane(self.output_pane)
        output_scroll.setBorder(BorderFactory.createTitledBorder("Output (wrapped)"))
        output_scroll.getVerticalScrollBar().setUnitIncrement(16)
        try:
            output_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        except:
            pass

        # ===== Saved requests table (RIGHT - bottom) =====
        self.req_table_model = DefaultTableModel(["Saved Requests (-r)"], 0)
        self.req_table = JTable(self.req_table_model)
        self.req_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.req_table.setRowHeight(22)
        self.req_table.setFillsViewportHeight(True)
        table_scroll = JScrollPane(self.req_table)
        table_scroll.setBorder(BorderFactory.createTitledBorder("Captured requests (optional)"))

        # ===== Controls panel (RIGHT - top) =====
        self.controls_panel = JPanel()
        self.controls_panel.setLayout(BoxLayout(self.controls_panel, BoxLayout.Y_AXIS))
        self.controls_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # --- Target / Auth ---
        self.controls_panel.add(self._section_title("Target / Auth"))
        self.target_checkbox = JCheckBox("Use Target URL (-u)")
        self.target_field = JTextField("http://target.com/page.php?id=1")
        self.controls_panel.add(self._row(self.target_checkbox, self.target_field))

        self.param_checkbox = JCheckBox("Parameter (-p)")
        self.param_field = JTextField("id")
        self.controls_panel.add(self._row(self.param_checkbox, self.param_field))

        self.cookies_checkbox = JCheckBox("Cookie (--cookie)")
        self.cookies_field = JTextField("")
        self.controls_panel.add(self._row(self.cookies_checkbox, self.cookies_field))

        self.headers_checkbox = JCheckBox("Headers (--headers)")
        self.headers_area = self._make_text_area(5, "User-Agent: Mozilla/5.0\nAccept: */*")
        self.headers_scroll = JScrollPane(self.headers_area)
        self.headers_scroll.setBorder(BorderFactory.createEtchedBorder())
        self.controls_panel.add(self._row(self.headers_checkbox, self.headers_scroll))

        self.data_checkbox = JCheckBox("POST body (--data)")
        self.data_area = self._make_text_area(4, "")
        self.data_scroll = JScrollPane(self.data_area)
        self.data_scroll.setBorder(BorderFactory.createEtchedBorder())
        self.controls_panel.add(self._row(self.data_checkbox, self.data_scroll))

        self.controls_panel.add(self._separator())

        # --- Core tuning ---
        self.controls_panel.add(self._section_title("Core tuning"))
        self.options = []

        def add_option(label, takes_value=False, default_value=""):
            box = JCheckBox(label)
            field = JTextField(default_value) if takes_value else None
            self.options.append((box, field))
            self.controls_panel.add(self._row(box, field if field else None))

        def add_dropdown(label, values, default_index=0):
            box = JCheckBox(label)
            dropdown = JComboBox(values)
            try:
                dropdown.setSelectedIndex(default_index)
            except:
                pass
            self.options.append((box, dropdown))
            self.controls_panel.add(self._row(box, dropdown))

        add_option("--risk", True, "3")
        add_option("--level", True, "5")
        add_dropdown("--threads", [str(i) for i in range(1, 11)], 4)
        add_option("--delay", True, "")
        add_option("--crawl", True, "")
        add_option("--proxy", True, "http://127.0.0.1:8080")
        add_option("--random-agent")

        self.controls_panel.add(self._separator())

        # --- Technique (multi-check) ---
        self.controls_panel.add(self._section_title("Injection technique"))
        self.technique_master = JCheckBox("--technique")
        self.technique_boxes = {
            "B": JCheckBox("B"),
            "T": JCheckBox("T"),
            "E": JCheckBox("E"),
            "U": JCheckBox("U"),
            "S": JCheckBox("S"),
            "Q": JCheckBox("Q"),
            "A": JCheckBox("A"),
        }
        tech_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        tech_row.add(self.technique_master)
        for k in ["B", "T", "E", "U", "S", "Q", "A"]:
            tech_row.add(self.technique_boxes[k])
        tech_row.setAlignmentX(0.0)
        self.controls_panel.add(tech_row)

        self.controls_panel.add(self._separator())

        # --- Enumeration / dump (BACK TO 1 ROW PER OPTION) ---
        self.controls_panel.add(self._section_title("Enumeration / dump"))
        add_option("--dbs")
        add_option("--tables")
        add_option("--columns")
        add_option("--dump")
        add_option("--dump-all")
        add_option("--current-user")
        add_option("--current-db")
        add_option("--passwords")
        add_option("--banner")
        add_option("--flush-session")

        self.controls_panel.add(self._separator())

        # --- Advanced ---
        self.controls_panel.add(self._section_title("Advanced"))
        add_option("--tamper", True, "space2comment")
        add_option("--dbms", True, "")
        add_option("--read-file", True, "")
        add_option("--file-write", True, "")
        add_option("--file-dest", True, "")
        add_option("-D", True, "")
        add_option("-T", True, "")
        add_option("-C", True, "")

        controls_scroll = JScrollPane(self.controls_panel)
        controls_scroll.setBorder(BorderFactory.createTitledBorder("Options"))
        controls_scroll.getVerticalScrollBar().setUnitIncrement(16)

        # ===== Buttons / console controls =====
        self.run_button = JButton("Run", actionPerformed=self.run_sqlmap)
        self.stop_button = JButton("Stop", actionPerformed=self.kill_sqlmap)
        self.clear_button = JButton("Clear output", actionPerformed=self.clear_output)
        self.copy_button = JButton("Copy output", actionPerformed=self.copy_output)
        self.save_button = JButton("Save output", actionPerformed=self.save_output)

        self.scroll_lock = JCheckBox("Scroll lock")
        self.timestamps = JCheckBox("Timestamps")
        self.timestamps.setSelected(True)

        btns = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        btns.add(self.run_button)
        btns.add(self.stop_button)
        btns.add(self.clear_button)
        btns.add(self.copy_button)
        btns.add(self.save_button)
        btns.add(self.scroll_lock)
        btns.add(self.timestamps)

        right = JPanel(BorderLayout())
        right.add(btns, BorderLayout.NORTH)
        right.add(controls_scroll, BorderLayout.CENTER)
        right.add(table_scroll, BorderLayout.SOUTH)
        table_scroll.setPreferredSize(Dimension(520, 220))

        split_main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, output_scroll, right)
        split_main.setResizeWeight(0.62)
        self.panel.add(split_main, BorderLayout.CENTER)

        self._apply_theme()

        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "SQLMap GUI"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("Send to SQLMap (save -r)", actionPerformed=lambda x: self.save_request(invocation)))
        menu.add(JMenuItem("Send to SQLMap (AUTO-FILL target/headers/cookies/body)",
                          actionPerformed=lambda x: self.autofill_from_invocation(invocation)))
        return menu

    # ----------------- UI helpers -----------------
    def _section_title(self, text):
        lbl = JLabel(text)
        lbl.setFont(Font(lbl.getFont().getName(), Font.BOLD, 12))
        lbl.setAlignmentX(0.0)
        return lbl

    def _separator(self):
        sep = JSeparator()
        sep.setMaximumSize(Dimension(9999, 10))
        return sep

    def _row(self, left_component, right_component):
        row = JPanel(BorderLayout(8, 0))
        row.setAlignmentX(0.0)
        row.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0))

        left_wrap = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        left_wrap.add(left_component)
        row.add(left_wrap, BorderLayout.WEST)

        if right_component is None:
            row.add(JPanel(), BorderLayout.CENTER)
        else:
            row.add(right_component, BorderLayout.CENTER)
        return row

    def _make_text_area(self, rows, default_text):
        ta = JTextArea(rows, 40)
        ta.setText(default_text)
        ta.setLineWrap(True)
        ta.setWrapStyleWord(True)
        ta.setFont(Font("Consolas", Font.PLAIN, 12))
        return ta

    def _apply_theme(self):
        bg = UIManager.getColor("TextArea.background")
        fg = UIManager.getColor("TextArea.foreground")
        caret = UIManager.getColor("TextArea.caretForeground")
        if bg is None:
            bg = Color(30, 30, 30)
        if fg is None:
            fg = Color(230, 230, 230)
        if caret is None:
            caret = fg

        def style_text_component(comp):
            try:
                comp.setBackground(bg)
                comp.setForeground(fg)
                comp.setCaretColor(caret)
            except:
                pass

        style_text_component(self.target_field)
        style_text_component(self.param_field)
        style_text_component(self.cookies_field)
        style_text_component(self.headers_area)
        style_text_component(self.data_area)
        style_text_component(self.output_pane)

    # ----------------- Output helpers -----------------
    def clear_output(self, _):
        try:
            self.output_pane.setText("")
        except:
            pass

    def copy_output(self, _):
        try:
            txt = self.output_pane.getText() or ""
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(txt), None)
            self.append_output("[+] Output copied to clipboard.\n", "green")
        except Exception as e:
            self.append_output("[!] Copy failed: %s\n" % str(e), "red")

    def save_output(self, _):
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Save output")
            if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
                fpath = chooser.getSelectedFile().getAbsolutePath()
                f = codecs.open(fpath, "w", encoding="utf-8")
                try:
                    f.write(self.output_pane.getText() or "")
                finally:
                    f.close()
                self.append_output("[+] Saved output to: %s\n" % fpath, "green")
        except Exception as e:
            self.append_output("[!] Save failed: %s\n" % str(e), "red")

    def _ts(self):
        if not self.timestamps.isSelected():
            return ""
        try:
            return time.strftime("[%H:%M:%S] ")
        except:
            return ""

    _ansi_re = re.compile(r"\x1b\[[0-9;]*m")

    def _strip_ansi(self, s):
        try:
            return self._ansi_re.sub("", s)
        except:
            return s

    def append_output(self, text, color):
        doc = self.output_pane.getStyledDocument()
        style = SimpleAttributeSet()

        if color == "red":
            StyleConstants.setForeground(style, Color(255, 80, 80))
        elif color == "orange":
            StyleConstants.setForeground(style, Color(255, 180, 80))
        elif color == "green":
            StyleConstants.setForeground(style, Color(120, 220, 120))
        else:
            fg = UIManager.getColor("TextArea.foreground")
            if fg is None:
                fg = Color(220, 220, 220)
            StyleConstants.setForeground(style, fg)

        StyleConstants.setFontSize(style, 13)
        StyleConstants.setBold(style, False)

        safe = self._strip_ansi(text)
        if safe and not safe.startswith("\n"):
            safe = self._ts() + safe

        doc.insertString(doc.getLength(), safe, style)

        if not self.scroll_lock.isSelected():
            try:
                self.output_pane.setCaretPosition(doc.getLength())
            except:
                pass

    # ----------------- AUTO-FILL from Burp request -----------------
    def autofill_from_invocation(self, invocation):
        reqs = invocation.getSelectedMessages()
        if not reqs:
            self.append_output("[-] No request selected.\n", "orange")
            return
        self._fill_from_request_message(reqs[0])

    def _fill_from_request_message(self, message):
        try:
            req_info = self._helpers.analyzeRequest(message)
            url = req_info.getUrl().toString()
            headers = list(req_info.getHeaders())
            body_bytes = message.getRequest()[req_info.getBodyOffset():]
            body = self._helpers.bytesToString(body_bytes)

            cookie_val = ""
            cleaned_headers = []

            for h in headers[1:]:
                hl = h.lower()
                if hl.startswith("host:"):
                    continue
                if hl.startswith("cookie:"):
                    cookie_val = h.split(":", 1)[1].strip()
                    continue
                cleaned_headers.append(h)

            self.target_checkbox.setSelected(True)
            self.target_field.setText(url)

            self.headers_checkbox.setSelected(True)
            self.headers_area.setText("\n".join(cleaned_headers))

            if cookie_val:
                self.cookies_checkbox.setSelected(True)
                self.cookies_field.setText(cookie_val)

            if body and body.strip():
                self.data_checkbox.setSelected(True)
                self.data_area.setText(body)

            self.append_output("[+] Auto-filled target/headers/cookies/body from request.\n", "green")
        except Exception as e:
            self.append_output("[!] Auto-fill failed: %s\n" % str(e), "red")

    # ----------------- Save request (-r) -----------------
    def save_request(self, invocation):
        reqs = invocation.getSelectedMessages()
        if not reqs:
            return

        request_info = self._helpers.analyzeRequest(reqs[0])
        headers = request_info.getHeaders()
        body = self._helpers.bytesToString(reqs[0].getRequest()[request_info.getBodyOffset():])

        timestamp = int(time.time())
        filename = os.path.join(REQ_DIR, "sqlmap-%d.req" % timestamp)

        f = codecs.open(filename, "w", encoding="utf-8")
        try:
            for h in headers:
                f.write(unicode(h) + u"\n")
            f.write(u"\n" + unicode(body))
        finally:
            f.close()

        self.saved_requests.append(filename)
        self.req_table_model.addRow([filename])
        self.append_output("[+] Saved: %s\n" % filename, "gray")

    # ----------------- Run / Stop -----------------
    def run_sqlmap(self, _):
        cmd = [PYTHON_EXE, SQLMAP_PY, "--batch"]

        if self.target_checkbox.isSelected():
            target = (self.target_field.getText() or "").strip()
            if not target:
                self.append_output("[-] Target URL is empty.\n", "red")
                return
            cmd.extend(["-u", target])
        else:
            row = self.req_table.getSelectedRow()
            if row == -1:
                self.append_output("[-] Select a saved request OR enable Target URL (-u).\n", "red")
                return
            filename = self.req_table_model.getValueAt(row, 0)
            cmd.extend(["-r", filename])

        if self.param_checkbox.isSelected():
            param = (self.param_field.getText() or "").strip()
            if not param:
                self.append_output("[-] -p enabled but no parameter specified.\n", "orange")
                return
            cmd.extend(["-p", param])

        if self.headers_checkbox.isSelected():
            hdrs = (self.headers_area.getText() or "").replace("\r\n", "\n").strip()
            if not hdrs:
                self.append_output("[-] --headers enabled but empty.\n", "orange")
                return
            cmd.extend(["--headers", hdrs])

        if self.cookies_checkbox.isSelected():
            ck = (self.cookies_field.getText() or "").strip()
            if not ck:
                self.append_output("[-] --cookie enabled but empty.\n", "orange")
                return
            cmd.extend(["--cookie", ck])

        if self.data_checkbox.isSelected():
            data = (self.data_area.getText() or "").strip()
            if not data:
                self.append_output("[-] --data enabled but empty.\n", "orange")
                return
            cmd.extend(["--data", data])

        for checkbox, field in self.options:
            if checkbox.isSelected():
                if isinstance(field, JComboBox):
                    value = field.getSelectedItem()
                    if value:
                        cmd.extend([checkbox.getText(), str(value)])
                elif field:
                    value = field.getText().strip()
                    if value:
                        cmd.extend([checkbox.getText(), value])
                else:
                    cmd.append(checkbox.getText())

        if self.technique_master.isSelected():
            tech = ""
            for k in ["B", "T", "E", "U", "S", "Q", "A"]:
                if self.technique_boxes[k].isSelected():
                    tech += k
            if not tech:
                self.append_output("[-] --technique enabled but none selected.\n", "orange")
                return
            cmd.extend(["--technique", tech])

        self.append_output("[+] Running:\n%s\n\n" % " ".join(cmd), "gray")

        def execute():
            try:
                creationflags = 0
                try:
                    creationflags = subprocess.CREATE_NO_WINDOW
                except:
                    creationflags = 0

                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=creationflags
                )

                for line in iter(self.proc.stdout.readline, b''):
                    if not line:
                        break

                    try:
                        decoded = line.decode("utf-8", "ignore")
                    except:
                        try:
                            decoded = line.decode("cp1252", "ignore")
                        except:
                            decoded = str(line)

                    decoded = decoded.rstrip()

                    if "vulnerable" in decoded.lower():
                        self.append_output(decoded + "\n", "green")
                    elif "[warning]" in decoded.lower():
                        self.append_output(decoded + "\n", "orange")
                    elif "[critical]" in decoded.lower() or "[error]" in decoded.lower():
                        self.append_output(decoded + "\n", "red")
                    else:
                        self.append_output(decoded + "\n", "gray")

                try:
                    self.proc.stdout.close()
                except:
                    pass
                self.proc = None

            except Exception as e:
                self.append_output("[!] Exception: %s\n" % str(e), "red")

        threading.Thread(target=execute).start()

    def kill_sqlmap(self, _):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except:
                pass
            self.append_output("[!] SQLMap process terminated.\n", "red")
            self.proc = None
        else:

            self.append_output("[!] No active scan to kill.\n", "orange")
