import sys
import csv
import time
import asyncio
import ipaddress
import ssl
import struct
import os
import json
from collections import Counter
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLineEdit, QPushButton, QTableWidget,
                               QHeaderView, QMessageBox, QFileDialog,
                               QLabel, QAbstractItemView, QLineEdit, QTableView,
                               QTableWidgetItem, QMenu, QWidgetAction, QListWidget,
                               QListWidgetItem, QSplitter)
from PySide6.QtCore import Qt, Signal, QThread, QSortFilterProxyModel, QPoint, QRect
from PySide6.QtGui import QColor, QStandardItemModel, QStandardItem, QPainter, QPainterPath
import aiohttp

# --- 核心逻辑：DNS 查询引擎 ---

class DNSQueryEngine:
    @staticmethod
    def build_dns_query(domain):
        transaction_id = b'\xaa\xbb'
        flags = b'\x01\x00'
        counts = struct.pack('>HHHH', 1, 0, 0, 0)
        query = b''
        for label in domain.split('.'):
            query += bytes([len(label)]) + label.encode('ascii')
        query += b'\x00' + struct.pack('>HH', 1, 1)
        return transaction_id + flags + counts + query

    @staticmethod
    def parse_dns_response(data):
        try:
            if len(data) < 12: return []
            idx = 12
            while data[idx] != 0: idx += data[idx] + 1
            idx += 5
            ips = []
            while idx < len(data) - 12:
                if data[idx] & 0xC0 == 0xC0: idx += 2
                else:
                    while data[idx] != 0: idx += data[idx] + 1
                    idx += 1
                if idx + 10 > len(data): break
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[idx:idx+10])
                idx += 10
                if rtype == 1 and rdlength == 4:
                    ip = ".".join(str(b) for b in data[idx:idx+4])
                    ips.append(ip)
                idx += rdlength
            return ips
        except:
            return ["Parse Error"]

    @staticmethod
    async def query_doh(session, url, domain, timeout):
        start = time.time()
        try:
            query = DNSQueryEngine.build_dns_query(domain)
            async with session.post(url, data=query, 
                                    headers={"Content-Type": "application/dns-message",
                                             "Accept": "application/dns-message"},
                                    timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    ips = DNSQueryEngine.parse_dns_response(data)
                    return {"ips": ips, "time": round((time.time() - start) * 1000, 2)}
                return {"ips": [f"HTTP {resp.status}"], "time": round((time.time() - start) * 1000, 2)}
        except asyncio.TimeoutError:
            return {"ips": ["Timeout"], "time": timeout * 1000}
        except Exception as e:
            return {"ips": [str(e)[:30]], "time": round((time.time() - start) * 1000, 2)}

    @staticmethod
    async def query_dot(reader, writer, domain, timeout):
        start = time.time()
        try:
            query = DNSQueryEngine.build_dns_query(domain)
            writer.write(struct.pack('>H', len(query)) + query)
            await writer.drain()
            len_data = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            resp_len = struct.unpack('>H', len_data)[0]
            data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=timeout)
            ips = DNSQueryEngine.parse_dns_response(data)
            return {"ips": ips, "time": round((time.time() - start) * 1000, 2)}
        except asyncio.TimeoutError:
            return {"ips": ["Timeout"], "time": timeout * 1000}
        except Exception as e:
            return {"ips": [str(e)[:30]], "time": round((time.time() - start) * 1000, 2)}
        finally:
            writer.close()

    @staticmethod
    async def query_udp(host, port, domain, timeout):
        start = time.time()
        loop = asyncio.get_running_loop()
        class DNSProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.future = loop.create_future()
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, addr):
                if not self.future.done():
                    self.future.set_result(data)
            def error_received(self, exc):
                if not self.future.done():
                    self.future.set_exception(exc)
            def connection_lost(self, exc):
                if not self.future.done():
                    self.future.set_exception(exc or Exception("Connection lost"))
        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(DNSProtocol, remote_addr=(host, port)),
                timeout=timeout
            )
            query = DNSQueryEngine.build_dns_query(domain)
            transport.sendto(query)
            data = await asyncio.wait_for(protocol.future, timeout=timeout)
            transport.close()
            ips = DNSQueryEngine.parse_dns_response(data)
            return {"ips": ips, "time": round((time.time() - start) * 1000, 2)}
        except asyncio.TimeoutError:
            return {"ips": ["Timeout"], "time": timeout * 1000}
        except Exception as e:
            return {"ips": [str(e)[:30]], "time": round((time.time() - start) * 1000, 2)}

# --- 后台测试线程 ---

class TestWorker(QThread):
    finished = Signal(list)
    
    def __init__(self, servers, domain):
        super().__init__()
        self.servers = servers
        self.domain = domain
        
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(self.async_run())
        loop.close()
        self.finished.emit(results)
        
    async def async_run(self):
        results = []
        timeout = 1.0
        async with aiohttp.ClientSession() as session:
            tasks = []
            for srv in self.servers:
                if srv['type'] == 'DoH':
                    tasks.append(DNSQueryEngine.query_doh(session, srv['url'], self.domain, timeout))
                elif srv['type'] == 'DoT':
                    ctx = ssl.create_default_context()
                    reader, writer = await asyncio.open_connection(srv['host'], int(srv['port']), ssl=ctx)
                    tasks.append(DNSQueryEngine.query_dot(reader, writer, self.domain, timeout))
                else:
                    tasks.append(DNSQueryEngine.query_udp(srv['host'], int(srv['port']), self.domain, timeout))
            
            res_list = await asyncio.gather(*tasks)
            for srv, res in zip(self.servers, res_list):
                results.append({
                    "name": srv['name'],
                    "type": srv['type'],
                    "ips": ", ".join(res['ips']),
                    "time": res['time']
                })
        return results

# --- Excel 风格筛选/排序 ---

class ExcelFilterProxyModel(QSortFilterProxyModel):
    """支持「全局关键字」+「逐列勾选值」的筛选代理模型"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._col_values = {}   # 列号 -> 允许显示的值集合(str)
        self._keyword = ""

    # --- 列筛选 ---
    def set_column_values(self, col, values):
        """values 为 None 表示清除该列筛选；为空集合表示该列不显示任何行"""
        if values is None:
            if self._col_values.pop(col, None) is None:
                return
        else:
            self._col_values[col] = set(values)
        self.invalidateFilter()

    def clear_all_columns(self):
        if not self._col_values:
            return
        self._col_values.clear()
        self.invalidateFilter()

    # --- 全局关键字 ---
    def set_global_keyword(self, text):
        kw = (text or "").strip().lower()
        if kw == self._keyword:
            return
        self._keyword = kw
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        if model is None:
            return True

        for col, allowed in self._col_values.items():
            value = model.data(model.index(source_row, col, source_parent), Qt.DisplayRole)
            if str(value) not in allowed:
                return False

        if self._keyword:
            for col in range(model.columnCount(source_parent)):
                value = model.data(model.index(source_row, col, source_parent), Qt.DisplayRole)
                if self._keyword in str(value).lower():
                    return True
            return False

        return True


class ExcelFilterHeader(QHeaderView):
    """带漏斗按钮的表头：点击漏斗 -> Excel 风格的值勾选筛选 + 排序"""

    filterChanged = Signal(int, object)   # (列号, 允许的值集合 或 None)

    BTN_SIZE = 12
    BTN_MARGIN = 5
    DEFAULT_WIDTHS = [140, 80, 360, 100]   # 服务器名称 / 协议 / 解析结果 / 耗时

    def __init__(self, table, proxy):
        super().__init__(Qt.Horizontal, table)
        self.table = table
        self.proxy = proxy
        self.setSectionsClickable(True)
        self.setHighlightSections(True)
        self.setMouseTracking(True)
        self.setMinimumHeight(26)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        self._filters = {}        # 列号 -> 当前生效的值集合
        self._hover_col = -1
        self._updating = False

    # ---------- 对外接口 ----------
    def reset_filters(self):
        self._filters.clear()
        self.viewport().update()

    # ---------- 列宽 ----------
    def auto_resize_column(self, col, max_width=520):
        """按当前显示内容自动调整某一列的宽度"""
        model = self.model()
        if model is None or col < 0:
            return
        fm = self.table.fontMetrics()
        h_fm = self.fontMetrics()
        title = model.headerData(col, Qt.Horizontal, Qt.DisplayRole) or ""
        width = h_fm.horizontalAdvance(str(title)) + self.BTN_SIZE + self.BTN_MARGIN * 2 + 14
        for row in range(model.rowCount()):
            value = model.data(model.index(row, col), Qt.DisplayRole)
            if value is None:
                continue
            width = max(width, fm.horizontalAdvance(str(value)) + 16)
        self.resizeSection(col, max(48, min(width, max_width)))

    def auto_resize_all(self):
        for col in range(self.count()):
            self.auto_resize_column(col)

    def restore_default_widths(self):
        for col, width in enumerate(self.DEFAULT_WIDTHS):
            if col < self.count():
                self.resizeSection(col, width)

    def _boundary_col(self, pos):
        """判断鼠标是否落在某列右侧的调整手柄上"""
        for col in range(self.count()):
            if self.isSectionHidden(col):
                continue
            if self._button_rect(col).contains(pos):
                return -1
            edge = self.sectionViewportPosition(col) + self.sectionSize(col)
            if abs(pos.x() - edge) <= 5 and col < self.count() - 1:
                return col
        return -1

    def is_filtered(self, col):
        return col in self._filters

    # ---------- 漏斗按钮 ----------
    def _button_rect(self, col):
        size = self.BTN_SIZE
        x = self.sectionViewportPosition(col) + self.sectionSize(col) - size - self.BTN_MARGIN
        y = (self.height() - size) // 2
        return QRect(int(x), int(y), size, size)

    @staticmethod
    def _funnel_path(rect):
        x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
        p = QPainterPath()
        p.moveTo(x, y)
        p.lineTo(x + w, y)
        p.lineTo(x + w * 0.62, y + h * 0.45)
        p.lineTo(x + w * 0.62, y + h)
        p.lineTo(x + w * 0.38, y + h)
        p.lineTo(x + w * 0.38, y + h * 0.45)
        p.closeSubpath()
        return p

    def paintEvent(self, event):
        super().paintEvent(event)          # 保留系统绘制的表头文字与排序箭头
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        rect = event.rect()
        for col in range(self.count()):
            if self.isSectionHidden(col):
                continue
            btn = self._button_rect(col)
            if not btn.intersects(rect):
                continue
            if self.is_filtered(col):
                painter.setBrush(QColor("#1a73e8"))
            elif col == self._hover_col:
                painter.setBrush(QColor("#5f6368"))
            else:
                painter.setBrush(QColor("#9aa0a6"))
            painter.drawPath(self._funnel_path(btn))
        painter.end()

    def mousePressEvent(self, event):
        col = self.logicalIndexAt(event.position().toPoint() if hasattr(event, "position") else event.pos())
        pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        if col >= 0 and self._button_rect(col).contains(pos):
            anchor_x = self.sectionViewportPosition(col) + self.sectionSize(col) - self.BTN_SIZE - self.BTN_MARGIN
            self.show_filter_menu(col, self.mapToGlobal(QPoint(int(anchor_x), self.height())))
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        col = self.logicalIndexAt(pos)
        hover = col if (col >= 0 and self._button_rect(col).contains(pos)) else -1
        if hover != self._hover_col:
            self._hover_col = hover
            self.viewport().update()
        super().mouseMoveEvent(event)

    def mouseDoubleClickEvent(self, event):
        """双击列边界 -> 该列自动适应内容（同 Excel）"""
        pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        col = self._boundary_col(pos)
        if col >= 0:
            self.auto_resize_column(col)
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def _show_context_menu(self, pos):
        col = self.logicalIndexAt(pos)
        menu = QMenu(self)
        if col >= 0:
            title = self.model().headerData(col, Qt.Horizontal, Qt.DisplayRole) or f"第{col + 1}列"
            menu.addAction(f"自动调整「{title}」列宽").triggered.connect(
                lambda: self.auto_resize_column(col))
        menu.addAction("自动调整所有列宽").triggered.connect(self.auto_resize_all)
        menu.addSeparator()
        act_reset = menu.addAction("恢复默认列宽")
        act_reset.triggered.connect(self.restore_default_widths)
        menu.exec(self.mapToGlobal(pos))

    def leaveEvent(self, event):
        if self._hover_col != -1:
            self._hover_col = -1
            self.viewport().update()
        super().leaveEvent(event)

    # ---------- 取值 ----------
    def _column_values(self, col):
        src = self.proxy.sourceModel()
        values, seen = [], set()
        if src is None:
            return values
        for row in range(src.rowCount()):
            v = src.data(src.index(row, col), Qt.DisplayRole)
            v = "" if v is None else str(v)
            if v not in seen:
                seen.add(v)
                values.append(v)
        try:
            values.sort(key=lambda s: (s == "", s.lower()))
        except Exception:
            values.sort()
        return values

    @staticmethod
    def _is_numeric(values):
        vals = [v for v in values if v.strip()]
        if not vals:
            return False
        for v in vals:
            try:
                float(v)
            except ValueError:
                return False
        return True

    @staticmethod
    def _to_float(text, default=None):
        text = (text or "").strip()
        if not text:
            return default
        try:
            return float(text)
        except ValueError:
            return default

    # ---------- 筛选菜单 ----------
    def show_filter_menu(self, col, global_pos):
        values = self._column_values(col)
        numeric = self._is_numeric(values)
        current = self._filters.get(col)

        menu = QMenu(self)
        menu.addAction("升序排序").triggered.connect(
            lambda: self.table.sortByColumn(col, Qt.AscendingOrder))
        menu.addAction("降序排序").triggered.connect(
            lambda: self.table.sortByColumn(col, Qt.DescendingOrder))
        menu.addSeparator()

        panel = QWidget()
        vbox = QVBoxLayout(panel)
        vbox.setContentsMargins(6, 4, 6, 4)
        vbox.setSpacing(4)

        search = QLineEdit()
        search.setPlaceholderText("搜索值…")
        vbox.addWidget(search)

        lst = QListWidget()
        lst.setMaximumHeight(260)
        lst.setMinimumWidth(200)
        self._updating = True
        for v in values:
            item = QListWidgetItem(v if v != "" else "(空白)")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setData(Qt.UserRole, v)
            item.setCheckState(Qt.Unchecked if (current is not None and v not in current) else Qt.Checked)
            lst.addItem(item)
        self._updating = False
        vbox.addWidget(lst, 1)

        range_widget = None
        min_edit = max_edit = None
        if numeric:
            range_widget = QWidget()
            rbox = QHBoxLayout(range_widget)
            rbox.setContentsMargins(0, 0, 0, 0)
            rbox.setSpacing(4)
            min_edit = QLineEdit()
            min_edit.setPlaceholderText("≥ 最小")
            max_edit = QLineEdit()
            max_edit.setPlaceholderText("≤ 最大")
            rbox.addWidget(QLabel("范围"))
            rbox.addWidget(min_edit, 1)
            rbox.addWidget(max_edit, 1)
            vbox.addWidget(range_widget)

        btns = QHBoxLayout()
        btn_all = QPushButton("全选")
        btn_none = QPushButton("清空")
        btn_ok = QPushButton("确定")
        btns.addWidget(btn_all)
        btns.addWidget(btn_none)
        btns.addStretch(1)
        btns.addWidget(btn_ok)
        vbox.addLayout(btns)

        def apply_filter(*_):
            if self._updating:
                return
            checked = set()
            for i in range(lst.count()):
                item = lst.item(i)
                if item.checkState() == Qt.Checked:
                    checked.add(item.data(Qt.UserRole))
            if numeric and range_widget is not None:
                lo = self._to_float(min_edit.text())
                hi = self._to_float(max_edit.text())
                kept = set()
                for v in checked:
                    if v == "":
                        kept.add(v)
                        continue
                    try:
                        num = float(v)
                    except ValueError:
                        kept.add(v)
                        continue
                    if (lo is None or num >= lo) and (hi is None or num <= hi):
                        kept.add(v)
                checked = kept
            total = lst.count()
            if total and len(checked) >= total:
                self._filters.pop(col, None)
                self.filterChanged.emit(col, None)
            else:
                self._filters[col] = checked
                self.filterChanged.emit(col, checked)
            self.viewport().update()

        def on_search(text):
            t = (text or "").strip().lower()
            for i in range(lst.count()):
                v = str(lst.item(i).data(Qt.UserRole)).lower()
                lst.item(i).setHidden(bool(t) and t not in v)

        def set_all(state):
            self._updating = True
            for i in range(lst.count()):
                lst.item(i).setCheckState(state)
            self._updating = False
            apply_filter()

        lst.itemChanged.connect(apply_filter)
        search.textChanged.connect(on_search)
        btn_all.clicked.connect(lambda: set_all(Qt.Checked))
        btn_none.clicked.connect(lambda: set_all(Qt.Unchecked))
        btn_ok.clicked.connect(menu.close)
        if numeric and range_widget is not None:
            min_edit.textChanged.connect(apply_filter)
            max_edit.textChanged.connect(apply_filter)

        holder = QWidgetAction(menu)
        holder.setDefaultWidget(panel)
        menu.addAction(holder)
        menu.exec(global_pos)


# --- GUI 界面 ---

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DNS 测试器")
        self.resize(800, 600)
        
        defaults = [
             {"name": "阿里DNS", "url": "223.5.5.5", "type": "UDP"},
             {"name": "阿里DNS", "url": "223.6.6.6", "type": "UDP"},
             {"name": "114DNS", "url": "114.114.114.114", "type": "UDP"},
             {"name": "114DNS", "url": "114.114.115.115", "type": "UDP"},
             {"name": "DNSPod", "url": "119.29.29.29", "type": "UDP"},
             {"name": "DNSPod", "url": "182.254.116.116", "type": "UDP"},
             {"name": "CNNIC", "url": "1.2.4.8", "type": "UDP"},
             {"name": "CNNIC", "url": "210.2.4.8", "type": "UDP"},
             {"name": "百度DNS", "url": "180.76.76.76", "type": "UDP"},
             {"name": "阿里DoH", "url": "https://dns.alidns.com/dns-query", "type": "DoH"},
             {"name": "阿里DoH", "url": "https://223.5.5.5/dns-query", "type": "DoH"},
             {"name": "阿里DoH", "url": "https://223.6.6.6/dns-query", "type": "DoH"},
             {"name": "DNSPod DoH", "url": "https://doh.pub/dns-query", "type": "DoH"},
             {"name": "Cloudflare", "url": "1.1.1.1", "type": "UDP"},
             {"name": "Cloudflare", "url": "1.0.0.1", "type": "UDP"},
             {"name": "Google", "url": "8.8.8.8", "type": "UDP"},
             {"name": "Google", "url": "8.8.4.4", "type": "UDP"},
             {"name": "Quad9", "url": "9.9.9.9", "type": "UDP"},
             {"name": "Quad9", "url": "149.112.112.112", "type": "UDP"},
             {"name": "OpenDNS", "url": "208.67.222.222", "type": "UDP"},
             {"name": "OpenDNS", "url": "208.67.220.220", "type": "UDP"},
             {"name": "Cloudflare DoH", "url": "https://1.1.1.1/dns-query", "type": "DoH"},
             {"name": "Cloudflare DoH", "url": "https://1.0.0.1/dns-query", "type": "DoH"},
             {"name": "Google DoH", "url": "https://dns.google/dns-query", "type": "DoH"},
             {"name": "Google DoH", "url": "https://8.8.8.8/dns-query", "type": "DoH"},
             {"name": "Google DoH", "url": "https://8.8.4.4/dns-query", "type": "DoH"},
             {"name": "AdGuard DoH", "url": "https://dns.adguard.com/dns-query", "type": "DoH"},
             {"name": "AdGuard DoH", "url": "https://94.140.14.14/dns-query", "type": "DoH"},
             {"name": "AdGuard DoH", "url": "https://94.140.15.15/dns-query", "type": "DoH"},
             {"name": "Quad9 DoH", "url": "https://dns.quad9.net/dns-query", "type": "DoH"},
             {"name": "Quad9 DoH", "url": "https://9.9.9.9/dns-query", "type": "DoH"},
             {"name": "Quad9 DoH", "url": "https://149.112.112.112/dns-query", "type": "DoH"},
        ]

        # 归一化默认列表：补齐 host/port，url 统一成 host:port 或完整 https URL
        self.servers = []
        for s in defaults:
            host, port, ptype, url = self.parse_server(s['url'])
            self.servers.append({"name": s['name'], "url": url, "type": ptype,
                                 "host": host, "port": port})

        # 服务器持久化文件：优先读取同目录下的 dns_tester_servers.json；不存在则用内置默认值
        self.servers_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "dns_tester_servers.json")
        self.load_servers_file()

        # 数据源
        self.source_model = QStandardItemModel(0, 4)
        self.source_model.setHorizontalHeaderLabels(["服务器名称", "协议", "解析结果", "耗时(ms)"])

        # 代理模型：全局关键字 + 逐列筛选 + 排序
        self.proxy_model = ExcelFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # --- 顶部输入区域 ---
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("待查域名:"))
        self.domain_input = QLineEdit("www.baidu.com")

        self.btn_test = QPushButton("开始测试")
        self.btn_test.clicked.connect(self.start_test)

        h1.addWidget(self.domain_input, 1)
        h1.addWidget(self.btn_test)
        layout.addLayout(h1)

        # 结果表格：QTableView + Excel 风格筛选表头
        self.table = QTableView(self)
        self.table.setModel(self.proxy_model)
        self.table_header = ExcelFilterHeader(self.table, self.proxy_model)
        self.table.setHorizontalHeader(self.table_header)
        # 列宽可由用户拖拽调整（双击列边界自动适应内容，右键表头有更多选项）
        self.table_header.setToolTip("拖动列边界调整列宽 · 双击边界自动适应内容 · 右键表头可选择自动调整")
        self.table_header.setSectionResizeMode(QHeaderView.Interactive)
        self.table_header.setStretchLastSection(True)
        for col, width in enumerate(ExcelFilterHeader.DEFAULT_WIDTHS):
            self.table_header.resizeSection(col, width)
        self.table_header.filterChanged.connect(self.proxy_model.set_column_values)

        # 启用排序：点击表头文字区域即可排序
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.reset_sorting()   # 去掉 Qt 默认的「第0列降序」，初始按原始结果顺序显示

        # 筛选状态栏
        hs = QHBoxLayout()
        self.filter_status = QLabel("共 0 行")
        self.filter_status.setStyleSheet("color:#5f6368;")
        self.btn_clear_filter = QPushButton("清除筛选与排序")
        self.btn_clear_filter.setToolTip("清除所有列筛选，并恢复默认的原始结果顺序")
        self.btn_clear_filter.clicked.connect(self.clear_all_filters)
        self.btn_export = QPushButton("导出结果到 CSV")
        self.btn_export.clicked.connect(self.export_csv)
        self.baseline_label = QLabel("基线: -")
        self.baseline_label.setStyleSheet("color:#5f6368;")
        hs.addWidget(self.filter_status)
        hs.addSpacing(16)
        hs.addWidget(self.baseline_label)
        hs.addStretch(1)
        hs.addWidget(self.btn_clear_filter)
        hs.addWidget(self.btn_export)

        for sig in (self.proxy_model.rowsInserted, self.proxy_model.rowsRemoved,
                    self.proxy_model.modelReset, self.proxy_model.layoutChanged):
            sig.connect(lambda *a: self.update_filter_status())

        # --- 底部服务器管理区域 ---
        h2 = QHBoxLayout()
        self.srv_input = QLineEdit()
        self.srv_input.setPlaceholderText("添加服务器：纯IP默认UDP(53)·纯域名默认DoT(853)·可加协议头(udp:///dot:///https://)或显式端口，如“阿里云|dns.alidns.com”或“自建|1.2.3.4:5353”")
        self.btn_add = QPushButton("添加左侧所填")
        self.btn_add.clicked.connect(self.add_server)
        self.btn_del = QPushButton("删除下方所选")
        self.btn_del.clicked.connect(self.del_server)
        h2.addWidget(self.srv_input, 1)
        h2.addWidget(self.btn_add)
        h2.addWidget(self.btn_del)

        # 底部表格同样允许拖拽调整列宽
        self.srv_table = QTableWidget(0, 2)
        self.srv_table.setHorizontalHeaderLabels(["名称", "地址/URL"])
        self.srv_table.setMinimumHeight(60)
        self.srv_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.srv_table.horizontalHeader().setStretchLastSection(True)
        self.srv_table.horizontalHeader().resizeSection(0, 140)
        self.refresh_srv_table()

        # --- 上下分区：拖动分隔条可调整下方（状态栏 + 服务器区）的高度 ---
        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addWidget(self.table, 1)

        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.addLayout(hs)
        bottom_layout.addLayout(h2)
        bottom_layout.addWidget(self.srv_table, 1)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setHandleWidth(6)
        self.splitter.setStyleSheet(
            "QSplitter::handle{background:#d0d0d0;border-radius:2px;}"
            "QSplitter::handle:hover{background:#1a73e8;}")
        self.splitter.addWidget(top)
        self.splitter.addWidget(bottom)
        self.splitter.setStretchFactor(0, 1)    # 窗口变高时多出来的空间给结果表格
        self.splitter.setStretchFactor(1, 0)
        self.splitter.setCollapsible(0, False)
        self.splitter.setCollapsible(1, False)  # 底部不会整体消失
        self.splitter.setSizes([420, 190])

        layout.addWidget(self.splitter, 1)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    # --- 以下是所有必需的方法 ---

    def clear_all_filters(self):
        """清除全部筛选，并把排序恢复为默认（按原始结果顺序）"""
        self.proxy_model.set_global_keyword("")
        self.proxy_model.clear_all_columns()
        self.table_header.reset_filters()
        self.reset_sorting()
        self.update_filter_status()

    def reset_sorting(self):
        """取消排序列，回到数据源的原始顺序（常用于"按序号排序"）"""
        self.proxy_model.sort(-1, Qt.AscendingOrder)          # -1 = 不排序
        self.table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)

    def update_filter_status(self):
        """刷新「显示 N / 共 M 行」状态"""
        total = self.source_model.rowCount()
        shown = self.proxy_model.rowCount()
        if shown == total:
            self.filter_status.setText(f"共 {total} 行")
        else:
            self.filter_status.setText(f"显示 {shown} / 共 {total} 行（已筛选）")

    def refresh_srv_table(self):
        """刷新服务器列表"""
        self.srv_table.setRowCount(len(self.servers))
        for i, s in enumerate(self.servers):
            self.srv_table.setItem(i, 0, QTableWidgetItem(s['name']))
            self.srv_table.setItem(i, 1, QTableWidgetItem(s['url']))

    @staticmethod
    def parse_server(addr):
        """解析服务器地址，返回 (host, port, type, url)。

        识别规则：
          - 显式协议头优先决定协议：https://、doh:// → DoH；dot://、tls:// → DoT；
            udp://、dns:// → UDP
          - 无协议头时：纯 IP 地址 → UDP；纯域名 → DoT
          - 显式端口号优先使用，否则按各协议默认端口（UDP=53 / DoT=853 / DoH=443）
        """
        SCHEME_PROTO = {
            "https": "DoH", "doh": "DoH",
            "dot": "DoT", "tls": "DoT",
            "udp": "UDP", "dns": "UDP",
        }
        DEFAULT_PORTS = {"UDP": 53, "DoT": 853, "DoH": 443}

        s = addr.strip()
        ptype = None

        # 1) 协议头
        if "://" in s:
            scheme, rest = s.split("://", 1)
            scheme = scheme.lower()
            if scheme in SCHEME_PROTO:
                ptype = SCHEME_PROTO[scheme]
                s = rest

        # 2) 分离 host 与显式端口（DoH 的 URL 含路径，不做 host:port 拆分）
        explicit_port = None
        host = s
        if ptype != "DoH" and ":" in s:
            maybe_host, maybe_port = s.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host
                explicit_port = int(maybe_port)

        # 3) 无协议头时按 IP / 域名判断默认协议
        if ptype is None:
            try:
                ipaddress.ip_address(host)
                ptype = "UDP"
            except ValueError:
                ptype = "DoT"

        # 4) 端口：显式优先，否则默认
        port = explicit_port if explicit_port is not None else DEFAULT_PORTS[ptype]

        if ptype == "DoH":
            url = "https://" + host      # 还原成完整 URL（doh:// 也转成 https://）
        elif port == DEFAULT_PORTS[ptype]:
            url = host                   # 默认端口不写出，除非显式指定了非默认端口
        else:
            url = f"{host}:{port}"

        return host, port, ptype, url

    def load_servers_file(self):
        """启动优先读取同目录下的 dns_tester_servers.json；缺失或非法则回退内置默认值。"""
        if not os.path.exists(self.servers_file):
            return
        try:
            with open(self.servers_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, list):
            return
        loaded = []
        for item in data:
            name = item.get("name", "")
            addr = item.get("url") or item.get("addr") or ""
            if not addr:
                continue
            try:
                host, port, ptype, url = self.parse_server(addr)
            except Exception:
                continue
            loaded.append({"name": name, "url": url, "type": ptype,
                           "host": host, "port": port})
        if loaded:
            self.servers = loaded

    def save_servers_file(self):
        """把当前服务器列表写回同目录下的 dns_tester_servers.json。"""
        try:
            with open(self.servers_file, "w", encoding="utf-8") as f:
                json.dump([{"name": s["name"], "url": s["url"]} for s in self.servers],
                          f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def add_server(self):
        """添加服务器"""
        text = self.srv_input.text().strip()
        if not text: return
        if "|" in text:
            parts = text.split("|", 1)
            name, addr = parts[0].strip(), parts[1].strip()
        else:
            name, addr = f"Server-{len(self.servers)+1}", text
        if not addr: return

        host, port, ptype, url = self.parse_server(addr)
        self.servers.append({"name": name, "url": url, "type": ptype,
                             "host": host, "port": port})
        self.refresh_srv_table()
        self.srv_input.clear()
        self.save_servers_file()

    def del_server(self):
        """删除服务器"""
        rows = set(idx.row() for idx in self.srv_table.selectedIndexes())
        for r in sorted(rows, reverse=True): self.servers.pop(r)
        self.refresh_srv_table()
        self.save_servers_file()

    def start_test(self):
        """开始测试"""
        domain = self.domain_input.text().strip()
        if not domain: return
        self.btn_test.setText("测试中...")
        self.btn_test.setEnabled(False)
        self.reset_sorting()   # 每次重新测试都回到默认的原始结果顺序
        self.worker = TestWorker(self.servers, domain)
        self.worker.finished.connect(self.on_test_finished)
        self.worker.start()

    @staticmethod
    def parse_ip_set(text):
        """把 '1.1.1.1, 2.2.2.2' 解析成 frozenset。

        顺序与重复项都不影响等价性（'1,2,3' 与 '2,1,3' 视为同一组合），
        Timeout / Parse Error 等非 IP 内容会被忽略，返回空集。
        """
        ips = set()
        for token in (text or "").split(','):
            token = token.strip()
            if not token:
                continue
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue   # 超时、解析失败、HTTP 错误码等，一律不参与基线统计
            ips.add(token)
        return frozenset(ips)

    @staticmethod
    def format_ip_set(ip_set):
        return ", ".join(sorted(ip_set)) if ip_set else "(无)"

    def update_baseline(self, baseline, count, total):
        """状态栏显示当前基线组合"""
        if not baseline:
            self.baseline_label.setText("基线: -")
            self.baseline_label.setToolTip("")
            return
        ips = sorted(baseline)
        shown = ", ".join(ips[:3]) + (f" …(+{len(ips) - 3})" if len(ips) > 3 else "")
        self.baseline_label.setText(f"基线({count}/{total} 一致): {shown}")
        self.baseline_label.setToolTip("基线 IP 组合（顺序无关）:\n" + self.format_ip_set(baseline))

    def on_test_finished(self, results):
        """测试完成回调"""
        self.btn_test.setText("开始测试")
        self.btn_test.setEnabled(True)
        self.update_results(results)

    def update_results(self, results):
        """更新结果表格 (使用 QStandardItemModel)"""
        self.source_model.removeRows(0, self.source_model.rowCount()) # 清空旧数据

        # 数据变了，旧的按列勾选已失效，重置掉（全局关键字保留）
        self.proxy_model.clear_all_columns()
        self.table_header.reset_filters()

        if not results:
            self.update_baseline(None, 0, 0)
            self.update_filter_status()
            return

        # 基线 = 出现次数最多的「IP 组合」；组合按集合比较，顺序和重复项不影响等价性
        combos = Counter()
        for r in results:
            r['ip_set'] = self.parse_ip_set(r['ips'])
            if r['ip_set']:
                combos[r['ip_set']] += 1
        baseline = combos.most_common(1)[0][0] if combos else None
        baseline_count = combos[baseline] if baseline else 0
        self.update_baseline(baseline, baseline_count, sum(combos.values()))

        suspicious_ips = {'127.0.0.1', '0.0.0.0', '10.0.0.1', '192.168.0.1'}

        for r in results:
            # 创建 QStandardItem 列表
            items = [
                QStandardItem(r['name']),
                QStandardItem(r['type']),
                QStandardItem(r['ips']),
            ]
            
            # 专门处理耗时列，设置其为整数类型
            time_item = QStandardItem()
            time_item.setData(int(r['time']), Qt.DisplayRole) # 关键修改：使用 setData 并指定角色
            
            items.append(time_item)
            
            # 异常检测：IP 集合与基线组合不同、命中黑名单、或压根没解析出 IP 都算异常
            ip_set = r['ip_set']
            is_suspicious = False
            reason = ""
            if not ip_set:
                # 没有任何有效 IP：Timeout / Parse Error / HTTP 5xx 等
                is_suspicious, reason = True, "无法完成操作"
            elif ip_set & suspicious_ips:
                is_suspicious, reason = True, "本地或保留地址"
            elif baseline and ip_set != baseline:
                is_suspicious, reason = True, "与基线不同 —— 注意：网络环境和分流规则可能导致不同结果"

            if is_suspicious:
                red_bg = QColor(255, 200, 200)
                for item in items:
                    item.setBackground(red_bg)
                items[2].setToolTip(
                    f"异常: {reason}\n"
                    f"基线组合: {self.format_ip_set(baseline)}\n"
                    f"本结果  : {r['ips'] or '(空)'}")

            # 将整行数据追加到 model 中
            self.source_model.appendRow(items)

        self.update_filter_status()

    def export_csv(self):
        """导出CSV"""
        path, _ = QFileDialog.getSaveFileName(self, "导出结果到 CSV", "dns_result.csv", "逗号分隔值 (*.csv)")
        if not path: return
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["服务器", "协议", "解析结果", "耗时(ms)"])
            # 遍历 source_model 获取数据
            for row in range(self.source_model.rowCount()):
                row_data = []
                for col in range(self.source_model.columnCount()):
                    item = self.source_model.item(row, col)
                    row_data.append(item.text() if item else "")
                writer.writerow(row_data)
        QMessageBox.information(self, "成功", f"已导出至:\n{path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())