from PyQt6.QtWidgets import QComboBox


# 在下拉三角框中添加网卡
def add_combo_items(interfaces_list, ui):
    if ui.interfaces_combo.addItems(interfaces_list):
        return True
    else:
        return False
