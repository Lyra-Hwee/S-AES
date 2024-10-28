import tkinter as tk
from tkinter import ttk  # 导入 ttk 模块以使用更好的小部件

# 尝试导入必要的 GUI 模块
try:
    from ASCII_GUI import SAES_ASCII_App
    from SAES_GUI import SAESApp
    from attack_GUI import AttackGUI
    from Work_GUI import WorkApp
except ImportError as e:
    print(f"导入 GUI 模块时出错: {e}")

# 启动 SAES ASCII GUI 的函数
def launch_saes_ascii():
    saes_ascii_window = tk.Toplevel(root)  # 创建新窗口
    saes_ascii_window.title("SAES ASCII GUI")  # 设置窗口标题
    SAES_ASCII_App(saes_ascii_window)  # 启动 SAES ASCII 应用

# 启动 SAES GUI 的函数
def launch_saes():
    saes_window = tk.Toplevel(root)
    saes_window.title("SAES GUI")
    SAESApp(saes_window)

# 启动攻击 GUI 的函数
def launch_attack():
    attack_window = tk.Toplevel(root)
    attack_window.title("Attack GUI")
    AttackGUI(attack_window)

# 启动工作 GUI 的函数
def launch_work():
    work_window = tk.Toplevel(root)
    work_window.title("Work GUI")
    WorkApp(work_window)

# 创建主窗口
root = tk.Tk()
root.title("主菜单")  # 设置主窗口标题
root.geometry("400x300")  # 设置窗口初始大小（宽 x 高）

# 使用框架进行更好的布局管理
main_frame = ttk.Frame(root, padding="20 20 20 20")   
main_frame.pack(fill="both", expand=True)

# 创建一个内部框架以居中按钮
button_frame = ttk.Frame(main_frame)
button_frame.grid(row=0, column=0, sticky="nsew")


main_frame.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)


buttons = [
    ("SAES GUI", launch_saes),
    ("SAES ASCII GUI", launch_saes_ascii),
    ("Attack GUI", launch_attack),
    ("Work GUI", launch_work),
]

# 设置按钮属性以增大按钮大小
button_width = 20
button_height = 2
button_padding = (10, 10)

# 创建增大尺寸的按钮
for i, (text, command) in enumerate(buttons):
    button = ttk.Button(button_frame, text=text, command=command, width=button_width, padding=button_padding)
    button.grid(row=i, column=0, padx=10, pady=10)

# 在主框架中居中按钮框架
button_frame.grid_columnconfigure(0, weight=1)

root.mainloop()