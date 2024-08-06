from PyQt5.QtWidgets import QApplication, QFileDialog

def select_folder():
    app = QApplication([])
    folder = QFileDialog.getExistingDirectory(None, "Select Folder")
    return folder

folder_path = select_folder()
if folder_path:
    print(f"Selected folder: {folder_path}")
else:
    print("No folder selected")
