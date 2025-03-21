
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QHBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt


#Define Classes


class role():
    def __init__(self, name, object_name):
        self.name = name
        self.object_name = object_name
        self.permissions = set()
        
    def set_permissions(self, permission_name):
        self.permissions.add(permission_name)
       
    
    def get_permissions(self):
        return list(self.permissions)

    def __repr__(self):
        return f"{self.name} ({self.object_name})" if self.object_name else self.name
        


class User:
    def __init__(self, name, role):
       self.name = name
       self.role = role
   


class engineer(role):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permissions("read_code")

class Quality_engineer(engineer):
    def __init__(self, name, object_name):
        super().__init__(name,object_name)
        self.set_permissions("test_code")
        

class Production_engineer(engineer):
     def __init__(self, name, object_name):
        super().__init__(name,object_name)
        self.set_permissions("deploy_code")
        

class Project_lead(Quality_engineer, Production_engineer):
    def __init__(self, name, object_name):
        Production_engineer.__init__(self, name, object_name)
        Quality_engineer.__init__(self, name, object_name)
        self.set_permissions("manage_project")
        


class Director(Project_lead):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permissions("assign_projects")

class Session():
    def __init__(self):
         self.users = []
         self.users.append(User("E1", engineer("Engineer", "Project A - Code1")))
         self.users.append(User("Q1", Quality_engineer("Quality Engineer", "Project A")))
         self.users.append(User("Prod1", Production_engineer("Production Engineer", "Project A Prod. Line")))
         self.users.append(User("PL", Project_lead("Project Lead", "Project A")))
         self.users.append(User("Dir", Director("Director", "Engineering Department")))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RBAC")
        self.setFixedSize(1100, 400)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 12px; \
             background-color: #663399;")        

        self.session = Session()
        # Create widgets
        self.roles_table = QTableWidget()
        self.users_table = QTableWidget()

        # Set up roles table
        self.roles_table.setColumnCount(2)
        self.roles_table.setHorizontalHeaderLabels(["Role", "Permissions"])
        self.roles_table.setSortingEnabled(True)
        self.roles_table.setStyleSheet("background-color: white; color: black")
      
        # Set up users table
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["User", "Role", "Object Name"])
        self.users_table.setSortingEnabled(True)
        #self.users_table.setMinimumWidth(400)
        self.users_table.setStyleSheet("background-color: white; color: black")
        
        # Populate tables
        self.populate_roles_table()
        self.populate_users_table()

        # Layout
        layout = QHBoxLayout()
        layout.addWidget(self.roles_table)
        layout.addWidget(self.users_table)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def populate_roles_table(self):
        seen_roles = set() 

        row = 0
        for user in self.session.users:
            role = user.role

            if role.name not in seen_roles:
                self.roles_table.insertRow(row)
                self.roles_table.setItem(row, 0, QTableWidgetItem(role.name))
                permissions_item = QTableWidgetItem(", ".join(role.get_permissions()))
                permissions_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self.roles_table.setItem(row, 1, permissions_item)
                row += 1
                seen_roles.add(role.name) 
        self.roles_table.resizeColumnsToContents()
        
    def populate_users_table(self):
        row = 0
        for user in self.session.users:
            self.users_table.insertRow(row)
            self.users_table.setItem(row, 0, QTableWidgetItem(user.name))
            self.users_table.setItem(row, 1, QTableWidgetItem(user.role.name))
            self.users_table.setItem(row, 2, QTableWidgetItem(user.role.object_name))
            row += 1
        self.users_table.resizeColumnsToContents()   

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())