import json
import os
import shutil
import sys
import time
import webbrowser
import codecs
import datetime
from PyQt5.QtWidgets import QApplication, QPushButton, QLineEdit, QFormLayout, QWidget, QLabel, \
    QBoxLayout, QGridLayout, QGroupBox, QListWidget, QSizePolicy, QMessageBox

try:
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)
except ImportError:
    import sys

    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)

# FILE LOCATIONS
cache_folder = os.path.join(os.getcwd(), '.cache')
whitelist_cache = '%s/whitelist.json' % cache_folder
session_cache = '%s/session.json' % cache_folder
credentials_cache = '%s/credentials.json' % cache_folder


def to_json(python_object):
    if isinstance(python_object, bytes):
        return {'__class__': 'bytes',
                '__value__': codecs.encode(python_object, 'base64').decode()}
    raise TypeError(repr(python_object) + ' is not JSON serializable')


def from_json(json_object):
    if '__class__' in json_object and json_object['__class__'] == 'bytes':
        return codecs.decode(json_object['__value__'].encode(), 'base64')
    return json_object


def onlogin_callback(api, new_settings_file):
    cache_settings = api.settings
    with open(new_settings_file, 'w') as outfile:
        json.dump(cache_settings, outfile, default=to_json)
        print('SAVED: {0!s}'.format(new_settings_file))


app = QApplication(sys.argv)


class mainWindow(QWidget):
    def __init__(self, api):
        QWidget.__init__(self)
        self.setWindowTitle('Instagram Unfollower Program')
        # some variables for the app process
        self.uuid = api.generate_uuid()
        self.unfollowers = {}
        self.api = api
        # try to load whitelist data
        if os.path.isfile(whitelist_cache):
            file = open(whitelist_cache, 'r', encoding='utf-8')
            self.whitelist_data = json.loads(file.read())
            file.close()
        else:
            self.whitelist_data = {"status": "failed"}
        # create layout
        self.layout = QGridLayout()

        # create groupBox
        groupbox = QGroupBox()
        groupbox.setTitle('User Info')
        label = QLabel('User ID:')
        userid = QLabel(api.authenticated_user_id)

        gbl = QBoxLayout(QBoxLayout.TopToBottom)
        gbl.addWidget(label)
        gbl.addWidget(userid)
        groupbox.setLayout(gbl)

        self.layout.addWidget(groupbox, 0, 0)

        # Create Buttons
        analyzeButton = QPushButton('Analyze')
        self.layout.addWidget(analyzeButton, 1, 0)
        analyzeButton.clicked.connect(self.analyze)
        runButton = QPushButton('Save Whitelist And Run Unfollower')
        self.layout.addWidget(runButton, 2, 0)
        runButton.clicked.connect(self.unfollower)
        logoutButton = QPushButton('Logout')
        self.layout.addWidget(logoutButton, 3, 0)
        logoutButton.clicked.connect(self.logout)

        # Create Unfollowers List
        groupbox1 = QGroupBox()
        groupbox1.setTitle('Unfollowers')
        gbl1 = QBoxLayout(QBoxLayout.TopToBottom)

        self.Unfollowers = QListWidget()

        gbl1.addWidget(self.Unfollowers)
        groupbox1.setLayout(gbl1)
        self.layout.addWidget(groupbox1, 0, 1, 5, 2)

        # Transfer buttons
        toWhitelist = QPushButton('=>')
        toWhitelist.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.layout.addWidget(toWhitelist, 1, 3)

        toFollowings = QPushButton('<=')
        toFollowings.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.layout.addWidget(toFollowings, 2, 3)

        toWhitelist.clicked.connect(self.toWhitelist)
        toFollowings.clicked.connect(self.toUnfollowers)

        # Whitelist

        self.whiteList = QListWidget()
        gbl2 = QBoxLayout(QBoxLayout.TopToBottom)
        gbl2.addWidget(self.whiteList)
        groupbox2 = QGroupBox()
        groupbox2.setTitle('Whitelist')

        groupbox2.setLayout(gbl2)
        self.layout.addWidget(groupbox2, 0, 4, 5, 5)

        if self.whitelist_data['status'] != 'failed':
            for whitelistted in self.whitelist_data['list']:
                self.whiteList.addItem(whitelistted)

        self.setLayout(self.layout)

    def logout(self):
        shutil.rmtree(cache_folder)
        print('successfully logged out.')
        sys.exit()

    def selectedItems(self, qlist):
        selectedItems = qlist.selectedItems()
        if not selectedItems: return []
        ids = []
        for item in selectedItems:
            ids.append(item.text())
        return ids

    def toWhitelist(self):
        for Id in self.selectedItems(self.Unfollowers):
            self.whiteList.addItem(Id)
        self.deleteItem(self.Unfollowers)

    def toUnfollowers(self):
        for Id in self.selectedItems(self.whiteList):
            self.Unfollowers.addItem(Id)
        self.deleteItem(self.whiteList)

    def deleteItem(self, qlist):
        selectedItems = qlist.selectedItems()
        if not selectedItems: return
        for item in selectedItems:
            qlist.takeItem(qlist.row(item))

    def analyze(self):
        b = time.perf_counter()
        # Get follows data
        followings_data = self.api.user_following(self.api.authenticated_user_id, self.uuid)
        followers_data = self.api.user_followers(self.api.authenticated_user_id, self.uuid)

        print('fetching followers and followings list...')
        # Get usernames
        followers = []
        follows = {}
        for f in followers_data['users']:
            followers.append(f['username'])

        for f in followings_data['users']:
            follows[f['username']] = f['pk']

        print('analyzing unfollowers..')
        # find unfollowers
        for f in follows.keys():
            if f not in followers:
                if self.whitelist_data['status'] == "success" and f not in self.whitelist_data['list'] or \
                        self.whitelist_data['status'] == "failed":
                    self.Unfollowers.addItem(f)
                    self.unfollowers[f] = follows[f]  # I use for the unfollowers id
        a = time.perf_counter()
        print(f'finished in {a - b:0.4f} seconds')

    def unfollower(self):
        b = time.perf_counter()
        print('collect whitelist and unfollowers list...')
        whitelist = []
        for i in range(self.whiteList.count() - 1):
            whitelist.append(self.whiteList.item(i).text())
        unfollowers = []
        for i in range(self.Unfollowers.count() - 1):
            unfollowers.append(self.Unfollowers.item(i).text())

        print('saving whitelist...')
        with open(whitelist_cache, 'w') as f:
            f.writelines(json.dumps({"list": whitelist, "status": "success"}))

        print('creating unfollowers list...')
        cu = []
        for user in self.unfollowers.keys():
            if user not in whitelist:
                cu.append(self.unfollowers[user])
                print('Unfollower id:', self.unfollowers[user], 'Username:', user, sep=' ')

        print('unfollow process started..')
        # unfollow unfollowers
        for user in cu:
            self.api.friendships_destroy(user)
        a = time.perf_counter()
        print(f'finished in {a - b:0.4f} seconds')


class loginWindow(QWidget):
    login_result = False

    def __init__(self):
        QWidget.__init__(self)
        self.setWindowTitle('Instagram Unfollower')

        # api
        self.api = None
        # create layout
        self.layout = QFormLayout()

        userNameInput = QLineEdit()
        self.layout.addRow(QLabel('Username:'), userNameInput)

        passwordInput = QLineEdit()
        passwordInput.setEchoMode(QLineEdit.Password)
        self.layout.addRow(QLabel('Password:'), passwordInput)

        githubButton = QPushButton('Github')
        githubUrl = "https://github.com/merchizm/InstagramUnfollower"
        githubButton.clicked.connect(lambda: webbrowser.open(githubUrl))

        loginButton = QPushButton('Login')
        loginButton.clicked.connect(lambda: self.login(userNameInput.text(), passwordInput.text()))
        self.layout.addRow(githubButton, loginButton)

        # Status
        self.status = QLabel('Status: Ok.')
        self.layout.addRow(self.status)

        self.setLayout(self.layout)

    def login(self, username, password):
        # check cache folder
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)

        # check credentials
        try:
            self.api = Client(username, password, on_login=lambda x: onlogin_callback(x, session_cache))
            with open(credentials_cache, 'w') as f:
                f.write(json.dumps({"username": username, "password": password}))
        except (ClientCookieExpiredError, ClientLoginRequiredError) as e:
            self.status.setText('Status: Login failed.')
            print('ClientCookieExpiredError/ClientLoginRequiredError: {0!s}'.format(e))
            return False

        self.status.setText('Status: You\'re logged in.')
        # Show when login expires
        cookie_expiry = self.api.cookie_jar.auth_expires
        print('Cookie Expiry: {0!s}'.format(
            datetime.datetime.fromtimestamp(cookie_expiry).strftime('%Y-%m-%dT%H:%M:%SZ')))
        mw = mainWindow(self.api)
        mw.show()
        self.hide()


class App:
    def __init__(self):
        self.device_id = None
        self.loginWindow = loginWindow()
        self.api = None
        try:
            if not os.path.isfile(session_cache):
                # session cache file does not exist
                print('Unable to find file: {0!s}'.format(session_cache))
                self.loginWindow.show()
            else:
                with open(session_cache) as file_data:
                    cached_settings = json.load(file_data, object_hook=from_json)
                print('Reusing session: {0!s}'.format(session_cache))

                with open(credentials_cache, 'r') as credentials_cache_file:
                    cached_credentials = json.load(credentials_cache_file)
                    print(cached_credentials['username'], cached_credentials['password'], session_cache)

                self.device_id = cached_settings['device_id']
                # reuse auth settings
                self.api = Client(cached_credentials['username'], cached_credentials['password'],
                                  settings=cached_settings)

                self.mainWindow = mainWindow(self.api)
                self.mainWindow.show()

                # Show when login expires
                cookie_expiry = self.api.cookie_jar.auth_expires
                print('Cookie Expiry: {0!s}'.format(
                    datetime.datetime.fromtimestamp(cookie_expiry).strftime('%Y-%m-%dT%H:%M:%SZ')))

        except ClientLoginError as e:
            self.error_dialog(e.code, e.msg, e.error_response)
        except ClientError as e:
            self.error_dialog(e.code, e.msg, e.error_response)
        except Exception as e:
            print('Unexpected Exception: {0!s}'.format(e))
            exit(99)

    def error_dialog(self, exception_type, exception_message, stack_trace):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)

        msg.setText("An error has occurred in the application.")
        msg.setInformativeText("%s : %s" % (exception_type, exception_message))
        msg.setWindowTitle("Error")
        msg.setDetailedText(stack_trace)
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg.buttonClicked.connect(lambda: msg.close())

        retval = msg.exec_()
        print("value of pressed message box button:", retval)


uyg = App()
app.exec()
