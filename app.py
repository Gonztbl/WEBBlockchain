from flask import Flask, render_template, url_for, redirect, abort, request, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from web3 import Web3
import json

# =========================================================== WEB3 ======================================================================
network_url = "HTTP://127.0.0.1:8545"
web = Web3(Web3.HTTPProvider(network_url))

truffleFile = json.load(open('./build/contracts/Election.json'))
abi = truffleFile['abi']
bytecode = truffleFile['bytecode']

# Tạo hợp đồng
contract_address = "0x70E1da5F670C3Df66ae4fAE285079A5013291C44"  # Thay bằng địa chỉ contract nếu đã deploy
if contract_address:
    election = web.eth.contract(address=contract_address, abi=abi)
else:
    election = None
    print("Contract not deployed or invalid contract address")

end = False  # Trạng thái kết thúc bầu cử

# =========================================================== FLASK CONFIG ======================================================================
app = Flask(__name__)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.config['SECRET_KEY'] = 'THIS_IS_A_SECRET_KEY'

# =========================================================== USER CLASS ======================================================================
class User(UserMixin):
    def __init__(self, username, password, address, key):
        self.username = username
        self.password = password
        self.address = address
        self.key = key

    def get_id(self):
        return self.username

# Tạo danh sách người dùng cố định
users = [
    User(
        username="admin",
        password=bcrypt.generate_password_hash("adminpassword").decode("utf-8"),
        address="0x1Ff0c0B0379Ec4DaE8dE7F63b86CDB089fB6E9A5",
        key="0xa55320d8584fca72c0e91e4c2f7e739195003afe7c18458b3bf378e1849daf58",
    ),
    User(
        username="user1",
        password=bcrypt.generate_password_hash("userpassword1").decode("utf-8"),
        address="0x8bE398D80E05c2c999d2c628cf7088e5EE9CC316",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0x1448310b4594c16aa178e407bb92d88b22d9761061eaa6acce14aa5db50bd7c7",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user2",
        password=bcrypt.generate_password_hash("userpassword2").decode("utf-8"),
        address="0xf7F1BCfdda58F02428Cb2B30A1FE34bd414e0423",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0x0c73753b72a665f93b84c45c7ac4f8d32284000815f9499eaeadeb8f1ed49655",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user3",
        password=bcrypt.generate_password_hash("userpassword3").decode("utf-8"),
        address="0xAEad1Ff736Eb941223285c6F8eA7194D8d90e6a8",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0x2678bd4b033f907297639c974c045afe90369af8e8ab51c93996e31080cb9d57",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user4",
        password=bcrypt.generate_password_hash("userpassword4").decode("utf-8"),
        address="0xAddress4",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey4",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user5",
        password=bcrypt.generate_password_hash("userpassword5").decode("utf-8"),
        address="0xAddress5",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey5",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user6",
        password=bcrypt.generate_password_hash("userpassword6").decode("utf-8"),
        address="0xAddress6",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey6",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user7",
        password=bcrypt.generate_password_hash("userpassword7").decode("utf-8"),
        address="0xAddress7",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey7",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user8",
        password=bcrypt.generate_password_hash("userpassword8").decode("utf-8"),
        address="0xAddress8",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey8",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user9",
        password=bcrypt.generate_password_hash("userpassword9").decode("utf-8"),
        address="0xAddress9",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey9",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
    User(
        username="user10",
        password=bcrypt.generate_password_hash("userpassword10").decode("utf-8"),
        address="0xAddress10",  # Địa chỉ ví của người dùng, thay bằng địa chỉ hợp lệ
        key="0xPrivateKey10",  # Khóa riêng của người dùng, thay bằng khóa hợp lệ
    ),
]

@login_manager.user_loader
def load_user(username):
    return next((user for user in users if user.username == username), None)

# =========================================================== FORMS ======================================================================
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Password"})
    address = StringField(validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Address"})
    key = StringField(validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Key"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        if any(user.username == username.data for user in users):
            raise ValidationError("Username already exists. Please choose another.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Log In")

# =========================================================== ROUTES ======================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = next((u for u in users if u.username == form.username.data), None)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['has_voted'] = False
            return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            address=form.address.data,
            key=form.key.data
        )
        users.append(new_user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    session.pop('has_voted', None)
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    form = LoginForm()
    if form.validate_on_submit():
        user = next((u for u in users if u.username == form.username.data), None)
        if user and user.username == "admin" and bcrypt.check_password_hash(user.password, "adminpassword"):
            login_user(user)
            return redirect(url_for('adminPortal'))
        else:
            abort(403)
    return render_template('adminLogin.html', form=form)

@app.route('/adminPortal', methods=['GET', 'POST'])
@login_required
def adminPortal():
    if current_user.username != "admin":
        abort(403)
    candidate1 = election.functions.candidates(1).call()
    candidate2 = election.functions.candidates(2).call()
    candidate3 = election.functions.candidates(3).call()
    print(candidate1)
    print(candidate2)
    print(candidate3)
    candidates = [candidate1, candidate2, candidate3]
    return render_template('admin.html', candidates =candidates)

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if session.get('has_voted', False):
        return "<h1>You have already voted in this session.</h1>"

    if end:
        return "<h1>ELECTION ENDED</h1>"

    def cast_vote(owner, signature, to_vote):
        if not election:
            return None
        transaction_body = {
            'nonce': web.eth.get_transaction_count(owner),
            'gas': 1728712,
            'gasPrice': web.to_wei(8, 'gwei'),
        }
        try:
           # print(election.functions.vote(to_))
            v = election.functions.vote(to_vote).build_transaction(transaction_body)
            #tx_hash = election.functions.vote(to_vote).transact()
            #tx_receipt = web.eth.wait_for_transaction_receipt(tx_hash)
            signed_transaction = web.eth.account.sign_transaction(v, signature)
            result = web.eth.send_raw_transaction(signed_transaction.rawTransaction)
            return result
        except Exception as e:
            print(f"Error: {e}")
            return None

    if request.method == 'POST':
        candidate = request.form.get('voteBtn')
        candidate_map = {'De 1': 1, 'De 2': 2, 'De 3': 3}
        to_vote = candidate_map.get(candidate)

        if to_vote is None:
            return "<h1>Invalid candidate selected.</h1>"
        print(current_user.address)
        result = cast_vote(current_user.address, current_user.key, to_vote)
        if result:
            session['has_voted'] = True
            return "<h1>Thank you for voting!</h1>"
        return "<h1>Error casting your vote. Please try again later.</h1>"

    return render_template('vote.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
