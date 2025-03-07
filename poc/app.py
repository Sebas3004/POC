from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

#Inicialización de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta_para_flask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Inicialización de la base de datos
db = SQLAlchemy(app)

#Configuración del gestor de inicio de sesión
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Creación de las tablas en la base de datos
with app.app_context():
    db.create_all()

#Rutas de la aplicación
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        #Verificación de que el usuario no exista ya
        user = User.query.filter_by(username=username).first()
        if user:
            flash('El nombre de usuario ya existe. Por favor, elija otro.')
            return redirect(url_for('register'))
        
        #Creación de un nuevo usuario
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Registro exitoso! Ahora puede iniciar sesión.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        #Verificación de las credenciales
        if user and user.check_password(password):
            login_user(user)
            flash('¡Inicio de sesión exitoso!')
            return redirect(url_for('dashboard'))
        else:
            flash('Error de inicio de sesión. Verifique sus credenciales.')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)