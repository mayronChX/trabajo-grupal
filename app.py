from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'clave_secreta'

# Conexión a MySQL (ajusta tu contraseña si es diferente)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1984@localhost/sistema_login1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Modelo de Usuario
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    rol = db.Column(db.String(50))  # NUEVO

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password_raw = request.form['password']
        rol = request.form['rol']

        # Verificar si ya existe ese email
        if Usuario.query.filter_by(email=email).first():
            flash('⚠️ El email ya está registrado.', 'danger')
            return redirect(url_for('registro'))

        # Validar longitud mínima de contraseña
        if len(password_raw) < 6:
            flash('⚠️ La contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('registro'))

        # Hashear la contraseña
        password = bcrypt.generate_password_hash(password_raw).decode('utf-8')

        nuevo_usuario = Usuario(nombre=nombre, email=email, password=password, rol=rol)

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash('✅ Registro exitoso. Inicia sesión.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print("❌ Error al registrar usuario:", e)
            flash('❌ Error interno al registrar.', 'danger')
            return redirect(url_for('registro'))

    return render_template('registro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and bcrypt.check_password_hash(usuario.password, password):
            session['usuario'] = usuario.nombre
            flash('Has iniciado sesión correctamente.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'usuario' in session:
        usuario = Usuario.query.filter_by(nombre=session['usuario']).first()
        return f"""
            <h2>Bienvenido, {usuario.nombre}</h2>
            <p>Tu rol es: <strong>{usuario.rol}</strong></p>
            <a href='/logout'>Cerrar sesión</a>
        """
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

# Asegurar que las tablas se creen si no existen
with app.app_context():
    db.create_all()
    print("✅ Tablas listas")

if __name__ == '__main__':
    app.run(debug=True)

