from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configura la conexión a MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:eenAqGzMWjTrMzFNiokxpZnxIOCzvTch@hopper.proxy.rlwy.net:32343/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de Usuario
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    contrasena = db.Column(db.String(200), nullable=False)
    ciudad = db.Column(db.String(100))
    pais = db.Column(db.String(100))
    celular = db.Column(db.String(20))
    rol = db.Column(db.String(20), default="usuario")

@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()

    required_fields = ['nombre', 'apellidos', 'correo', 'contrasena']
    for field in required_fields:
        if field not in data or not data[field].strip():
            return jsonify({"exito": False, "error": f"Falta el campo obligatorio: {field}"}), 400

    # Verificar si el correo ya está registrado
    if Usuario.query.filter_by(correo=data['correo']).first():
        return jsonify({"exito": False, "error": "Correo ya registrado"}), 409

    # Verificar si el celular ya está registrado (si es proporcionado)
    celular = data.get('celular')
    if celular and Usuario.query.filter_by(celular=celular).first():
        return jsonify({"exito": False, "error": "Celular ya registrado"}), 409

    hashed_password = generate_password_hash(data['contrasena'])

    nuevo_usuario = Usuario(
        nombre=data['nombre'],
        apellidos=data['apellidos'],
        correo=data['correo'],
        contrasena=hashed_password,
        ciudad=data.get('ciudad'),
        pais=data.get('pais'),
        celular=celular
    )

    db.session.add(nuevo_usuario)
    db.session.commit()

    return jsonify({"exito": True, "mensaje": "Usuario registrado correctamente", "rol": nuevo_usuario.rol}), 200


# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'correo' not in data or 'contrasena' not in data:
        return jsonify({"exito": False, "error": "Correo y contraseña son requeridos"}), 400

    usuario = Usuario.query.filter_by(correo=data['correo']).first()

    if usuario and check_password_hash(usuario.contrasena, data['contrasena']):
        return jsonify({
            "exito": True,
            "mensaje": "Inicio de sesión exitoso",
            "usuario": {
                "nombre": usuario.nombre,
                "apellidos": usuario.apellidos,
                "correo": usuario.correo,
                "rol": usuario.rol
            }
        })
    else:
        return jsonify({"exito": False, "error": "Correo o contraseña incorrectos"}), 401

# Punto de entrada
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
