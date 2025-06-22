from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Configura la conexión a PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://requisitoriados_user:x0xLGMH3N71ZfUG9UX7rcBiujKiELzKY@dpg-d114ho2li9vc738covqg-a.oregon-postgres.render.com/requisitoriados'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de Usuario
class Usuario(db.Model):
    __tablename__ = 'usuario'
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

    if Usuario.query.filter_by(correo=data['correo']).first():
        return jsonify({"exito": False, "error": "Correo ya registrado"}), 409

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
                "id": usuario.id,
                "nombre": usuario.nombre,
                "apellidos": usuario.apellidos,
                "correo": usuario.correo,
                "ciudad": usuario.ciudad,
                "pais": usuario.pais,
                "celular": usuario.celular,
                "rol": usuario.rol
            }
        })
    else:
        return jsonify({"exito": False, "error": "Correo o contraseña incorrectos"}), 401

@app.route('/usuario/<int:id>', methods=['GET'])
def obtener_usuario(id):
    usuario = Usuario.query.get(id)
    
    if not usuario:
        return jsonify({"exito": False, "error": "Usuario no encontrado"}), 404

    return jsonify({
        "exito": True,
        "usuario": {
            "id": usuario.id,
            "nombre": usuario.nombre,
            "apellidos": usuario.apellidos,
            "correo": usuario.correo,
            "ciudad": usuario.ciudad,
            "pais": usuario.pais,
            "celular": usuario.celular,
            "rol": usuario.rol
        }
    }), 200

@app.route('/usuario/<int:id>', methods=['PUT'])
def actualizar_usuario(id):
    data = request.get_json()
    usuario = Usuario.query.get(id)

    if not usuario:
        return jsonify({"exito": False, "error": "Usuario no encontrado"}), 404

    nuevo_correo = data.get('correo')
    if nuevo_correo and nuevo_correo != usuario.correo:
        if Usuario.query.filter_by(correo=nuevo_correo).first():
            return jsonify({"exito": False, "error": "Correo ya en uso"}), 409
        usuario.correo = nuevo_correo

    nuevo_celular = data.get('celular')
    if nuevo_celular and nuevo_celular != usuario.celular:
        if Usuario.query.filter_by(celular=nuevo_celular).first():
            return jsonify({"exito": False, "error": "Celular ya en uso"}), 409
        usuario.celular = nuevo_celular

    if 'nombre' in data:
        usuario.nombre = data['nombre']
    if 'apellidos' in data:
        usuario.apellidos = data['apellidos']
    if 'contrasena' in data:
        usuario.contrasena = generate_password_hash(data['contrasena'])
    if 'ciudad' in data:
        usuario.ciudad = data['ciudad']
    if 'pais' in data:
        usuario.pais = data['pais']

    db.session.commit()

    return jsonify({"exito": True, "mensaje": "Datos del usuario actualizados correctamente"}), 200

# 🚨 NUEVAS RUTAS DE RECUPERACIÓN DE CONTRASEÑA

@app.route('/verificar-usuario-recuperacion', methods=['POST'])
def verificar_usuario_recuperacion():
    data = request.get_json()
    correo = data.get('correo')
    celular = data.get('celular')

    if not correo or not celular:
        return jsonify({"exito": False, "error": "Correo y celular son requeridos"}), 400

    usuario = Usuario.query.filter_by(correo=correo, celular=celular).first()

    if not usuario:
        return jsonify({"exito": False, "error": "No se encontró un usuario con esos datos"}), 404

    return jsonify({
        "exito": True,
        "mensaje": "Usuario verificado. Puedes restablecer tu contraseña.",
        "usuario_id": usuario.id
    }), 200

@app.route('/restablecer-contrasena-directo', methods=['POST'])
def restablecer_contrasena_directo():
    data = request.get_json()
    usuario_id = data.get('usuario_id')
    nueva_contrasena = data.get('nueva_contrasena')

    if not usuario_id or not nueva_contrasena:
        return jsonify({"exito": False, "error": "Datos incompletos"}), 400

    usuario = Usuario.query.get(usuario_id)

    if not usuario:
        return jsonify({"exito": False, "error": "Usuario no encontrado"}), 404

    usuario.contrasena = generate_password_hash(nueva_contrasena)
    db.session.commit()

    return jsonify({"exito": True, "mensaje": "Contraseña actualizada correctamente"}), 200


if __name__ != '__main__':
    with app.app_context():
        db.create_all()
else:
    with app.app_context():
        db.create_all()
    app.run(debug=True)
