import os
import sys
import time
import uuid
import secrets
import hmac

from urllib.parse import quote

try:
    from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
    from flask_bcrypt import Bcrypt
    from functools import wraps
    from werkzeug.utils import secure_filename 
    from dotenv import load_dotenv
except Exception as e:
    print("\nERROR: faltan dependencias necesarias para ejecutar la aplicación.")
    print("Instale las dependencias dentro del entorno virtual y vuelva a intentarlo.")
    print("Comandos recomendados (desde el venv activado):")
    print("  pip install -r requirements.txt")
    print("Si no dispone de requirements.txt, instale al menos:")
    print("  pip install flask flask-bcrypt pymysql sqlalchemy python-dotenv")
    print("\nDetalle del error:", e, "\n")
    sys.exit(1)

from db import db
from db_supabase import get_connection_auth, get_connection_tienda
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY no definida. Créala en el archivo .env (p. ej. con: "
        "python -c \"import secrets; print(secrets.token_hex(32))\")."
    )

os.environ['TZ'] = 'America/Lima'


_tienda_uri = os.environ.get("DATABASE_URI_TIENDA")
if not _tienda_uri:
    raise RuntimeError("DATABASE_URI_TIENDA no definida en el archivo .env.")
app.config["SQLALCHEMY_DATABASE_URI"] = _tienda_uri

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 30
}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER      = os.path.join(app.root_path, 'static', 'img')
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024   # 5 MB máximo
# Endurecer la cookie de sesión: HttpOnly + SameSite=Lax.
# Secure solo si SESSION_COOKIE_SECURE=1 en el entorno (requiere HTTPS; en dev local se desactiva).
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def guardar_imagen(file_field):
    archivo = request.files.get(file_field)
    if not archivo or archivo.filename == '':
        return None
    if not allowed_file(archivo.filename):
        flash('Formato no permitido. Usa JPG, PNG, WEBP o GIF.', 'danger')
        return None
    ext          = archivo.filename.rsplit('.', 1)[1].lower()
    nombre_unico = f"{uuid.uuid4().hex}.{ext}"
    archivo.save(os.path.join(UPLOAD_FOLDER, nombre_unico))
    return nombre_unico
db.init_app(app)
bcrypt = Bcrypt(app)


def _inicializar_schema_auth():
    """Crea (si no existen) las tablas auxiliares de OTP/verificación en la BD
    Auth. Precondición: la tabla `cliente` ya debe existir.

    HISTÓRICO/CAUSA DE BUG: el archivo migracion_verificacion.sql definía una
    tabla `verificacion_registro` con sintaxis MySQL, mientras que el código
    usa `verificacion_cuenta` (PostgreSQL/Supabase). Si la tabla correcta no
    se creó, cualquier INSERT de registro falla y el usuario recibe el error
    genérico "No se pudo iniciar el registro". Este bootstrap es autocorregible.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection_auth()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS verificacion_cuenta (
                id_verificacion     SERIAL PRIMARY KEY,
                id_cliente          INTEGER NOT NULL,
                codigo_hash         TEXT NOT NULL,
                creado_en           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expira_en           TIMESTAMPTZ NOT NULL,
                usado               BOOLEAN NOT NULL DEFAULT FALSE,
                intentos_fallidos   INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recuperacion_contrasena (
                id_recuperacion     SERIAL PRIMARY KEY,
                id_usuario          INTEGER,
                id_cliente          INTEGER,
                codigo_hash         TEXT NOT NULL,
                creado_en           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expira_en           TIMESTAMPTZ NOT NULL,
                usado               BOOLEAN NOT NULL DEFAULT FALSE,
                intentos_fallidos   INTEGER NOT NULL DEFAULT 0,
                ip_solicitud        VARCHAR(64)
            )
        """)
        conn.commit()
        # Funcionalidad 1 (POS): columna `origen` para distinguir clientes creados
        # desde el Punto de Venta (origen='pos') de los registrados por la web
        # (origen='web'). Autocorrección igual que las tablas OTP: si el SQL de
        # migración no se ejecutó, se agrega aquí al arrancar la app.
        cursor.execute("""
            ALTER TABLE cliente
                ADD COLUMN IF NOT EXISTS origen VARCHAR(10) NOT NULL DEFAULT 'web'
        """)
        conn.commit()
        # Índice único parcial por documento: evita duplicar clientes al repetir
        # el mismo DNI/RUC desde el POS. Excluye ''/NULL (clientes web en registro).
        # Se aplica en commit aparte para que si existen duplicados viejos en
        # producción, el fallo de este índice NO revierta la columna origen.
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_cliente_documento
            ON cliente (id_tipo_documento, nro_documento)
            WHERE nro_documento IS NOT NULL AND nro_documento <> ''
        """)
        conn.commit()
        # Funcionalidad 1 (POS): los clientes creados desde el Punto de Venta no
        # tienen credenciales web (email y contrasena NULL por diseño; no pueden
        # iniciar sesión y el modal POS ni siquiera los solicita). `telefono` y
        # `direccion` también son opcionales (modal POS y formulario web los
        # validan a nivel de aplicación, no de BD). Si la BD Auth los declara
        # NOT NULL, el INSERT de /clientes/registrar_pos falla con
        # "null value in column ... violates not-null constraint". Aquí se
        # alinea la BD con el modelo de la app: solo se liberan las columnas
        # que EL PROPIO CÓDIGO envía como NULL y que el negocio no exige.
        # El registro web sigue exigiendo email y dirección en el formulario.
        for _col in ('email', 'contrasena', 'telefono', 'direccion'):
            cursor.execute("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'cliente'
                  AND column_name = %s
            """, (_col,))
            _row = cursor.fetchone()
            if _row is not None and _row[0] == 'NO':
                cursor.execute(
                    'ALTER TABLE cliente ALTER COLUMN %s DROP NOT NULL' % _col
                )
                conn.commit()
        app.logger.info("Esquema Auth verificado (verificacion_cuenta / recuperacion_contrasena / origen / columnas opcionales POS).")
    except Exception as e:
        app.logger.error(f"No se pudo crear el esquema auxiliar Auth: {e}")
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


with app.app_context():
    _inicializar_schema_auth()


def enviar_correo(destino, asunto, cuerpo_html, cuerpo_texto=None):
    
    smtp_user = os.environ.get('SMTP_USER', '').strip()
    smtp_pass = os.environ.get('SMTP_PASS', '').strip()
    if not smtp_user or not smtp_pass:
        app.logger.warning("SMTP no configurado (faltan SMTP_USER/SMTP_PASS en .env).")
        return 'smtp_no_configurado'
    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import smtplib

        msg = MIMEMultipart('alternative')
        msg['Subject'] = asunto
        msg['From']    = f'Ferretería CLEOFERR <{smtp_user}>'
        msg['To']      = destino
        msg.attach(MIMEText(cuerpo_texto or '', 'plain', 'utf-8'))
        msg.attach(MIMEText(cuerpo_html, 'html', 'utf-8'))

        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [destino], msg.as_string())
        server.quit()
        app.logger.info(f"Correo enviado a {destino} (asunto: {asunto})")
        return None
    except smtplib.SMTPAuthenticationError:
        app.logger.error("Gmail SMTP: error de autenticación. "
                         "Verifica SMTP_USER y SMTP_PASS (usa contraseña de aplicación).")
        return 'smtp_auth'
    except Exception as e:
        app.logger.error(f"Error enviando correo a {destino}: {e}")
        return 'error'


class Producto(db.Model):
    __tablename__ = "producto"
    id_producto  = db.Column(db.Integer, primary_key=True)
    nombre       = db.Column(db.String(100))
    descripcion  = db.Column(db.Text)
    precio       = db.Column(db.Numeric(10, 2))
    stock        = db.Column(db.Integer, default=0)
    id_categoria = db.Column(db.Integer)
    id_marca     = db.Column(db.Integer)
    activo       = db.Column(db.Boolean, default=True)
    imagen       = db.Column(db.String(255))

    def __repr__(self):
        return f"<Producto {self.nombre}>"


# ── Decorators ──────────────────────────────────────────────
# Rate-limit simple en memoria para los inicios de sesión (sin dependencias).
# Clave: IP + correo normalizado. Ventana de 15 min, máx 5 intentos fallidos.
_LIMITE_LOGIN = 5
_VENTANA_LOGIN = 900  # 15 minutos
_FALLOS_LOGIN = {}


def _clave_login(correo):
    return f"{request.remote_addr or '?'}:{str(correo or '').strip().lower()}"


def _bloqueado_login(clave):
    ahora = time.time()
    rec = _FALLOS_LOGIN.get(clave)
    if not rec:
        return False
    if ahora - rec.get('t', 0) > _VENTANA_LOGIN:
        _FALLOS_LOGIN.pop(clave, None)
        return False
    return rec['n'] >= _LIMITE_LOGIN


def _registrar_error_login(clave):
    ahora = time.time()
    rec = _FALLOS_LOGIN.get(clave)
    if not rec or ahora - rec.get('t', 0) > _VENTANA_LOGIN:
        _FALLOS_LOGIN[clave] = {'n': 1, 't': ahora}
    else:
        rec['n'] = rec.get('n', 0) + 1


def _resetear_login(clave):
    _FALLOS_LOGIN.pop(clave, None)


# ── CSRF focalizado ─────────────────────────────────────────
# Sin depender de Flask-WTF: token por sesión, validado SOLO en los endpoints
# de mayor riesgo (auth, OTP, cambio de clave, carrito/pago).
_CSRF_PROTEGIDAS = {
    'login', 'login_cliente', 'registro_cliente', 'verificar_registro',
    'recuperar_contrasena', 'restablecer_contrasena', 'cambiar_clave',
    'procesar_pago', 'carrito_confirmar_v2', 'carrito_agregar',
    'registrar_pos',
}


def _obtener_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['_csrf_token'] = token
    return token


@app.context_processor
def _ctx_csrf_token():
    return {'csrf_token': _obtener_csrf_token()}


@app.before_request
def _validar_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    if request.endpoint not in _CSRF_PROTEGIDAS:
        return None
    procedente = request.form.get('csrf_token') \
        or request.headers.get('X-CSRFToken') \
        or (request.get_json(silent=True) or {}).get('csrf_token')
    if procedente and hmac.compare_digest(str(procedente), session.get('_csrf_token', '')):
        return None
    return abort(400)


# Rutas de cliente (públicas/catálogo) que deben redirigir a /login_cliente,
# no al login administrativo
_RUTAS_CLIENTE = ('/carrito', '/mis_pedidos', '/procesar_pago')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:

            if any(request.path.startswith(r) for r in _RUTAS_CLIENTE):
                return redirect(url_for("login_cliente"))
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def escritura_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") not in ("administrador", "vendedor"):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ── Auth ─────────────────────────────────────────────────────
@app.context_processor
def _ctx_recuperacion_origen():
    """Determina desde qué login se llegó a recuperar_contrasena (admin | cliente)."""
    return {'recuperar_origen': request.values.get('origen', 'cliente')}


@app.route('/')
def inicio():
    return redirect(url_for('catalogo_cliente'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        clave  = request.form['clave']
        clave_lim = _clave_login(correo)
        if _bloqueado_login(clave_lim):
            return render_template('login.html', error='Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.')
        conn   = get_connection_auth()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.id_usuario, u.nombres, u.email, u.contrasena, r.nombre AS rol
            FROM usuario u
            INNER JOIN rol r ON u.id_rol = r.id_rol
            WHERE u.email = %s
        """, (correo,))
        usuario = cursor.fetchone()
        conn.close()

        if usuario and bcrypt.check_password_hash(usuario['contrasena'], clave):
            rol_usuario = (usuario.get('rol') or '').lower()
           
            if rol_usuario not in ('administrador', 'vendedor'):
              
                return render_template('login.html', error='Acceso restringido. Esta sección es solo para el personal administrativo de CLEOFERR.')
            _resetear_login(clave_lim)
            session['usuario_id'] = usuario['id_usuario']
            session['rol']        = usuario['rol']
            session['nombre']     = usuario['nombres']
            return redirect(url_for('productos'))
        _registrar_error_login(clave_lim)
        return render_template('login.html', error='Credenciales incorrectas')
    
    msg_admin = quote(
        "Hola Soporte de Inversiones CLEOFERR, soy del personal ADMINISTRATIVO "
        "(Administradora/Vendedora) y presento problemas con mis credenciales de acceso al sistema."
    )
    url_whatsapp = f"https://wa.me/51900555015?text={msg_admin}"
    return render_template('login.html', url_whatsapp=url_whatsapp)


@app.route('/login_cliente', methods=['GET', 'POST'])
def login_cliente():
    if request.method == 'POST':
        correo     = request.form['correo']
        contrasena = request.form['contrasena']
        clave_lim  = _clave_login(correo)
        if _bloqueado_login(clave_lim):
            return render_template('login_cliente.html',
                                   error='Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.')
        conn       = get_connection_auth()
        cursor     = conn.cursor(dictionary=True)
        # Busca el cliente por email — la columna nombre puede variar
        cursor.execute("SELECT * FROM cliente WHERE email = %s", (correo,))
        cliente = cursor.fetchone()
        conn.close()

        if cliente:
            # Cuenta registrada pero sin verificar su correo
            if not cliente.get('activo'):
                return render_template('login_cliente.html',
                                       error='Tu cuenta aún no está verificada. Completa el registro con el código enviado a tu correo.',
                                       registro_activo=True)
            # Solo Bcrypt: las contraseñas de clientes deben estar hasheadas con bcrypt.
            # Si el hash almacenado no es bcrypt válido, el acceso se rechaza.
            stored = cliente.get('contrasena') or cliente.get('password') or ''
            try:
                ok = bcrypt.check_password_hash(stored, contrasena)
            except (ValueError, TypeError):
                ok = False

            if ok:
                _resetear_login(clave_lim)
                nombre_cliente = (
                    cliente.get('nombre') or
                    cliente.get('nombres') or
                    cliente.get('name') or
                    cliente.get('email')
                )
                session['usuario_id'] = cliente.get('id_cliente') or cliente.get('id')
                session['rol']        = 'cliente'
                session['nombre']     = nombre_cliente
                return redirect(url_for('catalogo_cliente'))

        _registrar_error_login(clave_lim)
        return render_template('login_cliente.html', error='Credenciales incorrectas')
    # Botón WhatsApp para recuperar credenciales (clientes)
    msg_cliente = quote(
        "Hola Soporte de Inversiones CLEOFERR, soy un CLIENTE registrado y necesito ayuda "
        "para recuperar mi contraseña o mis datos de acceso al sistema web."
    )
    url_whatsapp = f"https://wa.me/51900555015?text={msg_cliente}"
    return render_template('login_cliente.html', url_whatsapp=url_whatsapp)


@app.route('/logout')
@login_required
def logout():
    es_cliente = session.get('rol') == 'cliente'
    session.clear()
    return redirect(url_for('login_cliente') if es_cliente else url_for('login'))



@app.route('/productos')
@login_required
def productos():
    if session.get('rol') == 'cliente':
        return redirect(url_for('catalogo_cliente'))

    categoria = request.args.get('categoria')
    marca     = request.args.get('marca')
    conn      = get_connection_tienda()
    cursor    = conn.cursor(dictionary=True)

    query = """
        SELECT p.*, c.nombre AS categoria, m.nombre AS marca
        FROM producto p
        LEFT JOIN categoria c ON p.id_categoria = c.id_categoria
        LEFT JOIN marca m ON p.id_marca = m.id_marca
        WHERE 1=1
    """
    params = []
    if categoria:
        query += " AND c.nombre = %s"
        params.append(categoria)
    if marca:
        query += " AND m.nombre = %s"
        params.append(marca)
    query += " ORDER BY p.id_producto"
    cursor.execute(query, params)
    lista = cursor.fetchall()

    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()

    # Contadores para los cards del dashboard
    pedidos_count = 0
    alertas_count = 0
    movimientos_count = 0
    bajo_stock = []
    try:
        cursor.execute("SELECT COUNT(*) AS cnt FROM venta")
        pedidos_count = cursor.fetchone()['cnt']
    except Exception:
        pass
    try:
        cursor.execute("SELECT COUNT(*) AS cnt FROM alerta WHERE resuelta = FALSE")
        alertas_count = cursor.fetchone()['cnt']
    except Exception:
        pass
    try:
        cursor.execute("SELECT COUNT(*) AS cnt FROM inventario_movimiento WHERE DATE(fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima') = CURRENT_DATE")
        movimientos_count = cursor.fetchone()['cnt']
    except Exception:
        pass
    try:
        cursor.execute("""
            SELECT id_producto, nombre, stock, stock_minimo, precio
            FROM producto WHERE stock < 15 ORDER BY stock ASC
        """)
        bajo_stock = cursor.fetchall()
    except Exception:
        pass

    conn.close()

    return render_template('productos.html', productos=lista, categorias=categorias, marcas=marcas,
                           pedidos_count=pedidos_count, alertas_count=alertas_count,
                           reportes_count=movimientos_count, bajo_stock=bajo_stock)


@app.route('/productos/detalle/<int:id>')
@login_required
@escritura_required
def producto_detalle(id):
    producto = db.get_or_404(Producto, id)
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    movimientos = []
    categoria_nombre = '–'
    marca_nombre = '–'
    try:
        if producto.id_categoria:
            cursor.execute("SELECT nombre FROM categoria WHERE id_categoria = %s", (producto.id_categoria,))
            row = cursor.fetchone()
            if row: categoria_nombre = row['nombre']
        if producto.id_marca:
            cursor.execute("SELECT nombre FROM marca WHERE id_marca = %s", (producto.id_marca,))
            row = cursor.fetchone()
            if row: marca_nombre = row['nombre']
        cursor.execute("""
            SELECT im.*, p.nombre AS producto_nombre
            FROM inventario_movimiento im
            LEFT JOIN producto p ON im.id_producto = p.id_producto
            WHERE im.id_producto = %s
            ORDER BY im.fecha DESC LIMIT 20
        """, (id,))
        movimientos = cursor.fetchall()
    except Exception:
        pass
    finally:
        conn.close()
    return render_template('producto_detalle.html', producto=producto, movimientos=movimientos,
                           categoria_nombre=categoria_nombre, marca_nombre=marca_nombre)


@app.route('/reportes/pedidos/exportar')
@login_required
@escritura_required
def exportar_pedidos_excel():
    """Exporta todos los pedidos a un archivo Excel."""
    try:
        import io, csv
        from flask import make_response
        # Consulta 1 (Tienda): ventas con total, sin joins cross-BD
        conn   = get_connection_tienda()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT v.id_venta,
                   v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima' AS fecha,
                   v.id_cliente,
                   ev.nombre AS estado,
                   tv.nombre AS tipo_venta,
                   v.id_usuario_vendedor,
                   COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            LEFT JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
            GROUP BY v.id_venta, v.fecha, v.id_cliente, ev.nombre,
                     tv.nombre, v.id_usuario_vendedor
            ORDER BY v.fecha DESC
        """)
        ventas = cursor.fetchall()
        conn.close()

        # Consulta 2 (Auth): diccionarios de clientes y usuarios
        conn_a   = get_connection_auth()
        cursor_a = conn_a.cursor(dictionary=True)
        cursor_a.execute("SELECT id_cliente, nombre, apellido, telefono FROM cliente")
        clientes_map = {c['id_cliente']: c for c in cursor_a.fetchall()}
        cursor_a.execute("SELECT id_usuario, nombres FROM usuario")
        usuarios_map = {u['id_usuario']: u for u in cursor_a.fetchall()}
        conn_a.close()

        # Unión en memoria (equivalente al antiguo JOIN cross-BD)
        pedidos = []
        for v in ventas:
            cli = clientes_map.get(v['id_cliente']) or {}
            usr = usuarios_map.get(v['id_usuario_vendedor']) or {}
            pedidos.append({
                'N° Pedido':    v['id_venta'],
                'Fecha (Perú)': v['fecha'],
                'Cliente':      (f"{cli.get('nombre') or ''} {cli.get('apellido') or ''}").strip(),
                'Teléfono':     cli.get('telefono'),
                'Estado':       v['estado'],
                'Tipo':         v['tipo_venta'],
                'Responsable':  usr.get('nombres'),
                'Total (S/)':   v['total'],
            })

        # Intentar usar openpyxl si está disponible, si no usar CSV
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Alignment
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Pedidos"

            # Encabezado con estilo
            headers = list(pedidos[0].keys()) if pedidos else ['N° Pedido','Fecha (Perú)','Cliente','Teléfono','Estado','Tipo','Responsable','Total (S/)']
            header_fill = PatternFill("solid", fgColor="1A1A2E")
            header_font = Font(color="FFFFFF", bold=True)
            for col, h in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col, value=h)
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = Alignment(horizontal='center')

            # Datos
            for row_idx, ped in enumerate(pedidos, 2):
                for col_idx, val in enumerate(ped.values(), 1):
                    cell = ws.cell(row=row_idx, column=col_idx, value=str(val) if val is not None else '')
                    if row_idx % 2 == 0:
                        cell.fill = PatternFill("solid", fgColor="EEF4FB")

            # Ancho de columnas automático
            for col in ws.columns:
                max_len = max((len(str(c.value or '')) for c in col), default=10)
                ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)

            output = io.BytesIO()
            wb.save(output)
            output.seek(0)
            response = make_response(output.read())
            response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            response.headers['Content-Disposition'] = 'attachment; filename=pedidos_cleoferr.xlsx'
            return response

        except ImportError:
            # Fallback a CSV si openpyxl no está instalado
            output = io.StringIO()
            if pedidos:
                writer = csv.DictWriter(output, fieldnames=pedidos[0].keys())
                writer.writeheader()
                for ped in pedidos:
                    writer.writerow({k: str(v) if v is not None else '' for k, v in ped.items()})
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv; charset=utf-8'
            response.headers['Content-Disposition'] = 'attachment; filename=pedidos_cleoferr.csv'
            return response

    except Exception as e:
        flash(f'Error al exportar pedidos: {e}', 'danger')
        return redirect(url_for('pedidos'))


def _excel_response(rows, filename, sheet_name='Datos'):
    """Helper: genera respuesta Excel/CSV a partir de una lista de dicts."""
    import io, csv
    from flask import make_response
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = sheet_name
        if not rows:
            output = io.BytesIO()
            wb.save(output); output.seek(0)
            resp = make_response(output.read())
            resp.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
            return resp
        headers = list(rows[0].keys())
        hf = PatternFill("solid", fgColor="1A1A2E")
        hfont = Font(color="FFFFFF", bold=True)
        for col, h in enumerate(headers, 1):
            c = ws.cell(row=1, column=col, value=h)
            c.fill = hf; c.font = hfont; c.alignment = Alignment(horizontal='center')
        alt = PatternFill("solid", fgColor="EEF4FB")
        for ri, row in enumerate(rows, 2):
            for ci, val in enumerate(row.values(), 1):
                cell = ws.cell(row=ri, column=ci, value=str(val) if val is not None else '')
                if ri % 2 == 0: cell.fill = alt
        for col in ws.columns:
            w = max((len(str(c.value or '')) for c in col), default=10)
            ws.column_dimensions[col[0].column_letter].width = min(w + 4, 40)
        output = io.BytesIO()
        wb.save(output); output.seek(0)
        resp = make_response(output.read())
        resp.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return resp
    except ImportError:
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            for r in rows: writer.writerow({k: str(v) if v is not None else '' for k, v in r.items()})
        resp = make_response('\ufeff' + output.getvalue())
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename={filename.replace(".xlsx",".csv")}'
        return resp


@app.route('/reportes/productos/exportar')
@login_required
@escritura_required
def exportar_productos_excel():
    conn = get_connection_tienda(); cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT p.id_producto AS "ID", p.nombre AS "Producto",
                   c.nombre AS "Categoría", m.nombre AS "Marca",
                   p.precio AS "Precio (S/)", p.stock AS "Stock",
                   CASE WHEN p.activo THEN 'activo' ELSE 'inactivo' END AS "Estado"
            FROM producto p
            LEFT JOIN categoria c ON p.id_categoria = c.id_categoria
            LEFT JOIN marca m ON p.id_marca = m.id_marca
            ORDER BY p.id_producto
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()
    return _excel_response(rows, 'productos_cleoferr.xlsx', 'Productos')


@app.route('/reportes/clientes/exportar')
@login_required
@escritura_required
def exportar_clientes_excel():
    conn = get_connection_auth(); cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id_cliente AS "ID",
                   CONCAT(COALESCE(nombre,''), ' ', COALESCE(apellido,'')) AS "Nombre completo",
                   email AS "Correo", telefono AS "Teléfono",
                   CASE WHEN activo THEN 'activo' ELSE 'inactivo' END AS "Estado"
            FROM cliente ORDER BY id_cliente
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()
    return _excel_response(rows, 'clientes_cleoferr.xlsx', 'Clientes')


@app.route('/reportes/proveedores/exportar')
@login_required
@escritura_required
def exportar_proveedores_excel():
    conn = get_connection_tienda(); cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id_proveedor AS "ID", nombre AS "Proveedor",
                   contacto AS "Contacto", telefono AS "Teléfono",
                   email AS "Correo",
                   CASE WHEN activo THEN 'activo' ELSE 'inactivo' END AS "Estado"
            FROM proveedor ORDER BY id_proveedor
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()
    return _excel_response(rows, 'proveedores_cleoferr.xlsx', 'Proveedores')


@app.route('/reportes/inventario/exportar')
@login_required
@escritura_required
def exportar_inventario_excel():
    conn = get_connection_tienda(); cursor = conn.cursor(dictionary=True)
    try:
        # Consulta 1 (Tienda): movimientos + producto
        cursor.execute("""
            SELECT im.id_movimiento AS id,
                   im.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima' AS fecha,
                   p.nombre AS producto,
                   im.tipo,
                   im.cantidad,
                   im.id_usuario,
                    COALESCE(im.observacion, '') AS motivo
            FROM inventario_movimiento im
            LEFT JOIN producto p ON im.id_producto = p.id_producto
            ORDER BY im.fecha DESC
        """)
        movimientos = cursor.fetchall()
        # Consulta 2 (Auth): nombres de usuarios
        conn_a = get_connection_auth()
        cursor_a = conn_a.cursor(dictionary=True)
        cursor_a.execute("SELECT id_usuario, nombres FROM usuario")
        usuarios_map = {u['id_usuario']: u['nombres'] for u in cursor_a.fetchall()}
        conn_a.close()
        # Unión en memoria
        rows = [{
            'ID': m['id'],
            'Fecha (Perú)': m['fecha'],
            'Producto': m['producto'],
            'Tipo': m['tipo'],
            'Cantidad': m['cantidad'],
            'Responsable': usuarios_map.get(m['id_usuario'], ''),
            'Motivo': m['motivo'],
        } for m in movimientos]
    except Exception:
        try:
            cursor.execute("""
                SELECT p.nombre AS "Producto", p.stock AS "Stock actual"
                 FROM producto p WHERE p.activo = TRUE ORDER BY p.nombre
            """)
            rows = cursor.fetchall()
        except Exception:
            rows = []
    finally:
        conn.close()
    return _excel_response(rows, 'inventario_cleoferr.xlsx', 'Inventario')


@app.route('/reportes/dia/exportar')
@login_required
@escritura_required
def exportar_ventas_dia_excel():
    conn = get_connection_tienda(); cursor = conn.cursor(dictionary=True)
    try:
        # Consulta 1 (Tienda): ventas del día (hora Perú) sin join a cliente
        cursor.execute("""
            SELECT v.id_venta,
                   v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima' AS fecha,
                   v.id_cliente,
                   ev.nombre AS estado,
                   tv.nombre AS tipo_venta,
                   COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            LEFT JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
            WHERE DATE(v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima') = CURRENT_DATE
            GROUP BY v.id_venta, v.fecha, v.id_cliente, ev.nombre, tv.nombre
            ORDER BY v.fecha DESC
        """)
        ventas = cursor.fetchall()
        # Consulta 2 (Auth): clientes + unión en memoria
        conn_a = get_connection_auth()
        cursor_a = conn_a.cursor(dictionary=True)
        cursor_a.execute("SELECT id_cliente, nombre, apellido FROM cliente")
        clientes_map = {c['id_cliente']: c for c in cursor_a.fetchall()}
        conn_a.close()
        rows = []
        for v in ventas:
            cli = clientes_map.get(v['id_cliente']) or {}
            rows.append({
                'N° Pedido': v['id_venta'],
                'Fecha/Hora (Perú)': v['fecha'],
                'Cliente': (f"{cli.get('nombre') or ''} {cli.get('apellido') or ''}").strip(),
                'Estado': v['estado'],
                'Tipo': v['tipo_venta'],
                'Total (S/)': v['total'],
            })
    finally:
        conn.close()
    return _excel_response(rows, 'ventas_hoy_cleoferr.xlsx', 'Ventas de hoy')


@app.route('/reportes/exportar')
@login_required
@escritura_required
def exportar_reportes_excel():
    return exportar_ventas_dia_excel()



@app.route('/productos/nuevo')
@login_required
@escritura_required
def nuevo_producto():
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()
    conn.close()
    return render_template('producto_form.html', categorias=categorias, marcas=marcas)


@app.route('/productos/guardar', methods=['POST'])
@login_required
@escritura_required
def guardar_producto():
    nombre_imagen = guardar_imagen('imagen')
    nuevo = Producto(
        nombre       = request.form['nombre'],
        descripcion  = request.form['descripcion'],
        precio       = request.form['precio'],
        stock        = request.form['stock'],
        id_categoria = request.form['id_categoria'],
        id_marca     = request.form['id_marca'],
        activo       = request.form.get('estado', 'activo') != 'inactivo',
        imagen       = nombre_imagen
    )
    db.session.add(nuevo)
    db.session.commit()
    flash("Producto creado correctamente.", "success")
    return redirect(url_for('productos'))


@app.route('/productos/editar/<int:id>')
@login_required
@escritura_required
def editar_producto(id):
    producto = db.get_or_404(Producto, id)
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categoria")
    categorias = cursor.fetchall()
    cursor.execute("SELECT * FROM marca")
    marcas = cursor.fetchall()
    conn.close()
    return render_template('producto_form.html', producto=producto, categorias=categorias, marcas=marcas)


@app.route('/productos/actualizar/<int:id>', methods=['POST'])
@login_required
@escritura_required
def actualizar_producto(id):
    producto             = db.get_or_404(Producto, id)
    nombre_imagen = guardar_imagen('imagen')            # ← NUEVO
    if nombre_imagen and producto.imagen:               # ← NUEVO: borra imagen vieja
        ruta_vieja = os.path.join(UPLOAD_FOLDER, producto.imagen)
        if os.path.exists(ruta_vieja):
            os.remove(ruta_vieja)
    producto.nombre      = request.form['nombre']
    producto.descripcion = request.form['descripcion']
    producto.precio      = request.form['precio']
    producto.stock       = request.form['stock']
    producto.id_categoria = request.form['id_categoria']
    producto.id_marca    = request.form['id_marca']
    producto.activo      = request.form.get('estado', 'activo') != 'inactivo'
    if nombre_imagen:                                   # ← CAMBIÓ
        producto.imagen = nombre_imagen
    db.session.commit()
    flash("Producto actualizado correctamente.", "success")
    return redirect(url_for('productos'))


@app.route('/productos/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_producto(id):
    producto = db.get_or_404(Producto, id)
    db.session.delete(producto)
    db.session.commit()
    flash("Producto eliminado correctamente.", "success")
    return redirect(url_for('productos'))



@app.route('/catalogo')
def catalogo_cliente():
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, c.nombre AS categoria, m.nombre AS marca
        FROM producto p
        LEFT JOIN categoria c ON p.id_categoria = c.id_categoria
        LEFT JOIN marca m ON p.id_marca = m.id_marca
        WHERE p.activo = TRUE
        ORDER BY p.id_producto
    """)
    lista = cursor.fetchall()
    conn.close()
    return render_template('catalogo.html', productos=lista)


# ── Gestión de Clientes ───────────────────────────────────────
@app.route('/clientes')
@login_required
@escritura_required
def clientes():
    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'cliente'
        ORDER BY ordinal_position
    """)
    columnas = [c['column_name'] for c in cursor.fetchall()]
    cursor.execute("SELECT * FROM cliente ORDER BY id_cliente DESC")
    lista = cursor.fetchall()
    conn.close()
    return render_template('clientes.html', clientes=lista, columnas=columnas)


@app.route('/clientes/nuevo', methods=['GET', 'POST'])
@login_required
@escritura_required
def nuevo_cliente():
    if request.method == 'POST':
        nombre    = request.form['nombre']
        email     = request.form['email']
        telefono  = request.form.get('telefono', '')
        direccion = request.form.get('direccion', '')
        contrasena = request.form.get('contrasena', '123456')
        hash_pw   = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        conn   = get_connection_auth()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO cliente (nombre, email, telefono, direccion, contrasena) VALUES (%s,%s,%s,%s,%s)",
                (nombre, email, telefono, direccion, hash_pw)
            )
            conn.commit()
            flash("Cliente registrado correctamente.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error al registrar cliente: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('clientes'))
    return render_template('cliente_form.html')


@app.route('/clientes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@escritura_required
def editar_cliente(id):
    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        nombre    = request.form['nombre']
        email     = request.form['email']
        telefono  = request.form.get('telefono', '')
        direccion = request.form.get('direccion', '')
        try:
            cursor.execute(
                "UPDATE cliente SET nombre=%s, email=%s, telefono=%s, direccion=%s WHERE id_cliente=%s",
                (nombre, email, telefono, direccion, id)
            )
            conn.commit()
            flash("Cliente actualizado correctamente.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('clientes'))

    cursor.execute("SELECT * FROM cliente WHERE id_cliente = %s", (id,))
    cliente = cursor.fetchone()
    conn.close()
    if not cliente:
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for('clientes'))
    return render_template('cliente_form.html', cliente=cliente)


# ── Registro rápido de cliente desde el Punto de Venta (por DNI/RUC) ────────
# Boleta  → DNI (8 dígitos) + nombre (autocompletado vía RENIEC en el frontend).
# Factura → RUC (11 dígitos, inicia en 10 o 20) + razón social + dirección fiscal.
# id_tipo_documento: 1 = DNI, 6 = RUC (catálogo SUNAT; el proyecto ya usa 1 = DNI
# en seed_data.py). Los clientes POS se crean con origen='pos' y sin email ni
# contraseña (no pueden iniciar sesión web, pero sí aparecen en ventas/reportes).
@app.route('/clientes/registrar_pos', methods=['POST'])
@login_required
@escritura_required
def registrar_pos():
    data = request.get_json(silent=True) or {}
    tipo = (data.get('tipo') or 'boleta').strip().lower()
    if tipo not in ('boleta', 'factura'):
        return {'ok': False, 'error': 'Tipo de comprobante inválido.'}, 400

    nombre    = (data.get('nombre') or '').strip()
    telefono  = (data.get('telefono') or '').strip()
    apellido  = (data.get('apellido') or '').strip()
    direccion = (data.get('direccion') or '').strip()

    if tipo == 'boleta':
        doc = (data.get('dni') or '').strip()
        if not doc.isdigit() or len(doc) != 8:
            return {'ok': False, 'error': 'El DNI debe tener exactamente 8 dígitos.'}, 400
        if len(nombre) < 3:
            return {'ok': False, 'error': 'El nombre del cliente es obligatorio (mínimo 3 caracteres).'}, 400
    else:
        doc = (data.get('ruc') or '').strip()
        if not doc.isdigit() or len(doc) != 11 or doc[:2] not in ('10', '20'):
            return {'ok': False, 'error': 'El RUC debe tener 11 dígitos y comenzar con 10 o 20.'}, 400
        if len(nombre) < 3:
            return {'ok': False, 'error': 'La razón social es obligatoria (mínimo 3 caracteres).'}, 400
        if len(direccion) < 5:
            return {'ok': False, 'error': 'La dirección fiscal es obligatoria para factura (mínimo 5 caracteres).'}, 400

    if telefono and (not telefono.isdigit() or len(telefono) != 9):
        return {'ok': False, 'error': 'El teléfono debe tener exactamente 9 dígitos.'}, 400

    id_tipo_doc = 1 if tipo == 'boleta' else 6
    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    try:
        # ¿Ya existe un cliente con ese documento? → se reutiliza (no se duplica)
        cursor.execute("""
            SELECT id_cliente, nombre, apellido, telefono FROM cliente
            WHERE id_tipo_documento = %s AND nro_documento = %s
        """, (id_tipo_doc, doc))
        existente = cursor.fetchone()
        if existente:
            if telefono and not (existente.get('telefono') or '').strip():
                cursor.execute(
                    "UPDATE cliente SET telefono = %s WHERE id_cliente = %s",
                    (telefono, existente['id_cliente']))
                conn.commit()
            nombre_existente = f"{existente.get('nombre') or ''} {existente.get('apellido') or ''}".strip()
            return {'ok': True, 'id_cliente': existente['id_cliente'],
                    'nombre': nombre_existente, 'ya_existia': True}

        # `apellido` es NOT NULL en la BD. Si no se envió y es una boleta (RENIEC:
        # Nombres ApellidoPaterno ApellidoMaterno), separamos el nombre completo;
        # como último recurso usamos '' (cadena vacía respeta NOT NULL). En
        # factura, la razón social se guarda completa en `nombre` y `apellido` ''.
        nombre_db   = nombre
        apellido_db = apellido
        if not apellido_db and tipo == 'boleta':
            partes = nombre.split()
            if len(partes) >= 2:
                nombre_db   = partes[0]
                apellido_db = ' '.join(partes[1:])
        cursor.execute("""
            INSERT INTO cliente (nombre, apellido, email, telefono, id_tipo_documento,
                                 nro_documento, direccion, contrasena, activo, origen)
            VALUES (%s, %s, NULL, %s, %s, %s, %s, NULL, TRUE, 'pos')
            RETURNING id_cliente
        """, (nombre_db, apellido_db, telefono or None, id_tipo_doc, doc,
              direccion or None))
        id_cliente = cursor.fetchone()['id_cliente']
        conn.commit()
        # Nombre completo para mostrar en el select del POS
        nombre_mostrar = f"{nombre_db} {apellido_db}".strip()
        return {'ok': True, 'id_cliente': id_cliente, 'nombre': nombre_mostrar,
                'ya_existia': False}
    except Exception as e:
        conn.rollback()
        app.logger.error("Error al registrar cliente desde el POS: %s", e)
        return {'ok': False, 'error': 'No se pudo guardar el cliente (error interno).'}, 500
    finally:
        conn.close()


@app.route('/clientes/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_cliente(id):
    conn   = get_connection_auth()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM cliente WHERE id_cliente = %s", (id,))
        conn.commit()
        flash("Cliente eliminado.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('clientes'))


# ── Inventario ────────────────────────────────────────────────
@app.route('/inventario')
@login_required
@escritura_required
def inventario():
    # Consulta 1 (Tienda): movimientos + producto + proveedor
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.*, p.nombre AS producto_nombre, pr.nombre AS proveedor_nombre
        FROM inventario_movimiento i
        LEFT JOIN producto p ON i.id_producto = p.id_producto
        LEFT JOIN proveedor pr ON i.id_proveedor = pr.id_proveedor
        ORDER BY i.fecha DESC
        LIMIT 200
    """)
    movimientos = cursor.fetchall()

    cursor.execute("SELECT * FROM producto WHERE activo = TRUE ORDER BY nombre")
    productos = cursor.fetchall()
    cursor.execute("SELECT * FROM proveedor ORDER BY nombre")
    proveedores = cursor.fetchall()
    conn.close()

    # Consulta 2 (Auth): usuarios y vendedores
    conn_a   = get_connection_auth()
    cursor_a = conn_a.cursor(dictionary=True)
    cursor_a.execute("SELECT id_usuario, nombres FROM usuario")
    usuarios_map = {u['id_usuario']: u['nombres'] for u in cursor_a.fetchall()}
    cursor_a.execute("""
        SELECT u.id_usuario, u.nombres
        FROM usuario u
        INNER JOIN rol r ON u.id_rol = r.id_rol
        WHERE r.nombre = 'vendedor'
        ORDER BY u.nombres
    """)
    vendedores = cursor_a.fetchall()
    conn_a.close()

    # Unión en memoria: añadir nombre de usuario a cada movimiento
    for m in movimientos:
        m['usuario_nombre'] = usuarios_map.get(m.get('id_usuario'))
    return render_template('inventario.html',
                           movimientos=movimientos,
                           productos=productos,
                           proveedores=proveedores,
                           vendedores=vendedores)


@app.route('/inventario/registrar', methods=['POST'])
@login_required
@escritura_required
def registrar_movimiento():
    tipo         = request.form['tipo']           # 'entrada' | 'salida'
    id_producto  = request.form['id_producto']
    # Para compatibilidad: recibimos ambos campos, uno estará vacío según tipo
    id_proveedor = request.form.get('id_proveedor') or None
    id_vendedor  = request.form.get('id_vendedor') or None
    cantidad     = int(request.form['cantidad'])
    precio_unit  = request.form.get('precio_unitario') or 0
    observacion  = request.form.get('observacion', '')
    id_usuario   = session['usuario_id']

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)

    # Obtener stock actual
    cursor.execute("SELECT stock FROM producto WHERE id_producto=%s", (id_producto,))
    prod = cursor.fetchone()
    if not prod:
        flash("Producto no encontrado.", "danger")
        conn.close()
        return redirect(url_for('inventario'))

    stock_actual = prod['stock']
    if tipo == 'salida' and cantidad > stock_actual:
        flash(f"Stock insuficiente. Disponible: {stock_actual}", "danger")
        conn.close()
        return redirect(url_for('inventario'))

    nuevo_stock = stock_actual + cantidad if tipo == 'entrada' else stock_actual - cantidad

    # Si es salida y se seleccionó un vendedor, obtener su nombre y añadir a observación
    # (la tabla usuario vive en la BD Auth, por eso se consulta por separado)
    if tipo == 'salida' and id_vendedor:
        try:
            conn_a   = get_connection_auth()
            cursor_a = conn_a.cursor(dictionary=True)
            cursor_a.execute("SELECT nombres FROM usuario WHERE id_usuario=%s", (id_vendedor,))
            row = cursor_a.fetchone()
            conn_a.close()
            nombre_vendedor = row['nombres'] if row else None
            if nombre_vendedor:
                observacion = f"Vendedor: {nombre_vendedor}" + (f" - {observacion}" if observacion else "")
        except Exception:
            # no crítico, continuar con la observación sin nombre
            pass

    # Para compatibilidad con la estructura actual, solo llenamos id_proveedor para entradas.
    proveedor_db_value = id_proveedor if tipo == 'entrada' and id_proveedor else None

    try:
        cursor.execute("""
            INSERT INTO inventario_movimiento
                (tipo, id_producto, id_proveedor, cantidad, precio_unitario, observacion, id_usuario, stock_resultante)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (tipo, id_producto, proveedor_db_value, cantidad, precio_unit, observacion, id_usuario, nuevo_stock))

        cursor.execute("UPDATE producto SET stock=%s WHERE id_producto=%s", (nuevo_stock, id_producto))
        conn.commit()
        flash(f"Movimiento de {'entrada' if tipo=='entrada' else 'salida'} registrado. Nuevo stock: {nuevo_stock}", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error al registrar movimiento: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('inventario'))


# ── Proveedores ───────────────────────────────────────────────
@app.route('/proveedores')
@login_required
@escritura_required
def proveedores():
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM proveedor ORDER BY nombre")
    lista = cursor.fetchall()
    conn.close()
    return render_template('proveedores.html', proveedores=lista)


@app.route('/proveedores/nuevo', methods=['GET', 'POST'])
@login_required
@escritura_required
def nuevo_proveedor():
    if request.method == 'POST':
        nombre    = request.form['nombre']
        contacto  = request.form.get('contacto', '')
        telefono  = request.form.get('telefono', '')
        email     = request.form.get('email', '')
        direccion = request.form.get('direccion', '')
        conn      = get_connection_tienda()
        cursor    = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO proveedor (nombre, contacto, telefono, email, direccion) VALUES (%s,%s,%s,%s,%s)",
                (nombre, contacto, telefono, email, direccion)
            )
            conn.commit()
            flash("Proveedor registrado.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('proveedores'))
    return render_template('proveedor_form.html')


@app.route('/proveedores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@escritura_required
def editar_proveedor(id):
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        nombre    = request.form['nombre']
        contacto  = request.form.get('contacto', '')
        telefono  = request.form.get('telefono', '')
        email     = request.form.get('email', '')
        direccion = request.form.get('direccion', '')
        try:
            cursor.execute(
                "UPDATE proveedor SET nombre=%s, contacto=%s, telefono=%s, email=%s, direccion=%s WHERE id_proveedor=%s",
                (nombre, contacto, telefono, email, direccion, id)
            )
            conn.commit()
            flash("Proveedor actualizado.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('proveedores'))
    cursor.execute("SELECT * FROM proveedor WHERE id_proveedor=%s", (id,))
    proveedor = cursor.fetchone()
    conn.close()
    return render_template('proveedor_form.html', proveedor=proveedor)


@app.route('/proveedores/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_proveedor(id):
    conn   = get_connection_tienda()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM proveedor WHERE id_proveedor=%s", (id,))
        conn.commit()
        flash("Proveedor eliminado.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('proveedores'))


# Reemplazar/añadir la vista de eliminación evitando sobrescribir un endpoint existente.
# Si ya existe otra función llamada eliminar_proveedor, esta usa un nombre de función y endpoint distintos.
@app.route('/proveedores/eliminar/<int:proveedor_id>', methods=['POST'], endpoint='eliminar_proveedor_post')
@login_required
@admin_required
def eliminar_proveedor_post(proveedor_id):
    if not session.get('usuario_id'):
        flash('Acceso no autorizado.', 'danger')
        return redirect('/login')

    try:
        # Borrado parametrizado para evitar inyecciones
        db.session.execute(text("DELETE FROM proveedor WHERE id_proveedor = :id"), {'id': proveedor_id})
        db.session.commit()
        flash('Proveedor eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar proveedor. Revise dependencias o logs.', 'danger')
        app.logger.exception("Error eliminando proveedor %s: %s", proveedor_id, e)
    return redirect('/proveedores')


# ── Pedidos ─────────────────────────────────────────────────
@app.route('/pedidos')
@login_required
@escritura_required
def pedidos():
    conn = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    # Estados válidos leídos de la tabla estado_venta (nunca desincronizados del HTML)
    cursor.execute("""
        SELECT nombre FROM estado_venta WHERE activo = TRUE ORDER BY orden
    """)
    lista_estados = [r['nombre'] for r in cursor.fetchall()]
    PASOS = [e for e in lista_estados if e != 'cancelado']

    # ── Filtros del panel (desde la barra de filtros del template) ──
    f_desde   = (request.args.get('desde') or '').strip()
    f_hasta   = (request.args.get('hasta') or '').strip()
    f_estado  = (request.args.get('estado') or '').strip()
    f_q       = (request.args.get('q') or '').strip()

    where     = []
    params    = []
    if f_desde:
        where.append("v.fecha::date >= %s")
        params.append(f_desde)
    if f_hasta:
        where.append("v.fecha::date <= %s")
        params.append(f_hasta)
    if f_estado:
        where.append("ev.nombre = %s")
        params.append(f_estado)
    if f_q:
        where.append("(CAST(v.id_venta AS TEXT) ILIKE %s OR v.id_cliente::TEXT ILIKE %s)")
        qq = f'%{f_q}%'
        params.append(qq)
        params.append(qq)
    where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''

    try:
        # Consulta 1 (Tienda): ventas + total, sin joins cross-BD
        cursor.execute(f"""
            SELECT
                v.id_venta      AS id_pedido,
                v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima' AS fecha,
                tv.nombre    AS tipo_venta,
                ev.nombre    AS estado,
                v.id_cliente,
                v.id_usuario_vendedor,
                COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM venta v
            LEFT JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
            {where_sql}
            GROUP BY v.id_venta, v.fecha, tv.nombre, ev.nombre,
                     v.id_cliente, v.id_usuario_vendedor
            ORDER BY v.fecha DESC
            LIMIT 200
        """, params)
        pedidos_raw = cursor.fetchall()

        # Consulta 2 (Auth): clientes y usuarios
        conn_a   = get_connection_auth()
        cursor_a = conn_a.cursor(dictionary=True)
        cursor_a.execute("SELECT id_cliente, nombre, apellido, telefono FROM cliente")
        clientes_map = {c['id_cliente']: c for c in cursor_a.fetchall()}
        cursor_a.execute("SELECT id_usuario, nombres FROM usuario")
        usuarios_map = {u['id_usuario']: u for u in cursor_a.fetchall()}
        conn_a.close()

        # Unión en memoria (equivalente al JOIN cross-BD)
        for ped in pedidos_raw:
            cli = clientes_map.get(ped['id_cliente']) or {}
            usr = usuarios_map.get(ped['id_usuario_vendedor']) or {}
            ped['cliente_nombre']    = (f"{cli.get('nombre') or ''} {cli.get('apellido') or ''}").strip() or None
            ped['cliente_telefono']  = cli.get('telefono')
            ped['responsable']       = usr.get('nombres')

        pedidos = []
        for ped in pedidos_raw:
            estado = ped.get('estado') or 'pendiente'
            ped['idx_actual'] = PASOS.index(estado) if estado in PASOS else -1
            ped['progreso'] = int((ped['idx_actual'] + 1) * 20) if ped['idx_actual'] >= 0 else 0
            # Venta local ya cobrada: NO aplica el flujo de despacho/entrega.
            ped['es_local_entregado'] = (ped.get('tipo_venta') == 'local' and estado == 'entregado')
            nombre   = ped.get('cliente_nombre') or 'Cliente'
            telefono = (ped.get('cliente_telefono') or '').strip()
            # El aviso por WhatsApp ("pedido procesado y listo") es del flujo
            # ONLINE (delivery). Las ventas locales se entregan en mostrador:
            # no se notifica un "pedido listo".
            if telefono and ped.get('tipo_venta') != 'local':
                from urllib.parse import quote
                if telefono.startswith('+'):
                    telefono = telefono[1:]
                if not telefono.startswith('51'):
                    telefono = '51' + telefono
                msg = quote(
                    f"Hola {nombre}, le saludamos de la Ferretería Inversiones CLEOFERR. "
                    "Le informamos que su pedido ya ha sido procesado en nuestro sistema "
                    "y se encuentra listo. ¡Muchas gracias por su preferencia!"
                )
                ped['url_whatsapp_pedido'] = f"https://wa.me/{telefono}?text={msg}"
            else:
                ped['url_whatsapp_pedido'] = None
            pedidos.append(ped)
    except Exception as e:
        print(f"ERROR en /pedidos: {e}")
        pedidos = []
    finally:
        conn.close()
    return render_template('pedidos.html', pedidos=pedidos, estados=lista_estados)

@app.route('/ventas/nueva', methods=['GET'])
@login_required
@escritura_required
def venta_nueva_form():
    clientes  = []
    productos = []
    try:
        # Consulta 1 (Auth): clientes activos
        conn_a   = get_connection_auth()
        cursor_a = conn_a.cursor(dictionary=True)
        cursor_a.execute("""
            SELECT id_cliente, CONCAT(nombre, ' ', COALESCE(apellido,'')) AS nombre, telefono
            FROM cliente WHERE activo = TRUE ORDER BY nombre
        """)
        clientes = cursor_a.fetchall()
        conn_a.close()
        # Consulta 2 (Tienda): productos con stock
        conn   = get_connection_tienda()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id_producto, nombre, precio, stock
            FROM producto WHERE activo = TRUE AND stock > 0 ORDER BY nombre
        """)
        productos = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"ERROR en /ventas/nueva GET: {e}")
    # Token de un solo uso: cada formulario solo puede cobrar UNA vez.
    # Evita dobles cobros por doble clic / re-envío del mismo POST.
    if not session.get('venta_token'):
        session['venta_token'] = secrets.token_hex(16)
    return render_template('venta_form.html', clientes=clientes, productos=productos,
                           venta_token=session.get('venta_token'))


@app.route('/ventas/nueva', methods=['POST'])
@login_required
@escritura_required
def venta_nueva_guardar():
    # Protección anti doble cobro: el token se genera en cada GET y se consume
    # con la primera venta. Si se re-envía el mismo formulario (doble clic,
    # F5/back + submit) el token ya no coincide y se rechaza el duplicado.
    venta_token = request.form.get('venta_token')
    if session.get('venta_token') and venta_token != session['venta_token']:
        flash('Esta venta ya fue registrada: no se permite un doble cobro.', 'warning')
        return redirect(url_for('pedidos'))
    # Consumir el ticket: esta página de cobro no puede volver a procesarse.
    session['venta_token'] = secrets.token_hex(16)

    id_cliente   = request.form.get('id_cliente') or None
    tipo_venta   = request.form.get('tipo_venta', 'local')
    metodo_pago  = request.form.get('metodo_pago', 'efectivo')
    metodo_db    = 'yape_plin' if metodo_pago == 'yape' else (
                   'tarjeta'   if metodo_pago == 'tarjeta' else 'efectivo')
    ids_producto = request.form.getlist('id_producto[]')
    cantidades   = request.form.getlist('cantidad[]')

    if not ids_producto:
        flash('Debes agregar al menos un producto.', 'danger')
        return redirect(url_for('venta_nueva_form'))

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    caja_activa = None
    try:
        # Las ventas LOCALES (presenciales) requieren una caja abierta;
        # las ventas online no dependen de la caja.
        if tipo_venta == 'local':
            cursor.execute("SELECT * FROM caja WHERE estado = 'abierta'")
            caja_activa = cursor.fetchone()
            if not caja_activa:
                flash('No puedes registrar una venta local sin una caja abierta. Abre caja primero en /caja.', 'danger')
                return redirect(url_for('caja'))

        # Regla de negocio: una venta LOCAL (caja/POS) se considera ENTREGADA
        # de inmediato al confirmarse el pago: el cliente recibe el producto en
        # el mostrador y NO pasa por pendiente → preparación → despacho.
        # Los pedidos ONLINE conservan su flujo (pendiente → ... → entregado)
        # y NUNCA se auto-marcan como entregados aquí.
        estado_nombre = 'entregado' if tipo_venta == 'local' else 'pendiente'

        # Crear la venta
        cursor.execute("""
            INSERT INTO venta (id_tipo_venta, id_cliente, id_usuario_vendedor, id_estado_venta)
            VALUES ((SELECT id_tipo_venta FROM tipo_venta WHERE nombre = %s), %s, %s,
                    (SELECT id_estado_venta FROM estado_venta WHERE nombre = %s))
            RETURNING id_venta
        """, (tipo_venta, id_cliente, session.get('usuario_id'), estado_nombre))
        id_venta = cursor.fetchone()['id_venta']

        # Insertar cada ítem y descontar stock
        for id_prod, cant in zip(ids_producto, cantidades):
            try:
                cant = int(cant) if cant else 1
            except (TypeError, ValueError):
                cant = 1
            if cant <= 0:
                raise ValueError("Las cantidades deben ser mayores a cero.")
            cursor.execute("SELECT precio, stock, nombre FROM producto WHERE id_producto = %s", (id_prod,))
            prod = cursor.fetchone()
            if not prod:
                continue
            # No permitir vender más stock del disponible (evita stock negativo)
            if cant > (prod['stock'] or 0):
                raise ValueError(
                    f"Stock insuficiente de \"{prod['nombre']}\" "
                    f"(disponible: {prod['stock']} unidades). Venta no registrada."
                )
            cursor.execute("""
                INSERT INTO detalle_venta (id_venta, id_producto, cantidad, precio_unitario)
                VALUES (%s, %s, %s, %s)
            """, (id_venta, id_prod, cant, prod['precio']))
            cursor.execute("""
                UPDATE producto SET stock = GREATEST(stock - %s, 0) WHERE id_producto = %s
            """, (cant, id_prod))

        # Registrar el pago y el ingreso en caja para ventas locales
        if tipo_venta == 'local' and caja_activa:
            cursor.execute("""
                INSERT INTO pago (id_venta, id_tipo_pago, id_caja, estado)
                VALUES (%s, (SELECT id_tipo_pago FROM tipo_pago WHERE nombre = %s), %s, 'confirmado')
            """, (id_venta, metodo_db, caja_activa['id_caja']))
            cursor.execute("""
                INSERT INTO movimiento_caja (id_caja, tipo, monto, concepto, id_usuario)
                SELECT %s, 'ingreso',
                       COALESCE(SUM(cantidad * precio_unitario), 0), %s, %s
                FROM detalle_venta WHERE id_venta = %s
            """, (caja_activa['id_caja'], f'Venta local #{id_venta}',
                  session.get('usuario_id'), id_venta))

        # ── Comprobante interno (boleta B001 / factura F001) ──
        # Sin integración SUNAT real todavía: estado_sunat = 'no_aplica'.
        # Replica el patrón de numeración del flujo online (prefijo B/F + 6
        # dígitos de la venta + 4 dígitos aleatorios). Si ese bloque opcional
        # falla, la venta se completa igual (savepoint, igual que el checkout).
        comp_tipo = request.form.get('comp_tipo', '').strip().lower()
        if comp_tipo in ('boleta', 'factura') and (id_cliente or request.form.get('comp_doc')):
            import random, string
            serie   = 'B001' if comp_tipo == 'boleta' else 'F001'
            prefijo = 'B' if comp_tipo == 'boleta' else 'F'
            numero  = f"{prefijo}{str(id_venta).zfill(6)}-" \
                      f"{''.join(random.choices(string.digits, k=4))}"
            doc_cliente = (request.form.get('comp_doc') or '').strip()
            if id_cliente and not doc_cliente:
                # Cliente elegido del dropdown: su documento vive en la BD Auth
                conn_a = None
                try:
                    conn_a   = get_connection_auth()
                    cursor_a = conn_a.cursor(dictionary=True)
                    cursor_a.execute(
                        "SELECT nro_documento FROM cliente WHERE id_cliente = %s",
                        (id_cliente,))
                    fila = cursor_a.fetchone()
                    doc_cliente = (fila or {}).get('nro_documento') or ''
                except Exception:
                    doc_cliente = ''
                finally:
                    if conn_a is not None:
                        try:
                            conn_a.close()
                        except Exception:
                            pass
            try:
                cursor.execute("SAVEPOINT sp_comprobante")
                cursor.execute("""
                    INSERT INTO comprobante (id_venta, tipo, tipo_boleta, ruc_cliente,
                                             numero, serie, estado_sunat, enviado_correo)
                    VALUES (%s, %s, %s, NULLIF(%s, ''), %s, %s, 'no_aplica', 0)
                """, (id_venta, comp_tipo,
                      'simple' if comp_tipo == 'boleta' else None,
                      doc_cliente, numero, serie))
            except Exception as e:
                app.logger.warning(
                    "No se pudo generar el comprobante interno de la venta local %s: %s",
                    id_venta, e)
                cursor.execute("ROLLBACK TO SAVEPOINT sp_comprobante")

        conn.commit()
        flash(f'Venta #{id_venta} registrada correctamente.', 'success')
        return redirect(url_for('pedidos'))

    except Exception as e:
        print(f"ERROR al guardar venta: {e}")
        flash(str(e) or 'Error al registrar la venta. Intenta de nuevo.', 'danger')
        return redirect(url_for('venta_nueva_form'))
    finally:
        conn.close()


# ── Caja (apertura / cierre / arqueo) ────────────────────────────────────────
# UMBRAL_DIFERENCIA_CAJA: |declarado - sistema| mayor a esto se marca como advertencia
UMBRAL_DIFERENCIA_CAJA = 20.0


@app.route('/caja')
@login_required
@escritura_required
def caja():
    """Panel de caja: estado actual, movimientos del turno, resumen por método
    de pago e historial de cierres.

    REGLA ECONÓMICA DE LA CAJA FÍSICA:
      EFECTIVO esperado = fondo inicial + ventas locales pagadas en EFECTIVO − egresos
    Yape/Plin y Tarjeta son pagos DIGITALES: se muestran aparte como resumen y
    NO forman parte del dinero físico de la caja (no suben el esperado).
    """
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    caja_abierta = None
    movimientos  = []
    historial = []
    resumen   = {}
    digitales_por_caja = {}
    uids = set()
    try:
        cursor.execute("SELECT * FROM caja WHERE estado = 'abierta' LIMIT 1")
        caja_abierta = cursor.fetchone()
        if caja_abierta:
            cursor.execute("""
                SELECT * FROM movimiento_caja
                WHERE id_caja = %s ORDER BY fecha DESC
            """, (caja_abierta['id_caja'],))
            movimientos = cursor.fetchall()
            uids.add(caja_abierta['id_usuario_apertura'])
            uids.update(m['id_usuario'] for m in movimientos if m['id_usuario'])

        cursor.execute("""
            SELECT * FROM caja ORDER BY fecha_apertura DESC LIMIT 10
        """)
        historial = cursor.fetchall()
        for h in historial:
            if h['id_usuario_apertura']: uids.add(h['id_usuario_apertura'])
            if h['id_usuario_cierre']:   uids.add(h['id_usuario_cierre'])

        # ── Resumen económico por caja (ventas LOCALES con pago confirmado) ──
        caja_ids = ([caja_abierta['id_caja']] if caja_abierta else []) \
                 + [h['id_caja'] for h in historial]
        if caja_ids:
            cursor.execute("""
                SELECT p.id_caja, tp.nombre AS metodo,
                       COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
                FROM pago p
                JOIN venta v       ON v.id_venta = p.id_venta
                JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
                JOIN tipo_pago tp  ON p.id_tipo_pago = tp.id_tipo_pago
                LEFT JOIN detalle_venta d ON d.id_venta = v.id_venta
                WHERE tv.nombre = 'local' AND p.estado = 'confirmado'
                  AND p.id_caja = ANY(%s)
                GROUP BY p.id_caja, tp.nombre
            """, (caja_ids,))
            ventas_por_caja = {}
            for r in cursor.fetchall():
                ventas_por_caja.setdefault(r['id_caja'], {})[r['metodo']] = float(r['total'] or 0)

            cursor.execute("""
                SELECT id_caja, COALESCE(SUM(monto), 0) AS total
                FROM movimiento_caja
                WHERE id_caja = ANY(%s) AND tipo = 'egreso'
                GROUP BY id_caja
            """, (caja_ids,))
            egresos_por_caja = {r['id_caja']: float(r['total'] or 0)
                                for r in cursor.fetchall()}

            for row in ([caja_abierta] if caja_abierta else []) + historial:
                met    = ventas_por_caja.get(row['id_caja'], {})
                fondo  = float(row.get('monto_apertura') or 0)
                ven_ef = met.get('efectivo', 0.0)
                yape   = met.get('yape_plin', 0.0)
                tar    = met.get('tarjeta', 0.0)
                egres  = egresos_por_caja.get(row['id_caja'], 0.0)
                esperado = fondo + ven_ef - egres
                digitales_por_caja[row['id_caja']] = {
                    'yape': yape,
                    'tarjeta': tar,
                    'total_digital': yape + tar,
                    'ventas_efectivo': ven_ef,
                }
                if caja_abierta and row['id_caja'] == caja_abierta['id_caja']:
                    resumen = {
                        'fondo':           fondo,
                        'ventas_efectivo': ven_ef,
                        'yape':            yape,
                        'tarjeta':         tar,
                        'total_ventas':    ven_ef + yape + tar,
                        'egresos':         egres,
                        'esperado':        esperado,
                    }
    except Exception as e:
        app.logger.exception("Error en /caja: %s", e)
    finally:
        conn.close()

    # Nombres de usuarios desde la BD Auth
    nombres = {}
    if uids:
        try:
            conn_a = get_connection_auth()
            cur_a  = conn_a.cursor(dictionary=True)
            cur_a.execute("SELECT id_usuario, nombres FROM usuario WHERE id_usuario = ANY(%s)",
                          (list(uids),))
            nombres = {u['id_usuario']: u['nombres'] for u in cur_a.fetchall()}
            conn_a.close()
        except Exception:
            pass

    return render_template('caja.html',
                           caja=caja_abierta,
                           movimientos=movimientos,
                           resumen=resumen,
                           digitales=digitales_por_caja,
                           historial=historial,
                           nombres=nombres,
                           umbral=UMBRAL_DIFERENCIA_CAJA)


@app.route('/caja/abrir', methods=['POST'])
@login_required
@escritura_required
def caja_abrir():
    """Abre una caja con un monto inicial (solo puede haber UNA abierta)."""
    try:
        monto = float(request.form.get('monto_apertura', '0') or 0)
    except ValueError:
        flash('Monto de apertura inválido.', 'danger')
        return redirect(url_for('caja'))
    if monto < 0:
        flash('El monto de apertura no puede ser negativo.', 'danger')
        return redirect(url_for('caja'))

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id_caja FROM caja WHERE estado = 'abierta' LIMIT 1")
        if cursor.fetchone():
            flash('Ya existe una caja abierta. Ciérrala antes de abrir otra.', 'danger')
            return redirect(url_for('caja'))

        cursor.execute("""
            INSERT INTO caja (id_usuario_apertura, monto_apertura, estado)
            VALUES (%s, %s, 'abierta')
            RETURNING id_caja
        """, (session.get('usuario_id'), monto))
        id_caja = cursor.fetchone()['id_caja']
        # Movimiento inicial de apertura por el monto de fondo
        # (CHECK de la tabla solo admite 'ingreso'/'egreso'; la apertura es un ingreso)
        cursor.execute("""
            INSERT INTO movimiento_caja (id_caja, tipo, monto, concepto, id_usuario)
            VALUES (%s, 'ingreso', %s, 'Apertura de caja (fondo inicial)', %s)
        """, (id_caja, monto, session.get('usuario_id')))
        conn.commit()
        flash(f'Caja #{id_caja} abierta con S/ {monto:.2f}.', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.exception("Error abriendo caja: %s", e)
        # El índice único parcial idx_caja_una_abierta también protege esto
        flash('No se pudo abrir la caja (¿ya existe una abierta?).', 'danger')
    finally:
        conn.close()
    return redirect(url_for('caja'))


@app.route('/caja/egreso', methods=['POST'])
@login_required
@escritura_required
def caja_egreso():
    """Registra un EGRESO (gasto/salida de efectivo) de la caja abierta.
    Descuenta del efectivo esperado del cierre."""
    concepto = request.form.get('concepto', '').strip()
    try:
        monto = float(request.form.get('monto', '0') or 0)
    except ValueError:
        monto = -1
    if not concepto:
        flash('El concepto del egreso es obligatorio.', 'danger')
        return redirect(url_for('caja'))
    if monto <= 0:
        flash('El monto del egreso debe ser mayor que cero.', 'danger')
        return redirect(url_for('caja'))

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id_caja FROM caja WHERE estado = 'abierta' LIMIT 1")
        caja = cursor.fetchone()
        if not caja:
            flash('No hay ninguna caja abierta. Abre la caja para registrar egresos.', 'danger')
            return redirect(url_for('caja'))

        cursor.execute("""
            INSERT INTO movimiento_caja (id_caja, tipo, monto, concepto, id_usuario)
            VALUES (%s, 'egreso', %s, %s, %s)
        """, (caja['id_caja'], monto, concepto, session.get('usuario_id')))
        conn.commit()
        flash(f'Egreso registrado en la caja #{caja["id_caja"]}: {concepto} por S/ {monto:.2f}.', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.exception("Error registrando egreso de caja: %s", e)
        flash('No se pudo registrar el egreso.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('caja'))


@app.route('/caja/cerrar', methods=['POST'])
@login_required
@escritura_required
def caja_cerrar():
    """Cierra la caja abierta: calcula el EFECTIVO esperado
    (fondo + ventas en efectivo − egresos) y registra la diferencia."""
    try:
        declarado = float(request.form.get('monto_declarado', '0') or 0)
    except ValueError:
        flash('Monto declarado inválido.', 'danger')
        return redirect(url_for('caja'))
    observaciones = request.form.get('observaciones', '').strip() or None

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM caja WHERE estado = 'abierta' LIMIT 1")
        caja = cursor.fetchone()
        if not caja:
            flash('No hay ninguna caja abierta para cerrar.', 'danger')
            return redirect(url_for('caja'))

        id_caja = caja['id_caja']
        fondo   = float(caja.get('monto_apertura') or 0)

        # Ventas LOCALES pagadas en EFECTIVO (el único dinero físico que entra)
        cursor.execute("""
            SELECT COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM pago p
            JOIN venta v       ON v.id_venta = p.id_venta
            JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            JOIN tipo_pago tp  ON p.id_tipo_pago = tp.id_tipo_pago
            LEFT JOIN detalle_venta d ON d.id_venta = v.id_venta
            WHERE tv.nombre = 'local' AND p.estado = 'confirmado'
              AND p.id_caja = %s AND tp.nombre = 'efectivo'
        """, (id_caja,))
        ventas_efectivo = float(cursor.fetchone()['total'] or 0)

        # Egresos del turno (descuentan del efectivo esperado)
        cursor.execute("""
            SELECT COALESCE(SUM(monto), 0) AS total
            FROM movimiento_caja WHERE id_caja = %s AND tipo = 'egreso'
        """, (id_caja,))
        egresos = float(cursor.fetchone()['total'] or 0)

        esperado = fondo + ventas_efectivo - egresos
        diferencia = declarado - esperado

        # Pagos DIGITALES del turno (resumen informativo; NO afectan el efectivo)
        cursor.execute("""
            SELECT tp.nombre AS metodo, COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM pago p
            JOIN venta v       ON v.id_venta = p.id_venta
            JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            JOIN tipo_pago tp  ON p.id_tipo_pago = tp.id_tipo_pago
            LEFT JOIN detalle_venta d ON d.id_venta = v.id_venta
            WHERE tv.nombre = 'local' AND p.estado = 'confirmado'
              AND p.id_caja = %s AND tp.nombre IN ('yape_plin', 'tarjeta')
            GROUP BY tp.nombre
        """, (id_caja,))
        digital = {r['metodo']: float(r['total'] or 0) for r in cursor.fetchall()}
        yape, tarjeta = digital.get('yape_plin', 0.0), digital.get('tarjeta', 0.0)

        # El cierre se refleja solo en la fila de caja (sin movimiento_caja 'cierre');
        # los montos quedan en la propia caja y sus movimientos del turno.
        cursor.execute("""
            UPDATE caja
            SET estado = 'cerrada',
                id_usuario_cierre = %s,
                fecha_cierre = NOW(),
                monto_cierre_sistema = %s,
                monto_cierre_declarado = %s,
                diferencia = %s,
                observaciones = %s
            WHERE id_caja = %s
        """, (session.get('usuario_id'), esperado, declarado, diferencia,
              observaciones, id_caja))
        conn.commit()

        mensaje = (
            f'Caja #{id_caja} cerrada. EFECTIVO: fondo S/ {fondo:.2f} + ventas '
            f'efectivo S/ {ventas_efectivo:.2f} − egresos S/ {egresos:.2f} '
            f'= esperado S/ {esperado:.2f} | '
            f'PAGOS DIGITALES: Yape/Plin S/ {yape:.2f}, Tarjeta S/ {tarjeta:.2f} | '
            f'Diferencia: S/ {diferencia:+.2f}.'
        )
        if abs(diferencia) > UMBRAL_DIFERENCIA_CAJA:
            flash(mensaje + f' ⚠ La diferencia supera el umbral (S/ {UMBRAL_DIFERENCIA_CAJA:.0f}).', 'warning')
        else:
            flash(mensaje, 'success')
    except Exception as e:
        conn.rollback()
        app.logger.exception("Error cerrando caja: %s", e)
        flash('No se pudo cerrar la caja.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('caja'))


@app.route('/pedidos/detalle/<int:id>')
@login_required
@escritura_required
def pedido_detalle(id):
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    pedido     = None
    items      = []
    comprobante = None
    try:
        # Consulta 1 (Tienda): venta + total
        cursor.execute("""
            SELECT
                v.*,
                ev.nombre AS estado,
                tv.nombre AS tipo_venta,
                COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            LEFT JOIN tipo_venta tv ON v.id_tipo_venta = tv.id_tipo_venta
            LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
            WHERE v.id_venta = %s
            GROUP BY v.id_venta, ev.nombre, tv.nombre
        """, (id,))
        pedido = cursor.fetchone()
        if pedido:
            pedido['id_venta'] = pedido.get('id_venta', id)
            # Consulta 2 (Auth): cliente y vendedor responsable
            conn_a   = get_connection_auth()
            cursor_a = conn_a.cursor(dictionary=True)
            if pedido.get('id_cliente'):
                cursor_a.execute(
                    "SELECT nombre, apellido, telefono, nro_documento, direccion FROM cliente WHERE id_cliente = %s",
                    (pedido['id_cliente'],))
                cli = cursor_a.fetchone() or {}
                pedido['cliente_nombre']    = (f"{cli.get('nombre') or ''} {cli.get('apellido') or ''}").strip()
                pedido['cliente_telefono']  = cli.get('telefono')
                pedido['cliente_documento'] = (cli.get('nro_documento') or '').strip() or None
                pedido['cliente_direccion'] = (cli.get('direccion') or '').strip() or None
            if pedido.get('id_usuario_vendedor'):
                cursor_a.execute(
                    "SELECT nombres FROM usuario WHERE id_usuario = %s",
                    (pedido['id_usuario_vendedor'],))
                usr = cursor_a.fetchone()
                pedido['responsable'] = usr['nombres'] if usr else None
            conn_a.close()
        cursor.execute("""
            SELECT d.*, p.nombre AS producto_nombre
            FROM detalle_venta d
            LEFT JOIN producto p ON d.id_producto = p.id_producto
            WHERE d.id_venta = %s
        """, (id,))
        items = cursor.fetchall()
        try:
            cursor.execute("SELECT * FROM comprobante WHERE id_venta = %s LIMIT 1", (id,))
            comprobante = cursor.fetchone()
        except Exception:
            comprobante = None
    except Exception as e:
        print(f"ERROR pedido_detalle: {e}")
    finally:
        conn.close()
    # Fases válidas leídas de la BD (misma fuente que el panel admin y el
    # cliente), de modo que el timeline siempre muestre nombres consistentes.
    PASOS = []
    try:
        conn_f   = get_connection_tienda()
        cursor_f = conn_f.cursor(dictionary=True)
        cursor_f.execute("SELECT nombre FROM estado_venta WHERE activo = TRUE ORDER BY orden")
        PASOS = [r['nombre'] for r in cursor_f.fetchall()]
        conn_f.close()
    except Exception:
        PASOS = []
    PASOS = [f for f in PASOS if f != 'cancelado']
    if not PASOS:
        PASOS = ['pendiente', 'confirmado', 'preparando', 'listo', 'entregado']
    # Calcular idx_actual en Python para evitar el error .index() en Jinja2
    estado_actual = (pedido.get('estado') or 'pendiente') if pedido else 'pendiente'
    idx_actual = PASOS.index(estado_actual) if estado_actual in PASOS else 0
    return render_template('pedido_detalle.html', pedido=pedido, items=items,
                           comprobante=comprobante, id=id,
                           idx_actual=idx_actual, fases_orden=PASOS,
                           estados=PASOS)

def _reportes_resumen(cursor):
    """Tarjetas de resumen (ventas hoy / stock total / alertas) usadas por /reportes
    y por /reportes/generar."""
    resumen = {}
    # Ventas hoy (si existe tabla venta con campo fecha)
    try:
        cursor.execute("""
            SELECT COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS ventas_hoy
            FROM venta v
            JOIN detalle_venta d ON v.id_venta = d.id_venta
            WHERE DATE(v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima') = CURRENT_DATE
        """)
        row = cursor.fetchone()
        resumen['ventas_hoy'] = float(row['ventas_hoy'] or 0)
    except Exception:
        resumen['ventas_hoy'] = 0

    # Stock total (suma de stock de productos)
    try:
        cursor.execute("SELECT COALESCE(SUM(stock),0) AS stock_total FROM producto")
        row = cursor.fetchone()
        resumen['stock_total'] = int(row['stock_total'] or 0)
    except Exception:
        resumen['stock_total'] = 0

    # Alertas pendientes
    try:
        cursor.execute("SELECT COUNT(*) AS cnt FROM alerta WHERE resuelta = FALSE")
        row = cursor.fetchone()
        resumen['alertas'] = int(row['cnt'] or 0)
    except Exception:
        resumen['alertas'] = 0

    return resumen


@app.route('/reportes')
@login_required
@escritura_required
def reportes():
    conn = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    reportes_data = None

    try:
        resumen = _reportes_resumen(cursor)

        # Dashboard inventario: entradas/salidas últimos 30 días (cantidad y valor)
        try:
            cursor.execute("""
                SELECT tipo,
                       COALESCE(SUM(cantidad),0) AS total_cantidad,
                       COALESCE(SUM(precio_unitario * cantidad),0) AS total_valor
                FROM inventario_movimiento
                WHERE fecha >= NOW() - INTERVAL '30 days'
                GROUP BY tipo
            """)
            agg = cursor.fetchall()
            # Construir filas para la tabla de reportes
            headers = ['Tipo', 'Cantidad (30d)', 'Valor (30d)']
            rows = []
            entradas = salidas = 0
            entradas_val = salidas_val = 0.0
            for a in agg:
                tipo = a.get('tipo') or '–'
                qty  = int(a.get('total_cantidad') or 0)
                val  = float(a.get('total_valor') or 0.0)
                rows.append([tipo, qty, f"{val:.2f}"])
                if tipo == 'entrada':
                    entradas += qty; entradas_val += val
                elif tipo == 'salida':
                    salidas += qty; salidas_val += val
            reportes_data = {
                'headers': headers,
                'rows': rows,
                'entradas_30d': entradas,
                'salidas_30d': salidas,
                'entradas_val_30d': entradas_val,
                'salidas_val_30d': salidas_val
            }
        except Exception:
            reportes_data = None

    finally:
        conn.close()

    return render_template('reportes.html', resumen=resumen, reportes=reportes_data)


@app.route('/reportes/generar')
@login_required
@escritura_required
def reportes_generar():
    tipo  = (request.args.get('tipo') or 'ventas').strip()
    desde = (request.args.get('desde') or '').strip() or None
    hasta = (request.args.get('hasta') or '').strip() or None

    conn = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    resumen = _reportes_resumen(cursor)
    reportes_data = None

    try:
        cond = []
        params = []
        if desde:
            cond.append("v.fecha >= %s")
            params.append(desde + 'T00:00:00')
        if hasta:
            cond.append("v.fecha < %s::timestamptz + INTERVAL '1 day'")
            params.append(hasta + 'T00:00:00')
        where = ("WHERE " + " AND ".join(cond)) if cond else ""

        if tipo == 'ventas':
            cursor.execute(f"""
                SELECT v.id_venta,
                       COALESCE(c.nombre, '—') AS cliente,
                       v.fecha,
                       COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
                FROM venta v
                LEFT JOIN cliente c ON v.id_cliente = c.id_cliente
                LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
                {where}
                GROUP BY v.id_venta, c.nombre, v.fecha
                ORDER BY v.fecha DESC
            """, params)
            filas = cursor.fetchall()
            reportes_data = {
                'headers': ['N°', 'Cliente', 'Fecha', 'Total (S/)'],
                'rows': [[r['id_venta'], r['cliente'] or '—', r['fecha'],
                          f"{float(r['total'] or 0):.2f}"] for r in filas],
            }
        elif tipo == 'pedidos':
            cursor.execute(f"""
                SELECT v.id_venta,
                       COALESCE(c.nombre, '—') AS cliente,
                       COALESCE(e.nombre, '—') AS estado,
                       v.fecha,
                       COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
                FROM venta v
                LEFT JOIN cliente c ON v.id_cliente = c.id_cliente
                LEFT JOIN estado_venta e ON v.id_estado_venta = e.id_estado_venta
                LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
                {where}
                GROUP BY v.id_venta, c.nombre, e.nombre, v.fecha
                ORDER BY v.fecha DESC
            """, params)
            filas = cursor.fetchall()
            reportes_data = {
                'headers': ['N°', 'Cliente', 'Estado', 'Fecha', 'Total (S/)'],
                'rows': [[r['id_venta'], r['cliente'] or '—', r['estado'], r['fecha'],
                          f"{float(r['total'] or 0):.2f}"] for r in filas],
            }
        elif tipo == 'productos':
            cursor.execute("""
                SELECT id_producto, nombre, precio, stock
                FROM producto ORDER BY nombre
            """)
            filas = cursor.fetchall()
            reportes_data = {
                'headers': ['ID', 'Producto', 'Precio (S/)', 'Stock'],
                'rows': [[r['id_producto'], r['nombre'],
                          f"{float(r['precio'] or 0):.2f}", r['stock']] for r in filas],
            }
        elif tipo == 'inventario':
            ini = (desde or 'now() - interval \'30 days\'')
            params_inv = []
            if desde:
                ini = '%s'
                params_inv.append(desde + 'T00:00:00')
            sql = f"""
                SELECT id_movimiento, id_producto, tipo, cantidad,
                       precio_unitario, fecha
                FROM inventario_movimiento
                WHERE fecha >= {ini}
                ORDER BY fecha DESC
                LIMIT 500
            """
            cursor.execute(sql, params_inv)
            filas = cursor.fetchall()
            reportes_data = {
                'headers': ['ID', 'Producto', 'Tipo', 'Cantidad', 'P.U. (S/)', 'Fecha'],
                'rows': [[r['id_movimiento'], r['id_producto'], r['tipo'], r['cantidad'],
                          f"{float(r['precio_unitario'] or 0):.2f}", r['fecha']] for r in filas],
            }
        else:
            reportes_data = {'headers': ['Aviso'], 'rows': [['Tipo de reporte no válido.']]}
    except Exception:
        app.logger.exception("Error al generar reporte tipo=%s", tipo)
        reportes_data = None
    finally:
        conn.close()

    return render_template('reportes.html', resumen=resumen, reportes=reportes_data)


# ── Alertas ─────────────────────────────────────────────────
@app.route('/alertas')
@login_required
@escritura_required
def alertas():
    conn = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    alertas = []
    bajo_stock = []
    try:
        cursor.execute("""
            SELECT id_producto, nombre, stock, precio
            FROM producto WHERE stock < 15 ORDER BY stock ASC
        """)
        bajo_stock = cursor.fetchall()
        # Sincronizar: crear alerta en BD para cada producto con stock < 15 si no existe ya una sin resolver
        # (esquema real: tabla alerta con id_producto + id_tipo_alerta; 1 = stock_bajo)
        for p in bajo_stock:
            cursor.execute("""
                SELECT id_alerta FROM alerta
                WHERE id_tipo_alerta = 1 AND id_producto = %s AND resuelta = FALSE
                LIMIT 1
            """, (p['id_producto'],))
            if not cursor.fetchone():
                prioridad = 'alta' if p['stock'] < 5 else 'media'
                cursor.execute("""
                    INSERT INTO alerta (id_tipo_alerta, id_producto, descripcion, prioridad, fecha)
                    VALUES (1, %s, %s, %s, NOW())
                """, (
                    p['id_producto'],
                    f"Stock insuficiente: {p['nombre']} tiene {p['stock']} unidades (mínimo sugerido: 15)",
                    prioridad
                ))
        conn.commit()
        cursor.execute("SELECT * FROM alerta ORDER BY fecha DESC LIMIT 200")
        alertas = cursor.fetchall()
    except Exception:
        alertas = []
    finally:
        conn.close()
    return render_template('alertas.html', alertas=alertas, bajo_stock=bajo_stock)


@app.route('/alertas/resolver/<int:id>', methods=['POST'])
@login_required
@escritura_required
def alertas_resolver(id):
    conn = get_connection_tienda()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE alerta SET resuelta = TRUE WHERE id_alerta = %s", (id,))
        conn.commit()
        flash("Alerta marcada como resuelta.", "success")
    except Exception as e:
        conn.rollback()
        flash("Error al resolver alerta.", "danger")
        app.logger.exception("Error resolviendo alerta %s: %s", id, e)
    finally:
        conn.close()
    return redirect(url_for('alertas'))

# ── Carrito cliente ────────────────────────────────────────────
@app.route('/carrito')
@login_required
def carrito():
    if session.get('rol') != 'cliente':
        return redirect(url_for('productos'))
    return render_template('carrito.html')


@app.route('/carrito/agregar', methods=['POST'])
@login_required
def carrito_agregar():
    if session.get('rol') != 'cliente':
        return {'ok': False, 'error': 'Solo clientes pueden agregar productos al carrito.'}, 403
    data        = request.get_json()
    id_producto = int(data.get('id_producto', 0))
    cantidad    = int(data.get('cantidad', 1))
    carrito     = session.get('carrito', {})
    key         = str(id_producto)
    if key in carrito:
        carrito[key]['cantidad'] += cantidad
    else:
        conn   = get_connection_tienda()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT nombre, precio FROM producto WHERE id_producto=%s", (id_producto,))
        prod = cursor.fetchone()
        conn.close()
        if prod:
            carrito[key] = {
                'id_producto': id_producto,
                'nombre':      prod['nombre'],
                'precio':      float(prod['precio']),
                'cantidad':    cantidad
            }
    session['carrito'] = carrito
    return {'ok': True, 'items': len(carrito)}


@app.route('/procesar_pago', methods=['POST'])
@login_required
def procesar_pago():
    # Soporta tanto form POST clásico (pago.html: campo "metodo") como fetch JSON
    if session.get('rol') != 'cliente':
        flash("Solo clientes pueden procesar pagos.", "warning")
        return redirect(url_for('productos'))

    data = request.get_json(silent=True) or request.form.to_dict()

    # 1) Ítems: del body JSON si vienen, si no de la sesión (ultimo_pedido o carrito)
    items = data.get('items')
    if not items:
        items = session.get('ultimo_pedido') or []
    if not items:
        carrito = session.get('carrito', {})
        items = [{
            'id_producto': v.get('id_producto') or v.get('id'),
            'cantidad':    v.get('cantidad'),
            'precio':      v.get('precio')
        } for v in carrito.values()]
    if not items:
        flash("No hay items en el carrito para procesar.", "warning")
        return redirect(url_for('catalogo_cliente'))

    # 2) Parámetros del formulario (pago.html) o del fetch JSON
    metodo_pago      = data.get('metodo_pago') or data.get('metodo') or 'efectivo'
    tipo_comprobante = data.get('tipo_comprobante') or 'boleta_simple'
    ruc              = (data.get('ruc') or '').strip() or None
    num_operacion    = (data.get('num_operacion') or '').strip() or None

    resp = _confirmar_carrito(
        items=items,
        metodo_pago=metodo_pago,
        tipo_comprobante=tipo_comprobante,
        ruc=ruc,
        num_operacion=num_operacion,
    )
    if isinstance(resp, dict) and resp.get('ok') and resp.get('id_pedido'):
        flash("Tu pago fue registrado. El pedido quedó en estado pendiente.", "success")
        return redirect(url_for('pedido_aceptado', id=resp['id_pedido']))
    flash(resp.get('error') or 'No se pudo procesar el pago.', "danger")
    return redirect(url_for('catalogo_cliente'))


# ── Cambiar clave ─────────────────────────────────────────────
@app.route('/cambiar_clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    es_cliente = session.get('rol') == 'cliente'
    if request.method == 'POST':
        nueva     = request.form['nueva']
        confirmar = request.form['confirmar']
        if nueva != confirmar:
            return render_template('cambiar_clave.html', error='Las contraseñas no coinciden')
        nueva_hash = bcrypt.generate_password_hash(nueva).decode('utf-8')
        conn   = get_connection_auth()
        cursor = conn.cursor()
        if es_cliente:
            cursor.execute("UPDATE cliente SET contrasena = %s WHERE id_cliente = %s",
                           (nueva_hash, session['usuario_id']))
        else:
            cursor.execute("UPDATE usuario SET contrasena = %s WHERE id_usuario = %s",
                           (nueva_hash, session['usuario_id']))
        conn.commit()
        conn.close()
        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('catalogo_cliente') if es_cliente else url_for('productos'))
    return render_template('cambiar_clave.html')



# ═══════════════════════════════════════════════════════════════════
# NUEVAS RUTAS – Registro cliente, pedido aceptado, fases, comprobante
# ═══════════════════════════════════════════════════════════════════

def _correo_html_codigo(nombre, codigo, motivo):
    """HTML estándar (marca CLEOFERR) para correos que contienen un código."""
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;border:1px solid #ddd;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#1A1A2E,#4682B4);padding:24px;text-align:center">
        <h2 style="color:white;margin:0;font-size:1.4rem">🔧 Ferretería Inversiones CLEOFERR</h2>
      </div>
      <div style="padding:28px">
        <p style="color:#333;font-size:1rem">Hola <strong>{nombre}</strong>,</p>
        <p style="color:#555">{motivo}</p>
        <div style="text-align:center;margin:24px 0">
          <span style="font-size:2.8rem;font-weight:900;letter-spacing:12px;color:#4682B4;
                       background:#f0f6ff;padding:16px 24px;border-radius:12px;
                       display:inline-block;border:2px dashed #4682B4">{codigo}</span>
        </div>
        <p style="color:#888;font-size:0.85rem;text-align:center">
          ⏱ Este código es válido por <strong>10 minutos</strong>.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
        <p style="color:#aaa;font-size:0.78rem;text-align:center">
          Si no solicitaste este código, puedes ignorar este mensaje.
        </p>
      </div>
    </div>
    """


@app.route('/registro_cliente', methods=['POST'])
def registro_cliente():
    """Registro de nuevo cliente: crea la cuenta con activo=FALSE y guarda el
    hash del código OTP en verificacion_cuenta (BD Auth)."""
    import random

    nombre     = request.form.get('nombre', '').strip()
    apellido   = request.form.get('apellido', '').strip()
    correo     = request.form.get('correo', '').strip()
    telefono   = request.form.get('telefono', '').strip()
    direccion  = request.form.get('direccion', '').strip()
    contrasena = request.form.get('contrasena', '')
    confirmar  = request.form.get('confirmar', '')

    if not nombre or not correo or not contrasena:
        return render_template('login_cliente.html',
                               error='Nombre, correo y contraseña son obligatorios.',
                               registro_activo=True)
    if len(direccion) < 5:
        return render_template('login_cliente.html',
                               error='La dirección es obligatoria para registrarte (mínimo 5 caracteres).',
                               registro_activo=True)
    if contrasena != confirmar:
        return render_template('login_cliente.html',
                               error='Las contraseñas no coinciden.',
                               registro_activo=True)

    codigo      = str(random.randint(100000, 999999))
    hash_pw     = bcrypt.generate_password_hash(contrasena).decode('utf-8')
    codigo_hash = bcrypt.generate_password_hash(codigo).decode('utf-8')

    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    try:
        # ¿Ya existe el correo?
        cursor.execute("SELECT id_cliente, activo FROM cliente WHERE email = %s", (correo,))
        existente = cursor.fetchone()
        if existente and existente['activo']:
            return render_template('login_cliente.html',
                                   error='Este correo ya está registrado. Inicia sesión.',
                                   registro_activo=True)

        if existente:
            # Registro pendiente de verificación: actualizar datos del formulario
            id_cliente = existente['id_cliente']
            cursor.execute("""
                UPDATE cliente SET nombre=%s, apellido=%s, telefono=%s, contrasena=%s, direccion=%s
                WHERE id_cliente=%s
            """, (nombre, apellido or '', telefono or None, hash_pw, direccion, id_cliente))
        else:
            # id_tipo_documento=1 (DNI) y nro_documento vacío ('') por defecto;
            # el formulario web no pide documento todavía
            cursor.execute("""
                INSERT INTO cliente (nombre, apellido, email, telefono, contrasena,
                                     id_tipo_documento, nro_documento, direccion, activo)
                VALUES (%s, %s, %s, %s, %s, 1, '', %s, FALSE)
                RETURNING id_cliente
            """, (nombre, apellido or '', correo, telefono or None, hash_pw, direccion))
            id_cliente = cursor.fetchone()['id_cliente']

        # Invalidar códigos anteriores de este cliente y guardar el nuevo (solo el hash)
        cursor.execute("""
            UPDATE verificacion_cuenta SET usado = TRUE
            WHERE id_cliente = %s AND usado = FALSE
        """, (id_cliente,))
        cursor.execute("""
            INSERT INTO verificacion_cuenta (id_cliente, codigo_hash, creado_en, expira_en, usado)
            VALUES (%s, %s, NOW(), NOW() + INTERVAL '10 minutes', FALSE)
        """, (id_cliente, codigo_hash))
        conn.commit()
    except Exception as e:
        conn.rollback()
        # ── Log detallado real (no engañar al usuario ni al debug) ──
        import traceback
        app.logger.error(
            "Error en registro_cliente (correo=%s): %s\n%s",
            correo, e, traceback.format_exc()
        )
        print(f"ERROR registro_cliente [{correo}]: {e}")
        # Validación de datos / conflictos → mensaje específico
        if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
            msg = 'Este correo o teléfono ya está registrado. Intenta iniciar sesión.'
        elif 'not null' in str(e).lower():
            msg = 'Faltan datos obligatorios para crear la cuenta. Completa todos los campos.'
        elif 'verificacion_cuenta' in str(e).lower() or 'relation' in str(e).lower():
            msg = 'Error interno: la tabla de verificación no existe. Contacta al administrador.'
        else:
            msg = 'No se pudo iniciar el registro (error interno). Contacta al administrador.'
        return render_template('login_cliente.html',
                               error=msg,
                               registro_activo=True)
    finally:
        conn.close()

    # En sesión solo queda el correo (el código vive en la BD Auth)
    session['reg_correo'] = correo

    resultado = enviar_correo(
        correo,
        f'Tu código de verificación CLEOFERR: {codigo}',
        _correo_html_codigo(nombre, codigo, 'Tu código de verificación para crear tu cuenta es:'),
        f"Hola {nombre},\n\nTu código de verificación es: {codigo}\n\nVálido por 10 minutos."
    )

    if resultado == 'smtp_no_configurado':
        # SMTP no configurado: modo desarrollo, mostrar el código en pantalla
        return render_template('login_cliente.html',
                               verificar_activo=True,
                               correo_verificar=correo,
                               codigo_visible=codigo,
                               aviso_smtp=True)
    if resultado in ('smtp_auth', 'smtp_error', 'error'):
        # El código YA quedó almacenado en BD (transacción confirmada arriba).
        # Para no dejar al usuario bloqueado, mostramos la pantalla de
        # verificación con el código en pantalla + aviso de que el correo
        # no se pudo enviar (SMTP mal configurado / credenciales inválidas).
        app.logger.error(f"No se pudo enviar el correo de verificación a {correo} "
                         f"(resultado: {resultado}). El código se muestra en pantalla.")
        return render_template('login_cliente.html',
                               verificar_activo=True,
                               correo_verificar=correo,
                               codigo_visible=codigo,
                               aviso_smtp=True,
                               aviso_smtp_motivo=(
                                   'Credenciales SMTP inválidas (revisa SMTP_USER/SMTP_PASS '
                                   'usando una contraseña de aplicación de Gmail).'
                                   if resultado == 'smtp_auth'
                                   else 'El servicio de correo presentó un error. Revisa el log del backend.'
                               ))

    return render_template('login_cliente.html',
                           verificar_activo=True,
                           correo_verificar=correo)


@app.route('/verificar_registro', methods=['POST'])
def verificar_registro():
    """Verifica el código OTP contra verificacion_cuenta y activa la cuenta."""
    codigo_ingresado = request.form.get('codigo', '').strip()
    correo = session.get('reg_correo')

    if not correo:
        return render_template('login_cliente.html',
                               error='Sesión expirada. Por favor regístrate de nuevo.',
                               registro_activo=True)

    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    try:
        # Cliente pendiente de verificación
        cursor.execute("SELECT id_cliente FROM cliente WHERE email = %s", (correo,))
        cliente = cursor.fetchone()
        if not cliente:
            return render_template('login_cliente.html',
                                   error='No hay un registro pendiente para este correo.',
                                   registro_activo=True)
        id_cliente = cliente['id_cliente']

        # Último código vigente no usado para ese cliente
        cursor.execute("""
            SELECT id_verificacion, codigo_hash, expira_en, intentos_fallidos
            FROM verificacion_cuenta
            WHERE id_cliente = %s AND usado = FALSE
            ORDER BY creado_en DESC LIMIT 1
        """, (id_cliente,))
        verif = cursor.fetchone()

        if not verif:
            return render_template('login_cliente.html',
                                   error='No hay un código activo. Solicita uno nuevo desde el registro.',
                                   verificar_activo=True,
                                   correo_verificar=correo)

        from datetime import datetime, timezone
        if verif['expira_en'] < datetime.now(timezone.utc):
            return render_template('login_cliente.html',
                                   error='El código expiró. Regístrate de nuevo para recibir uno nuevo.',
                                   verificar_activo=True,
                                   correo_verificar=correo)

        # Bloqueo tras 5 intentos fallidos (mismo criterio que la recuperación de contraseña)
        if verif['intentos_fallidos'] >= 5:
            cursor.execute("UPDATE verificacion_cuenta SET usado = TRUE WHERE id_verificacion = %s",
                           (verif['id_verificacion'],))
            conn.commit()
            return render_template('login_cliente.html',
                                   error='Demasiados intentos fallidos. Regístrate de nuevo para recibir un código nuevo.',
                                   verificar_activo=True,
                                   correo_verificar=correo)

        try:
            coincide = bcrypt.check_password_hash(verif['codigo_hash'], codigo_ingresado)
        except (ValueError, TypeError):
            coincide = False

        if not coincide:
            intentos = verif['intentos_fallidos'] + 1
            cursor.execute("""
                UPDATE verificacion_cuenta
                SET intentos_fallidos = %s, usado = (CASE WHEN %s >= 5 THEN TRUE ELSE usado END)
                WHERE id_verificacion = %s
            """, (intentos, intentos, verif['id_verificacion']))
            conn.commit()
            return render_template('login_cliente.html',
                                   error=('Demasiados intentos fallidos. Regístrate de nuevo '
                                          'para recibir un código nuevo.' if intentos >= 5
                                          else f'Código incorrecto. Te quedan {5 - intentos} intentos.'),
                                   verificar_activo=True,
                                   correo_verificar=correo)

        # Código correcto: marcarlo usado y activar la cuenta
        cursor.execute("UPDATE verificacion_cuenta SET usado = TRUE WHERE id_verificacion = %s",
                       (verif['id_verificacion'],))
        cursor.execute("UPDATE cliente SET activo = TRUE WHERE id_cliente = %s", (id_cliente,))
        conn.commit()
        session.pop('reg_correo', None)
        return render_template('login_cliente.html',
                               success='¡Cuenta creada y verificada! Ya puedes iniciar sesión.')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error en verificar_registro: {e}")
        return render_template('login_cliente.html',
                               error='Error al verificar el código. Intenta de nuevo.',
                               registro_activo=True)
    finally:
        conn.close()


# ── Recuperación de contraseña ──────────────────────────────
def _buscar_cuenta_por_correo(cursor, correo):
    """Busca el correo en usuario y en cliente (BD Auth).
    Devuelve (tipo, dict) donde tipo es 'usuario' o 'cliente', o (None, None)."""
    cursor.execute("SELECT id_usuario, nombres FROM usuario WHERE email = %s", (correo,))
    u = cursor.fetchone()
    if u:
        return 'usuario', u
    cursor.execute("SELECT id_cliente, nombre FROM cliente WHERE email = %s", (correo,))
    c = cursor.fetchone()
    if c:
        return 'cliente', c
    return None, None


@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    """Paso 1: el usuario ingresa su correo y recibe un código OTP de 6 dígitos."""
    import random

    if request.method == 'GET':
        return render_template('recuperar_contrasena.html')

    correo = request.form.get('correo', '').strip()
    if not correo:
        return render_template('recuperar_contrasena.html',
                               error='Ingresa tu correo electrónico.')

    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    try:
        tipo, cuenta = _buscar_cuenta_por_correo(cursor, correo)
        if not cuenta:
            # Mensaje genérico para no revelar si el correo existe o no
            return render_template('recuperar_contrasena.html',
                                   verificar_activo=True, correo_verificar=correo)

        nombre = cuenta.get('nombres') or cuenta.get('nombre') or correo
        codigo = str(random.randint(100000, 999999))
        codigo_hash = bcrypt.generate_password_hash(codigo).decode('utf-8')

        id_usuario = cuenta['id_usuario'] if tipo == 'usuario' else None
        id_cliente = cuenta['id_cliente'] if tipo == 'cliente' else None

        # Invalidar códigos anteriores de esta cuenta
        cursor.execute("""
            UPDATE recuperacion_contrasena SET usado = TRUE
            WHERE COALESCE(id_usuario, -1) = COALESCE(%s, -1)
              AND COALESCE(id_cliente, -1) = COALESCE(%s, -1)
              AND usado = FALSE
        """, (id_usuario, id_cliente))
        cursor.execute("""
            INSERT INTO recuperacion_contrasena
                (id_usuario, id_cliente, codigo_hash, creado_en, expira_en, usado, ip_solicitud)
            VALUES (%s, %s, %s, NOW(), NOW() + INTERVAL '10 minutes', FALSE, %s)
        """, (id_usuario, id_cliente, codigo_hash, request.remote_addr))
        conn.commit()
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error en recuperar_contrasena: {e}")
        return render_template('recuperar_contrasena.html',
                               error='No se pudo procesar la solicitud. Intenta de nuevo.')
    finally:
        conn.close()

    resultado = enviar_correo(
        correo,
        f'Tu código para recuperar tu contraseña CLEOFERR: {codigo}',
        _correo_html_codigo(nombre, codigo, 'Tu código para restablecer tu contraseña es:'),
        f"Hola {nombre},\n\nTu código para recuperar tu contraseña es: {codigo}\n\nVálido por 10 minutos."
    )
    if resultado == 'smtp_no_configurado':
        return render_template('recuperar_contrasena.html',
                               verificar_activo=True, correo_verificar=correo,
                               codigo_visible=codigo, aviso_smtp=True)
    if resultado == 'smtp_auth':
        return render_template('recuperar_contrasena.html',
                               error='Error de autenticación con el correo. Contacta al administrador.')
    if resultado:
        return render_template('recuperar_contrasena.html',
                               error='No se pudo enviar el correo. Intenta de nuevo.')

    return render_template('recuperar_contrasena.html',
                           verificar_activo=True, correo_verificar=correo)


@app.route('/restablecer_contrasena', methods=['POST'])
def restablecer_contrasena():
    """Paso 2: valida el OTP y cambia la contraseña (usuario o cliente)."""
    correo     = request.form.get('correo', '').strip()
    codigo     = request.form.get('codigo', '').strip()
    nueva      = request.form.get('nueva', '')
    confirmar  = request.form.get('confirmar', '')

    def _reenviar_con_error(msg):
        return render_template('recuperar_contrasena.html',
                               error=msg, verificar_activo=True,
                               correo_verificar=correo)

    if not correo or not codigo or not nueva:
        return _reenviar_con_error('Todos los campos son obligatorios.')
    if nueva != confirmar:
        return _reenviar_con_error('Las contraseñas no coinciden.')
    if len(nueva) < 6:
        return _reenviar_con_error('La contraseña debe tener al menos 6 caracteres.')

    conn   = get_connection_auth()
    cursor = conn.cursor(dictionary=True)
    try:
        tipo, cuenta = _buscar_cuenta_por_correo(cursor, correo)
        if not cuenta:
            return _reenviar_con_error('Solicitud no válida. Vuelve a solicitar el código.')

        id_usuario = cuenta['id_usuario'] if tipo == 'usuario' else None
        id_cliente = cuenta['id_cliente'] if tipo == 'cliente' else None

        cursor.execute("""
            SELECT id_recuperacion, codigo_hash, expira_en, intentos_fallidos
            FROM recuperacion_contrasena
            WHERE COALESCE(id_usuario, -1) = COALESCE(%s, -1)
              AND COALESCE(id_cliente, -1) = COALESCE(%s, -1)
              AND usado = FALSE
            ORDER BY creado_en DESC LIMIT 1
        """, (id_usuario, id_cliente))
        rec = cursor.fetchone()

        if not rec:
            return _reenviar_con_error('No hay un código activo. Solicita uno nuevo.')

        from datetime import datetime, timezone
        if rec['expira_en'] < datetime.now(timezone.utc):
            return _reenviar_con_error('El código expiró. Solicita uno nuevo.')

        if rec['intentos_fallidos'] >= 5:
            cursor.execute("UPDATE recuperacion_contrasena SET usado = TRUE WHERE id_recuperacion = %s",
                           (rec['id_recuperacion'],))
            conn.commit()
            return render_template('recuperar_contrasena.html',
                                   error='Demasiados intentos fallidos. Solicita un nuevo código.')

        try:
            coincide = bcrypt.check_password_hash(rec['codigo_hash'], codigo)
        except (ValueError, TypeError):
            coincide = False

        if not coincide:
            intentos = rec['intentos_fallidos'] + 1
            cursor.execute("""
                UPDATE recuperacion_contrasena
                SET intentos_fallidos = %s, usado = (CASE WHEN %s >= 5 THEN TRUE ELSE usado END)
                WHERE id_recuperacion = %s
            """, (intentos, intentos, rec['id_recuperacion']))
            conn.commit()
            if intentos >= 5:
                return render_template('recuperar_contrasena.html',
                                       error='Demasiados intentos fallidos. Solicita un nuevo código.')
            return _reenviar_con_error(f'Código incorrecto. Te quedan {5 - intentos} intentos.')

        # Código correcto: cambiar contraseña y marcar código como usado
        nuevo_hash = bcrypt.generate_password_hash(nueva).decode('utf-8')
        if tipo == 'usuario':
            cursor.execute("""
                UPDATE usuario SET contrasena = %s, fecha_ultimo_cambio_pwd = NOW()
                WHERE id_usuario = %s
            """, (nuevo_hash, id_usuario))
        else:
            cursor.execute("""
                UPDATE cliente SET contrasena = %s, fecha_ultimo_cambio_pwd = NOW()
                WHERE id_cliente = %s
            """, (nuevo_hash, id_cliente))
        cursor.execute("UPDATE recuperacion_contrasena SET usado = TRUE WHERE id_recuperacion = %s",
                       (rec['id_recuperacion'],))
        conn.commit()

        # Volver al login correspondiente
        if tipo == 'usuario':
            return render_template('login.html',
                                   success='Contraseña actualizada. Inicia sesión con tu nueva clave.')
        return render_template('login_cliente.html',
                               success='Contraseña actualizada. Inicia sesión con tu nueva clave.')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error en restablecer_contrasena: {e}")
        return _reenviar_con_error('Error al actualizar la contraseña. Intenta de nuevo.')
    finally:
        conn.close()


@app.route('/mis_pedidos')
def mis_pedidos():
    """Historial de pedidos del cliente con estado actualizado."""
    if not session.get('usuario_id'):
        return redirect(url_for('login_cliente'))
    if session.get('rol') != 'cliente':
        return redirect(url_for('pedidos'))
    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    pedidos_lista = []
    fases_orden = []
    try:
        # Fases válidas leídas de la BD (misma fuente que el panel admin)
        cursor.execute("SELECT nombre FROM estado_venta WHERE activo = TRUE ORDER BY orden")
        fases_orden = [r['nombre'] for r in cursor.fetchall()]
        fases_orden = [f for f in fases_orden if f != 'cancelado']
        PASOS = fases_orden
        cursor.execute("""
            SELECT v.id_venta,
                   v.fecha AT TIME ZONE 'UTC' AT TIME ZONE 'America/Lima' AS fecha,
                   ev.nombre AS estado,
                   COALESCE(SUM(d.cantidad * d.precio_unitario), 0) AS total
            FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            LEFT JOIN detalle_venta d ON v.id_venta = d.id_venta
            WHERE v.id_cliente = %s
            GROUP BY v.id_venta, v.fecha, ev.nombre
            ORDER BY v.fecha DESC
        """, (session['usuario_id'],))
        pedidos_lista = cursor.fetchall()
        for ped in pedidos_lista:
            ped['fecha_peru'] = ped.get('fecha')
            estado = ped.get('estado') or 'pendiente'
            ped['idx_actual'] = PASOS.index(estado) if estado in PASOS else 0
            try:
                cursor.execute("""
                    SELECT d.cantidad, d.precio_unitario, p.nombre AS producto_nombre
                    FROM detalle_venta d
                    LEFT JOIN producto p ON d.id_producto = p.id_producto
                    WHERE d.id_venta = %s
                """, (ped['id_venta'],))
                ped['items'] = cursor.fetchall()
            except Exception:
                ped['items'] = []
    except Exception as e:
        app.logger.exception("Error mis_pedidos: %s", e)
    finally:
        conn.close()
    if not fases_orden:
        fases_orden = ['pendiente', 'confirmado', 'preparando', 'listo', 'entregado']
    return render_template('mis_pedidos.html', pedidos=pedidos_lista, fases_orden=fases_orden)


@app.route('/pedido_aceptado')
@login_required
def pedido_aceptado():
    """Página de confirmación con fases del pedido para el cliente."""
    if session.get('rol') != 'cliente':
        return redirect(url_for('pedidos'))
    id_pedido = request.args.get('id', '')
    estado    = 'pendiente'
    if id_pedido:
        conn   = get_connection_tienda()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
            SELECT ev.nombre AS estado, v.id_cliente FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            WHERE v.id_venta = %s
        """, (id_pedido,))
            row = cursor.fetchone()
            if row:
                # IDOR: este pedido solo pertenece al cliente logueado
                if row.get('id_cliente') is not None and row['id_cliente'] != session.get('usuario_id'):
                    abort(403)
                estado = row.get('estado', 'pendiente')
        except Exception:
            pass
        finally:
            conn.close()
    return render_template('pedido_aceptado.html', id_pedido=id_pedido, estado=estado)


@app.route('/pedidos/<int:id>/estado', methods=['POST'])
@login_required
@escritura_required
def pedido_cambiar_estado(id):
    """Vendedor/Admin cambia el estado (fase) de un pedido.
    Responde JSON si la petición es AJAX (X-Requested-With), o redirige
    si llega desde un formulario clásico.
    """
    conn_v   = get_connection_tienda()
    cursor_v = conn_v.cursor(dictionary=True)
    cursor_v.execute("SELECT nombre FROM estado_venta WHERE activo = TRUE ORDER BY orden")
    estados_validos = tuple(r['nombre'] for r in cursor_v.fetchall())
    conn_v.close()

    nuevo_estado = request.form.get('estado', '').strip()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if nuevo_estado not in estados_validos:
        if is_ajax:
            return {'ok': False, 'error': f'Estado "{nuevo_estado}" no es válido.'}, 400
        flash('Estado no válido.', 'danger')
        return redirect(url_for('pedido_detalle', id=id))

    conn   = get_connection_tienda()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE venta
            SET id_estado_venta = (SELECT id_estado_venta FROM estado_venta WHERE nombre = %s)
            WHERE id_venta = %s
        """, (nuevo_estado, id))
        conn.commit()

        if is_ajax:
            return {'ok': True, 'estado': nuevo_estado, 'mensaje': f'Estado actualizado a "{nuevo_estado}".'}

        flash(f'Estado actualizado a "{nuevo_estado}".', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error al actualizar estado pedido #{id}: {e}")
        if is_ajax:
            return {'ok': False, 'error': f'Error de base de datos: {e}'}, 500
        flash(f'Error al actualizar estado: {e}', 'danger')
    finally:
        conn.close()

    ref = request.referrer or ''
    if '/pedidos?' in ref or ref.rstrip('/').endswith('/pedidos'):
        return redirect(url_for('pedidos'))
    return redirect(url_for('pedido_detalle', id=id))


@app.route('/carrito/confirmar_v2', methods=['POST'])
@login_required
def carrito_confirmar_v2():
    """Confirma el pedido guardando método de pago y generando comprobante."""
    data = request.get_json(silent=True) or request.form.to_dict()
    return _confirmar_carrito(
        items            = data.get('items') or [],
        metodo_pago      = data.get('metodo_pago') or data.get('metodo') or 'efectivo',
        tipo_comprobante = data.get('tipo_comprobante') or 'boleta_simple',
        ruc              = (data.get('ruc') or '').strip() or None,
        num_operacion    = (data.get('num_operacion') or '').strip() or None,
    )


def _confirmar_carrito(items, metodo_pago='efectivo', tipo_comprobante='boleta_simple',
                       ruc=None, num_operacion=None):
    """Lógica compartida de confirmación de carrito (pago + venta + detalle + comprobante)."""
    import random, string
    if not items:
        return {'ok': False, 'error': 'Carrito vacío'}
    if session.get('rol') != 'cliente':
        return {'ok': False, 'error': 'Solo clientes pueden confirmar pedidos'}

    # Validar que todos los productos del carrito existan y estén activos
    # (el carrito vive en localStorage del navegador y puede traer IDs obsoletos
    #  si el catálogo cambió desde que se agregaron los ítems)
    conn_val   = get_connection_tienda()
    cursor_val = conn_val.cursor(dictionary=True)
    ids_items  = {int(it.get('id_producto') or it.get('id') or 0) for it in items}
    cursor_val.execute(
        "SELECT id_producto, nombre, precio, stock FROM producto "
        "WHERE id_producto = ANY(%s) AND activo = TRUE",
        (list(ids_items),))
    prods_validos = {r['id_producto']: r for r in cursor_val.fetchall()}
    ids_validos = set(prods_validos)
    conn_val.close()

    ids_faltantes = ids_items - ids_validos
    if ids_faltantes:
        nombres_bad = []
        for it in items:
            pid = int(it.get('id_producto') or it.get('id') or 0)
            if pid in ids_faltantes:
                nombres_bad.append(it.get('nombre') or f'producto #{pid}')
        return {'ok': False, 'error': (
            'Este producto ya no está disponible: ' + ', '.join(nombres_bad)
            + '. Eliminalo del carrito para continuar.'
        )}

    tipo_boleta  = 'electronica' if tipo_comprobante == 'boleta_electronica' else 'simple'
    tipo_comp_db = 'factura' if (ruc and len(ruc) == 11 and ruc.startswith('20')) else 'boleta'
    metodo_db    = 'yape_plin' if metodo_pago == 'yape' else (
                   'tarjeta'   if metodo_pago == 'tarjeta' else 'efectivo')

    conn   = get_connection_tienda()
    cursor = conn.cursor()
    try:
        # El esquema real de venta usa FKs: id_tipo_venta e id_estado_venta.
        # El método de pago se registra en la tabla pago (id_tipo_pago).
        cursor.execute("""
            INSERT INTO venta (id_tipo_venta, id_cliente, id_estado_venta, num_operacion)
            VALUES ((SELECT id_tipo_venta FROM tipo_venta WHERE nombre = 'online'),
                    %s,
                    (SELECT id_estado_venta FROM estado_venta WHERE nombre = 'pendiente'),
                    %s)
            RETURNING id_venta
        """, (session['usuario_id'], num_operacion))
        id_venta = cursor.fetchone()[0]
        try:
            # Pago en savepoint: si la tabla pago/tipo_pago no existe o falla,
            # se revierte SOLO este bloque sin abortar la venta ni el detalle.
            cursor.execute("SAVEPOINT sp_pago")
            cursor.execute("SELECT id_caja FROM caja WHERE estado = 'abierta' LIMIT 1")
            fila_caja  = cursor.fetchone()
            id_caja_a  = fila_caja[0] if fila_caja else None
            cursor.execute("""
                INSERT INTO pago (id_venta, id_tipo_pago, id_caja, estado)
                VALUES (%s, (SELECT id_tipo_pago FROM tipo_pago WHERE nombre = %s), %s, 'pendiente')
            """, (id_venta, metodo_db, id_caja_a))
        except Exception as e:
            app.logger.warning("No se pudo registrar el pago del pedido %s (tabla opcional): %s",
                               id_venta, e)
            cursor.execute("ROLLBACK TO SAVEPOINT sp_pago")

        for it in items:
            id_producto = int(it.get('id_producto') or it.get('id') or 0)
            cantidad    = int(it.get('cantidad', 1) or 1)
            if cantidad <= 0:
                return {'ok': False, 'error': 'Cantidad inválida en el carrito.'}
            prod_info = prods_validos.get(id_producto)
            if prod_info is None:
                continue
            if cantidad > (prod_info['stock'] or 0):
                return {'ok': False,
                        'error': f'Stock insuficiente de "{prod_info["nombre"]}" '
                                 f'(disponible: {prod_info["stock"]} unidades).'}
            # Precio del catálogo en BD (nunca el que envía el cliente)
            precio_unit = float(prod_info['precio'])
            cursor.execute("""
                INSERT INTO detalle_venta (id_venta, id_producto, cantidad, precio_unitario)
                VALUES (%s, %s, %s, %s)
            """, (id_venta, id_producto, cantidad, precio_unit))
            cursor.execute("""
                UPDATE producto SET stock = GREATEST(stock - %s, 0) WHERE id_producto = %s
            """, (cantidad, id_producto))

        # Generar número de comprobante y guardarlo
        num_comp = 'B' + str(id_venta).zfill(6) + '-' + ''.join(random.choices(string.digits, k=4))
        try:
            cursor.execute("SAVEPOINT sp_comprobante")
            cursor.execute("""
                INSERT INTO comprobante (id_venta, id_tipo_comprobante, numero, ruc)
                VALUES (%s, (SELECT id_tipo_comprobante FROM tipo_comprobante WHERE nombre = %s), %s, %s)
            """, (id_venta, tipo_comp_db, num_comp, ruc))
        except Exception as e:
            app.logger.warning("No se pudo generar el comprobante del pedido %s (tabla opcional): %s",
                               id_venta, e)
            cursor.execute("ROLLBACK TO SAVEPOINT sp_comprobante")

        conn.commit()
        session['carrito'] = {}
        session['ultimo_pedido'] = items
        return {'ok': True, 'id_pedido': id_venta}

    except Exception as e:
        conn.rollback()
        app.logger.exception("Error carrito_confirmar_v2: %s", e)
        return {'ok': False, 'error': str(e)}
    finally:
        conn.close()


if __name__ == '__main__':
    # debug solo si FLASK_DEBUG=1 explícitamente en el entorno (nunca en producción)
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
