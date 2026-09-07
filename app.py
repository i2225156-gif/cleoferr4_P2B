import os
import sys
import uuid
# AÑADIR después de: import uuid
from urllib.parse import quote
# Intento seguro de importar dependencias externas; si faltan, mostrar instrucciones claras y salir.
try:
    from flask import Flask, render_template, request, redirect, url_for, session, flash
    from flask_bcrypt import Bcrypt
    from functools import wraps
    from werkzeug.utils import secure_filename   # ← NUEVO
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

# El ORM (modelo Producto) usa la BD Tienda.
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


def enviar_correo(destino, asunto, cuerpo_html, cuerpo_texto=None):
    """Envía un correo vía Gmail SMTP (STARTTLS, puerto 587).

    Usa SMTP_USER / SMTP_PASS del entorno (contraseña de aplicación de Gmail).

    Retorna:
      - None                  -> envío exitoso
      - 'smtp_no_configurado' -> faltan SMTP_USER/SMTP_PASS (modo desarrollo)
      - 'smtp_auth'           -> error de autenticación con Gmail
      - 'error'               -> cualquier otro fallo de envío
    """
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
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            flash("Acceso denegado.", "danger")
            return redirect(url_for("productos"))
        return f(*args, **kwargs)
    return decorated_function

def escritura_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") not in ("administrador", "vendedor"):
            flash("No tienes permisos para realizar esta acción.", "danger")
            return redirect(url_for("productos"))
        return f(*args, **kwargs)
    return decorated_function


# ── Auth ─────────────────────────────────────────────────────
@app.route('/')
def inicio():
    return redirect(url_for('catalogo_cliente'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        clave  = request.form['clave']
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
            # Permitir solo administradores y vendedores en este login
            if rol_usuario not in ('administrador', 'vendedor'):
                # Mensaje breve indicando redirección al login de clientes
                return render_template('login.html', error='Acceso restringido. Si eres cliente usa el acceso de clientes: /login_cliente')
            session['usuario_id'] = usuario['id_usuario']
            session['rol']        = usuario['rol']
            session['nombre']     = usuario['nombres']
            return redirect(url_for('productos'))
        return render_template('login.html', error='Credenciales incorrectas')
    # Botón WhatsApp para recuperar credenciales (personal administrativo)
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
    session.clear()
    return redirect(url_for('login'))



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
def eliminar_proveedor_post(proveedor_id):
    # Verificar sesión / permisos básicos
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
    PASOS = ['pendiente', 'procesando', 'enviado', 'entregado']
    try:
        # Consulta 1 (Tienda): ventas + total, sin joins cross-BD
        cursor.execute("""
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
            GROUP BY v.id_venta, v.fecha, tv.nombre, ev.nombre,
                     v.id_cliente, v.id_usuario_vendedor
            ORDER BY v.fecha DESC
            LIMIT 200
        """)
        pedidos_raw = cursor.fetchall()
        conn.close()

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
            nombre   = ped.get('cliente_nombre') or 'Cliente'
            telefono = (ped.get('cliente_telefono') or '').strip()
            if telefono:
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
    return render_template('pedidos.html', pedidos=pedidos)

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
    return render_template('venta_form.html', clientes=clientes, productos=productos)


@app.route('/ventas/nueva', methods=['POST'])
@login_required
@escritura_required
def venta_nueva_guardar():
    id_cliente   = request.form.get('id_cliente') or None
    tipo_venta   = request.form.get('tipo_venta', 'local')
    ids_producto = request.form.getlist('id_producto[]')
    cantidades   = request.form.getlist('cantidad[]')

    if not ids_producto:
        flash('Debes agregar al menos un producto.', 'danger')
        return redirect(url_for('venta_nueva_form'))

    conn   = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    try:
        # Crear la venta
        cursor.execute("""
            INSERT INTO venta (id_tipo_venta, id_cliente, id_usuario_vendedor, id_estado_venta)
            VALUES ((SELECT id_tipo_venta FROM tipo_venta WHERE nombre = %s), %s, %s,
                    (SELECT id_estado_venta FROM estado_venta WHERE nombre = 'pendiente'))
            RETURNING id_venta
        """, (tipo_venta, id_cliente, session.get('usuario_id')))
        id_venta = cursor.fetchone()['id_venta']

        # Insertar cada ítem y descontar stock
        for id_prod, cant in zip(ids_producto, cantidades):
            cant = int(cant) if cant else 1
            cursor.execute("SELECT precio, stock FROM producto WHERE id_producto = %s", (id_prod,))
            prod = cursor.fetchone()
            if not prod:
                continue
            cursor.execute("""
                INSERT INTO detalle_venta (id_venta, id_producto, cantidad, precio_unitario)
                VALUES (%s, %s, %s, %s)
            """, (id_venta, id_prod, cant, prod['precio']))
            cursor.execute("""
                UPDATE producto SET stock = stock - %s WHERE id_producto = %s
            """, (cant, id_prod))

        conn.commit()
        flash(f'Venta #{id_venta} registrada correctamente.', 'success')
        return redirect(url_for('pedidos'))

    except Exception as e:
        print(f"ERROR al guardar venta: {e}")
        flash('Error al registrar la venta. Intenta de nuevo.', 'danger')
        return redirect(url_for('venta_nueva_form'))
    finally:
        conn.close()


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
                    "SELECT nombre, apellido, telefono FROM cliente WHERE id_cliente = %s",
                    (pedido['id_cliente'],))
                cli = cursor_a.fetchone() or {}
                pedido['cliente_nombre']   = (f"{cli.get('nombre') or ''} {cli.get('apellido') or ''}").strip()
                pedido['cliente_telefono'] = cli.get('telefono')
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
    # Calcular idx_actual en Python para evitar el error .index() en Jinja2
    PASOS = ['pendiente', 'procesando', 'enviado', 'entregado']
    estado_actual = (pedido.get('estado') or 'pendiente') if pedido else 'pendiente'
    idx_actual = PASOS.index(estado_actual) if estado_actual in PASOS else 0
    return render_template('pedido_detalle.html', pedido=pedido, items=items,
                           comprobante=comprobante, id=id,
                           idx_actual=idx_actual, fases_orden=PASOS)

@app.route('/reportes')
@login_required
@escritura_required
def reportes():
    conn = get_connection_tienda()
    cursor = conn.cursor(dictionary=True)
    resumen = {}
    reportes_data = None

    try:
        # Ventas hoy (si existe tabla pedido con campo total y fecha)
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

        # Dashboard inventario: entradas/salidas últimos 30 días (cantidad y valor)
        try:
            cursor.execute("""
                SELECT tipo,
                       COALESCE(SUM(cantidad),0) AS total_cantidad,
                       COALESCE(SUM(precio_unitario * cantidad),0) AS total_valor
                FROM inventario_movimiento
                WHERE fecha >= DATE_SUB(NOW(), INTERVAL 30 DAY)
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
    # Simulación de pago: si hay items en session['ultimo_pedido'] o en session['carrito'], crear pedido si cliente
    if session.get('rol') != 'cliente':
        flash("Solo clientes pueden procesar pagos.", "warning")
        return redirect(url_for('productos'))

    # Preferir items del body si llegan (compatibilidad con pago.html)
    items = session.get('ultimo_pedido') or []
    if not items:
        # intentar obtener desde session carrito dict -> transformar a lista
        carrito = session.get('carrito', {})
        items = []
        for k, v in carrito.items():
            items.append({
                'id_producto': v.get('id_producto') or v.get('id'),
                'cantidad': v.get('cantidad'),
                'precio': v.get('precio')
            })

    if not items:
        flash("No hay items en el carrito para procesar.", "warning")
        return redirect(url_for('catalogo_cliente'))

    # Reusar la lógica de carrito_confirmar_v2 para crear pedido (llamar internamente)
    resp = carrito_confirmar_v2()  # devuelve dict o respuesta
    # carrito_confirmar_v2 ya hizo commit y flash
    # redirigir al cliente a catálogo o a detalle del pedido si id devuelto
    if isinstance(resp, dict) and resp.get('ok') and resp.get('id_pedido'):
        return redirect(url_for('catalogo_cliente'))
    # si fue Response (JS fetch), intentar interpretar
    try:
        # si retornó flask Response con JSON
        d = resp.get_json() if hasattr(resp, 'get_json') else {}
        if d.get('ok') and d.get('id_pedido'):
            return redirect(url_for('catalogo_cliente'))
    except Exception:
        pass
    # fallback
    return redirect(url_for('catalogo_cliente'))


# ── Cambiar clave ─────────────────────────────────────────────
@app.route('/cambiar_clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    if request.method == 'POST':
        nueva     = request.form['nueva']
        confirmar = request.form['confirmar']
        if nueva != confirmar:
            return render_template('cambiar_clave.html', error='Las contraseñas no coinciden')
        nueva_hash = bcrypt.generate_password_hash(nueva).decode('utf-8')
        conn   = get_connection_auth()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuario SET contrasena = %s WHERE id_usuario = %s",
                       (nueva_hash, session['usuario_id']))
        conn.commit()
        conn.close()
        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('productos'))
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
    contrasena = request.form.get('contrasena', '')
    confirmar  = request.form.get('confirmar', '')

    if not nombre or not correo or not contrasena:
        return render_template('login_cliente.html',
                               error='Nombre, correo y contraseña son obligatorios.',
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
                UPDATE cliente SET nombre=%s, apellido=%s, telefono=%s, contrasena=%s
                WHERE id_cliente=%s
            """, (nombre, apellido or None, telefono or None, hash_pw, id_cliente))
        else:
            # id_tipo_documento=1 (DNI) y nro_documento vacío ('') por defecto;
            # el formulario web no pide documento todavía
            cursor.execute("""
                INSERT INTO cliente (nombre, apellido, email, telefono, contrasena,
                                     id_tipo_documento, nro_documento, activo)
                VALUES (%s, %s, %s, %s, %s, 1, '', FALSE)
                RETURNING id_cliente
            """, (nombre, apellido or None, correo, telefono or None, hash_pw))
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
        app.logger.error(f"Error en registro_cliente: {e}")
        return render_template('login_cliente.html',
                               error='No se pudo iniciar el registro. Intenta de nuevo.',
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
        # Modo desarrollo: mostrar el código en pantalla
        return render_template('login_cliente.html',
                               verificar_activo=True,
                               correo_verificar=correo,
                               codigo_visible=codigo,
                               aviso_smtp=True)
    if resultado == 'smtp_auth':
        return render_template('login_cliente.html',
                               error='Error de autenticación con el correo. Contacta al administrador.',
                               registro_activo=True)
    if resultado:
        return render_template('login_cliente.html',
                               error='No se pudo enviar el correo de verificación. Intenta de nuevo.',
                               registro_activo=True)

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
            SELECT id_verificacion, codigo_hash, expira_en
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

        try:
            coincide = bcrypt.check_password_hash(verif['codigo_hash'], codigo_ingresado)
        except (ValueError, TypeError):
            coincide = False

        if not coincide:
            cursor.execute("UPDATE verificacion_cuenta SET intentos_fallidos = intentos_fallidos + 1 WHERE id_verificacion = %s",
                           (verif['id_verificacion'],))
            conn.commit()
            return render_template('login_cliente.html',
                                   error='Código incorrecto. Intenta de nuevo.',
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
    PASOS = ['pendiente', 'procesando', 'enviado', 'entregado']
    try:
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
    return render_template('mis_pedidos.html', pedidos=pedidos_lista)


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
            SELECT ev.nombre AS estado FROM venta v
            LEFT JOIN estado_venta ev ON v.id_estado_venta = ev.id_estado_venta
            WHERE v.id_venta = %s
        """, (id_pedido,))
            row = cursor.fetchone()
            if row:
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
    """Vendedor/Admin cambia el estado (fase) de un pedido."""
    estados_validos = ('pendiente', 'procesando', 'enviado', 'entregado', 'cancelado')
    nuevo_estado = request.form.get('estado', 'pendiente')
    if nuevo_estado not in estados_validos:
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
        flash(f'Estado actualizado a "{nuevo_estado}".', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al actualizar estado: {e}', 'danger')
    finally:
        conn.close()
    # Volver a la lista si el cambio vino desde /pedidos, sino al detalle
    ref = request.referrer or ''
    if '/pedidos?' in ref or ref.rstrip('/').endswith('/pedidos'):
        return redirect(url_for('pedidos'))
    return redirect(url_for('pedido_detalle', id=id))


@app.route('/carrito/confirmar_v2', methods=['POST'])
@login_required
def carrito_confirmar_v2():
    """Confirma el pedido guardando método de pago y generando comprobante."""
    import random, string
    data             = request.get_json() or {}
    items            = data.get('items', [])
    metodo_pago      = data.get('metodo_pago', 'efectivo')
    tipo_comprobante = data.get('tipo_comprobante', 'boleta_simple')
    ruc              = (data.get('ruc') or '').strip() or None
    num_operacion    = (data.get('num_operacion') or '').strip() or None

    if not items:
        return {'ok': False, 'error': 'Carrito vacío'}
    if session.get('rol') != 'cliente':
        return {'ok': False, 'error': 'Solo clientes pueden confirmar pedidos'}

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
            cursor.execute("""
                INSERT INTO pago (id_venta, id_tipo_pago, estado)
                VALUES (%s, (SELECT id_tipo_pago FROM tipo_pago WHERE nombre = %s), 'pendiente')
            """, (id_venta, metodo_db))
        except Exception:
            pass  # tabla/columna de pago opcional; no bloquea el pedido

        for it in items:
            id_producto = int(it.get('id_producto') or it.get('id') or 0)
            cantidad    = int(it.get('cantidad', 1))
            precio_unit = float(it.get('precio', 0) or 0)
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
            cursor.execute("""
                INSERT INTO comprobante (id_venta, id_tipo_comprobante, numero, ruc)
                VALUES (%s, (SELECT id_tipo_comprobante FROM tipo_comprobante WHERE nombre = %s), %s, %s)
            """, (id_venta, tipo_comp_db, num_comp, ruc))
        except Exception:
            pass  # tabla comprobante puede no existir; no es crítico

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
