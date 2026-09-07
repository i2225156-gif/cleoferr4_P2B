"""seed_data.py — Carga datos de prueba realistas en las dos bases de Supabase.

Uso:
    python seed_data.py

Características:
- Idempotente: se puede ejecutar varias veces sin duplicar datos
  (cada registro se busca primero por su clave natural; solo se inserta si no existe).
- Relaciones consistentes: los productos referencian categorías y marcas reales.
- Imprime un resumen al final con los insertados/omitidos por tabla.

Reutilizable después de limpiar las bases.
"""

import bcrypt
from sqlalchemy import text

from db_supabase import engine_auth, engine_tienda

resumen = {}  # {tabla: {'insertados': n, 'existentes': n}}


def _reg(tabla, inserto):
    d = resumen.setdefault(tabla, {'insertados': 0, 'existentes': 0})
    d['insertados' if inserto else 'existentes'] += 1


def seed_auth():
    print('-- BD AUTH (login/usuarios) --')
    with engine_auth.begin() as c:
        # ── Roles ──
        roles = {}
        for nombre in ['administrador', 'vendedor']:
            row = c.execute(text("SELECT id_rol FROM rol WHERE nombre=:n"),
                            {'n': nombre}).fetchone()
            if row:
                roles[nombre] = row[0]
                _reg('rol', False)
            else:
                roles[nombre] = c.execute(
                    text("INSERT INTO rol (nombre, activo) VALUES (:n, TRUE) RETURNING id_rol"),
                    {'n': nombre}).fetchone()[0]
                _reg('rol', True)

        # ── Usuarios ──
        # (contraseñas por defecto para pruebas locales)
        usuarios = [
            ('Administradora CLEOFERR', 'admin@cleoferr.com',      'Admin123!',  'administrador'),
            ('Vendedora CLEOFERR',      'vendedor@cleoferr.com',   'Vendedor123','vendedor'),
        ]
        for nombres, email, clave, rol_nombre in usuarios:
            existe = c.execute(text("SELECT 1 FROM usuario WHERE email=:e"),
                               {'e': email}).fetchone()
            if existe:
                _reg('usuario', False)
                continue
            hash_pw = bcrypt.hashpw(clave.encode(), bcrypt.gensalt()).decode()
            c.execute(text("""
                INSERT INTO usuario (email, contrasena, id_rol, nombres, activo)
                VALUES (:e, :p, :r, :n, TRUE)
            """), {'e': email, 'p': hash_pw, 'r': roles[rol_nombre], 'n': nombres})
            _reg('usuario', True)

        # ── Clientes (activos, listos para pruebas manuales) ──
        # id_tipo_documento: 1 = DNI
        clientes = [
            # nombre, apellido, email, telefono, dni, direccion, clave
            ('María',   'Quispe Ramos',   'maria.quispe@gmail.com',  '987654321',
             '45678812', 'Av. Los Pinos 123, Trujillo',  'Cliente123'),
            ('José',    'Torres Vega',    'jose.torres@gmail.com',   '998877665',
             '78451236', 'Jr. Bolívar 456, Trujillo',    'Cliente123'),
            ('Carmen',  'Ruiz Díaz',      'carmen.ruiz@gmail.com',   '955443322',
             '10234567', 'Calle Real 789, Huanchaco',    'Cliente123'),
        ]
        for nombre, apellido, email, fono, dni, direccion, clave in clientes:
            existe = c.execute(text("SELECT 1 FROM cliente WHERE email=:e"),
                               {'e': email}).fetchone()
            if existe:
                _reg('cliente', False)
                continue
            hash_pw = bcrypt.hashpw(clave.encode(), bcrypt.gensalt()).decode()
            c.execute(text("""
                INSERT INTO cliente (nombre, apellido, email, telefono,
                                     id_tipo_documento, nro_documento,
                                     direccion, contrasena, activo)
                VALUES (:nom, :ape, :em, :fono, 1, :dni, :dir, :pw, TRUE)
            """), {'nom': nombre, 'ape': apellido, 'em': email, 'fono': fono,
                   'dni': dni, 'dir': direccion, 'pw': hash_pw})
            _reg('cliente', True)


def seed_tienda():
    print('-- BD TIENDA --')
    with engine_tienda.begin() as c:
        # ── Categorías ──
        categorias = {}
        for nombre in ['Herramientas', 'Pinturas', 'Electricidad', 'Plomería', 'Construcción']:
            row = c.execute(text("SELECT id_categoria FROM categoria WHERE nombre=:n"),
                            {'n': nombre}).fetchone()
            if row:
                categorias[nombre] = row[0]
                _reg('categoria', False)
            else:
                categorias[nombre] = c.execute(
                    text("INSERT INTO categoria (nombre, activo) VALUES (:n, TRUE) RETURNING id_categoria"),
                    {'n': nombre}).fetchone()[0]
                _reg('categoria', True)

        # ── Marcas ──
        marcas = {}
        for nombre in ['Truper', 'Bosch', 'Stanley', 'Pavco']:
            row = c.execute(text("SELECT id_marca FROM marca WHERE nombre=:n"),
                            {'n': nombre}).fetchone()
            if row:
                marcas[nombre] = row[0]
                _reg('marca', False)
            else:
                marcas[nombre] = c.execute(
                    text("INSERT INTO marca (nombre, activo) VALUES (:n, TRUE) RETURNING id_marca"),
                    {'n': nombre}).fetchone()[0]
                _reg('marca', True)

        # ── Proveedores ──
        proveedores = [
            # nombre, contacto, telefono, email, direccion
            ('Distribuidora Ferretera SAC', 'Luis Mendoza', '014455667',
             'ventas@disferre.pe', 'Av. Argentina 1500, Lima'),
            ('Importaciones del Norte EIRL', 'Rosa Chávez', '044789123',
             'contacto@impnorte.pe', 'Calle Comercio 45, Trujillo'),
            ('Grupo Constructor Perú',      'Andrés Paredes', '019988776',
             'pedidos@gcperu.pe', 'Av. Industrial 890, Arequipa'),
        ]
        for nombre, contacto, fono, email, direccion in proveedores:
            existe = c.execute(text("SELECT 1 FROM proveedor WHERE nombre=:n"),
                               {'n': nombre}).fetchone()
            if existe:
                _reg('proveedor', False)
                continue
            c.execute(text("""
                INSERT INTO proveedor (nombre, contacto, telefono, email, direccion, activo)
                VALUES (:n, :c, :f, :e, :d, TRUE)
            """), {'n': nombre, 'c': contacto, 'f': fono, 'e': email, 'd': direccion})
            _reg('proveedor', True)

        # ── Productos ── (nombre, descripcion, precio, stock, stock_min, cat, marca)
        productos = [
            ('Martillo carpintero 16 oz', 'Cabo de fibra de vidrio, mango ergonómico',
             28.50, 25, 5, 'Herramientas', 'Truper'),
            ('Taladro percutor 650W', 'Velocidad variable, mandril 13mm, con brocas',
             189.90, 12, 3, 'Herramientas', 'Bosch'),
            ('Juego de destornilladores 6 pzs', 'Planos y phillips, acero CR-V',
             32.00, 30, 8, 'Herramientas', 'Stanley'),
            ('Alicate universal 8"', 'Corte lateral, aislamiento 1000V',
             24.90, 20, 5, 'Herramientas', 'Truper'),
            ('Wincha métrica 5m', 'Cinta de acero con freno automático',
             15.50, 40, 10, 'Herramientas', 'Stanley'),
            ('Pintura látex blanca 1 gl', 'Interior/exterior, alto cubrimiento',
             68.00, 18, 5, 'Pinturas', 'Truper'),
            ('Esmalte sintético azul 1/4 gl', 'Acabado brillante, secado rápido',
             32.50, 22, 6, 'Pinturas', 'Bosch'),
            ('Brocha 4" cerda mixta', 'Para pinturas al agua y esmaltes',
             6.50, 60, 15, 'Pinturas', 'Truper'),
            ('Cable eléctrico THW 2.5mm (metro)', 'Cobre, uso domiciliario',
             2.80, 500, 50, 'Electricidad', 'Bosch'),
            ('Interruptor simple 15A', 'Empotrable, color blanco',
             4.50, 80, 20, 'Electricidad', 'Stanley'),
            ('Tomacorriente doble con tierra', '15A, placa marfil',
             7.90, 45, 12, 'Electricidad', 'Truper'),
            ('Foco LED 12W luz fría', 'Rosca E27, 10,000 horas',
             9.90, 100, 25, 'Electricidad', 'Bosch'),
            ('Tubo PVC 1/2" x 3m', 'Para agua fría, presión 150 psi',
             12.00, 35, 10, 'Plomería', 'Pavco'),
            ('Codo PVC 1/2" 90°', 'Accesorio para tubería de agua',
             1.50, 120, 30, 'Plomería', 'Pavco'),
            ('Pegamento PVC 1/8 gl', 'Para unión de tuberías y accesorios',
             14.90, 25, 8, 'Plomería', 'Pavco'),
            ('Cemento Portland Tipo I, bolsa 42.5 kg', 'Uso general en construcción',
             25.50, 60, 15, 'Construcción', 'Truper'),
            ('Ladrillo King Kong 18 huecos', '23x12x9 cm, arcilla cocida',
             0.95, 2000, 500, 'Construcción', 'Stanley'),
            ('Clavos para concreto 3" (kg)', 'Acero templado',
             8.50, 40, 10, 'Construcción', 'Truper'),
            ('Alambre de amarre N°16 (kg)', 'Recocido, para estructuras',
             7.20, 55, 12, 'Construcción', 'Bosch'),
            ('Carretilla de construcción 5.5 ft³', 'Llanta neumática, bandeja metálica',
             165.00, 6, 2, 'Construcción', 'Truper'),
        ]
        for nombre, desc, precio, stock, stock_min, cat, marca in productos:
            existe = c.execute(text("SELECT 1 FROM producto WHERE nombre=:n"),
                               {'n': nombre}).fetchone()
            if existe:
                _reg('producto', False)
                continue
            c.execute(text("""
                INSERT INTO producto (nombre, descripcion, precio, stock, stock_minimo,
                                      id_categoria, id_marca, destacado, activo)
                VALUES (:n, :d, :p, :s, :sm, :cat, :mar, FALSE, TRUE)
            """), {'n': nombre, 'd': desc, 'p': precio, 's': stock, 'sm': stock_min,
                   'cat': categorias[cat], 'mar': marcas[marca]})
            _reg('producto', True)


def main():
    try:
        seed_auth()
        seed_tienda()
    except Exception as e:
        print(f'\nERROR: {e}')
        raise SystemExit(1)

    print('\n=============== RESUMEN ===============')
    tot_i = tot_e = 0
    for tabla, d in sorted(resumen.items()):
        tot_i += d['insertados']
        tot_e += d['existentes']
        print(f"  {tabla:<12} insertados: {d['insertados']:<3} ya existian: {d['existentes']}")
    print('  --------------------------------------')
    print(f"  {'TOTAL':<12} insertados: {tot_i:<3} ya existian: {tot_e}")
    print('\nCredenciales de prueba:')
    print('  admin@cleoferr.com / Admin123!       (administrador)')
    print('  vendedor@cleoferr.com / Vendedor123  (vendedor)')
    print('  maria.quispe@gmail.com / Cliente123  (cliente)')
    print('  (clientes: jose.torres@ y carmen.ruiz@ igual / Cliente123)')


if __name__ == '__main__':
    main()
