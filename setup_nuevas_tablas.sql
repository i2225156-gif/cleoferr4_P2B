-- ============================================================
-- CLEOFERR - Script para nuevas tablas: cliente, proveedor, inventario
-- PostgreSQL / Supabase
-- NOTA: la tabla `cliente` vive en la BD de AUTENTICACION (engine_auth);
--       `proveedor` e `inventario_movimiento` en la BD TIENDA (engine_tienda).
--       Ejecutar cada seccion en la base correspondiente.
-- ============================================================

-- ── BD AUTH ─────────────────────────────────────────────────
-- 1. Asegurarse de que la tabla cliente tenga las columnas necesarias
ALTER TABLE cliente
  ADD COLUMN IF NOT EXISTS telefono   VARCHAR(20),
  ADD COLUMN IF NOT EXISTS direccion  VARCHAR(255),
  ADD COLUMN IF NOT EXISTS contrasena VARCHAR(255);

-- ── BD TIENDA ───────────────────────────────────────────────
-- 2. Tabla de proveedores
CREATE TABLE IF NOT EXISTS proveedor (
    id_proveedor INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nombre       VARCHAR(150) NOT NULL,
    contacto     VARCHAR(100),
    telefono     VARCHAR(20),
    email        VARCHAR(100),
    direccion    VARCHAR(255),
    creado_en    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabla de movimientos de inventario
--    ENUM -> VARCHAR + CHECK constraint
--    NOTA: no se crea FK id_usuario -> usuario porque `usuario` esta en la
--    BD de autenticacion y PostgreSQL no permite FKs entre bases distintas.
CREATE TABLE IF NOT EXISTS inventario_movimiento (
    id_movimiento    INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tipo             VARCHAR(10) NOT NULL CHECK (tipo IN ('entrada', 'salida')),
    id_producto      INTEGER NOT NULL,
    id_proveedor     INTEGER,
    cantidad         INTEGER NOT NULL,
    precio_unitario  NUMERIC(10,2) DEFAULT 0.00,
    stock_resultante INTEGER NOT NULL,
    observacion      TEXT,
    id_usuario       INTEGER,   -- referencia logica a auth.usuario (sin FK)
    fecha            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_producto)  REFERENCES producto(id_producto)   ON DELETE CASCADE,
    FOREIGN KEY (id_proveedor) REFERENCES proveedor(id_proveedor) ON DELETE SET NULL
);

-- 4. Proveedores de ejemplo
INSERT INTO proveedor (nombre, contacto, telefono, email, direccion) VALUES
  ('Ferretería Central SAC', 'Juan Quispe', '987654321', 'jquispe@ferrcentral.pe', 'Av. Industrial 345, Lima'),
  ('Distribuidora El Constructor', 'María López', '976543210', 'mlopez@elconstructor.pe', 'Jr. Materiales 123, Lima'),
  ('Importaciones TecnoFerr', 'Carlos Ramos', '965432109', 'cramos@tecnoferr.pe', 'Calle Progreso 789, Lima');
