-- Migración: tablas auxiliares para códigos de verificación (Supabase / PostgreSQL)
--
-- NOTA IMPORTANTE: el código (app.py) usa la tabla `verificacion_cuenta`, no
-- `verificacion_registro`. Este archivo corrije esa discrepancia. Si tu base
-- quedó con la tabla antigua/inexistente, el registro de clientes fallaba con
-- "No se pudo iniciar el registro. Intenta de nuevo".
--
-- Puedes ejecutar esto directamente en el SQL Editor de Supabase, o bien la
-- propia app lo crea automáticamente al iniciar (_inicializar_schema_auth en app.py).

-- Tabla de códigos OTP para registro de clientes
CREATE TABLE IF NOT EXISTS verificacion_cuenta (
    id_verificacion     SERIAL PRIMARY KEY,
    id_cliente          INTEGER NOT NULL,
    codigo_hash         TEXT NOT NULL,
    creado_en           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expira_en           TIMESTAMPTZ NOT NULL,
    usado               BOOLEAN NOT NULL DEFAULT FALSE,
    intentos_fallidos   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_verificacion_cuenta_cliente
    ON verificacion_cuenta (id_cliente);

-- Tabla de códigos OTP para recuperación de contraseña
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
);

CREATE INDEX IF NOT EXISTS idx_recuperacion_usuario
    ON recuperacion_contrasena (id_usuario);
CREATE INDEX IF NOT EXISTS idx_recuperacion_cliente
    ON recuperacion_contrasena (id_cliente);

-- Limpiar registros expirados (>10 min) - ejecutar periódicamente
-- DELETE FROM verificacion_cuenta WHERE expira_en < NOW() - INTERVAL '10 minutes';

-- ────────────────────────────────────────────────────────────────────────────
-- FUNCIONALIDAD 1 – Cliente registrado desde el Punto de Venta (POS)
-- ────────────────────────────────────────────────────────────────────────────
-- `origen` distingue clientes creados desde el POS (origen='pos') de los
-- registrados por la web (origen='web', valor por defecto). Los clientes POS
-- no tienen email ni contraseña (no pueden iniciar sesión web).
-- Ejecutar en el SQL Editor de Supabase (PostgreSQL), BD Auth.
ALTER TABLE cliente
    ADD COLUMN IF NOT EXISTS origen VARCHAR(10) NOT NULL DEFAULT 'web';

-- Índice único por tipo de documento + número, para que el POS no duplique
-- clientes al repetir el mismo DNI/RUC. Se excluyen registros sin documento
-- (los clientes web aún pueden registrarse con nro_documento = '').
-- Nota: si ya existieran DUPLICADOS en producción, este CREATE fallará;
-- depúralos antes (ver AUDITORIA.md §NUEVO).
CREATE UNIQUE INDEX IF NOT EXISTS uq_cliente_documento
    ON cliente (id_tipo_documento, nro_documento)
    WHERE nro_documento IS NOT NULL AND nro_documento <> '';

-- Los clientes del Punto de Venta se registran con origen='pos' y SIN email ni
-- contrasena (no pueden iniciar sesión web; el modal POS solo pide DNI/RUC,
-- nombre y teléfono). Si la tabla `cliente` declara estas columnas como
-- NOT NULL, el INSERT de /clientes/registrar_pos falla con:
--     null value in column "email" of relation "cliente" violates not-null constraint
-- Se liberan SOLO las columnas que el código envía como NULL para el POS y que
-- el negocio no exige. El registro web y el panel admin siguen exigiendo email
-- y dirección a nivel de formulario (validación en la app), por lo que la
-- integridad de los clientes web no cambia. Idempotente: no afecta a columnas
-- que ya permiten NULL, ni elimina datos ni valores DEFAULT.
ALTER TABLE cliente ALTER COLUMN email DROP NOT NULL;
ALTER TABLE cliente ALTER COLUMN contrasena DROP NOT NULL;
ALTER TABLE cliente ALTER COLUMN telefono DROP NOT NULL;
ALTER TABLE cliente ALTER COLUMN direccion DROP NOT NULL;