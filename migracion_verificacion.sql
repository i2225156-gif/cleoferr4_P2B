-- Migración: tabla para códigos de verificación de registro (opcional si usas sesión)
-- PostgreSQL / Supabase – BD de AUTENTICACION
-- NOTA: actualmente app.py guarda el código en la sesión Flask y NO usa esta
-- tabla; solo es necesaria si se prefiere persistencia en BD.

CREATE TABLE IF NOT EXISTS verificacion_registro (
    id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correo     VARCHAR(255) NOT NULL,
    codigo     CHAR(6) NOT NULL,
    nombre     VARCHAR(200),
    apellido   VARCHAR(100),
    telefono   VARCHAR(20),
    hash_pw    TEXT NOT NULL,
    creado_en  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verif_correo ON verificacion_registro (correo);

-- Limpiar registros expirados (>10 min) - ejecutar periódicamente
-- DELETE FROM verificacion_registro WHERE creado_en < CURRENT_TIMESTAMP - INTERVAL '10 minutes';
