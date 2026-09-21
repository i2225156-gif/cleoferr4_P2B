-- ============================================================
-- CLEOFERR – Tablas para flujo de pago completo
-- PostgreSQL / Supabase – ejecutar sobre la BD TIENDA
-- ============================================================

-- 1. Columna usada por el codigo (app.py: INSERT INTO venta ... num_operacion)
ALTER TABLE venta
  ADD COLUMN IF NOT EXISTS num_operacion VARCHAR(60);

-- NOTA: el script original agregaba `metodo_pago` ENUM y modificaba el ENUM
-- `estado` de venta. En el esquema real eso NO existe: el metodo de pago se
-- registra en la tabla `pago` (FK a `tipo_pago`) y el estado en la tabla
-- catalogo `estado_venta` (venta.id_estado_venta). Se eliminan esos ALTERs
-- porque no coinciden con lo que usa app.py.

-- 2. Tabla comprobante (columnas exactas que usa app.py:
--    INSERT INTO comprobante (id_venta, id_tipo_comprobante, numero, ruc))
CREATE TABLE IF NOT EXISTS comprobante (
    id_comprobante      INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id_venta            INTEGER,
    id_tipo_comprobante INTEGER,
    numero              VARCHAR(30),
    ruc                 VARCHAR(11),
    fecha_emision       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_venta)            REFERENCES venta(id_venta)                      ON DELETE SET NULL,
    FOREIGN KEY (id_tipo_comprobante) REFERENCES tipo_comprobante(id_tipo_comprobante) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_comprobante_venta ON comprobante (id_venta);
