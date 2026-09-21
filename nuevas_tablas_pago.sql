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

-- 3. Estados ampliados de pedido en el catálogo estado_venta (BD TIENDA).
--    app.py lee los estados válidos de esta tabla (ORDER BY orden), así que
--    basta con insertarlos para habilitar procesando/enviado/cancelado sin
--    tocar código. Idempotente: no duplica si ya existen.
INSERT INTO estado_venta (nombre, orden, activo)
SELECT v.nombre, v.orden, TRUE
FROM (VALUES
    ('pendiente',  1),
    ('confirmado', 2),
    ('procesando', 3),
    ('enviado',    4),
    ('entregado',  5),
    ('cancelado',  6)
) AS v(nombre, orden)
WHERE NOT EXISTS (SELECT 1 FROM estado_venta e WHERE e.nombre = v.nombre);

-- 4. Tipos de comprobante usados por las numeraciones B/F (BD TIENDA)
INSERT INTO tipo_comprobante (nombre)
SELECT v.nombre
FROM (VALUES ('boleta'), ('factura')) AS v(nombre)
WHERE NOT EXISTS (SELECT 1 FROM tipo_comprobante t WHERE t.nombre = v.nombre);

-- 5. Comprobantes INTERNOS (fase de prueba, sin integración SUNAT real)
--    - `serie`: B001 (boleta) | F001 (factura).
--    - `estado_sunat`: 'no_aplica' = comprobante interno de prueba; cuando se
--      conecte un PSE (Nubefact/Facturador SUNAT) pasará a 'pendiente'/'enviado'.
ALTER TABLE comprobante
  ADD COLUMN IF NOT EXISTS serie VARCHAR(4),
  ADD COLUMN IF NOT EXISTS estado_sunat VARCHAR(12) DEFAULT 'no_aplica'
    CHECK (estado_sunat IN ('pendiente','no_aplica','enviado'));
