"""Migración puntual: permite NULL en cliente.nro_documento (BD Auth).

Motivo: la columna tenía NOT NULL + UNIQUE(id_tipo_documento, nro_documento),
lo que impedía más de un registro web sin documento (insertar '' chocaba
con la clave única; insertar NULL chocaba con el NOT NULL).
En PostgreSQL los NULL no chocan entre sí en índices UNIQUE.
"""
from sqlalchemy import text
from db_supabase import engine_auth

with engine_auth.begin() as c:
    c.execute(text("ALTER TABLE cliente ALTER COLUMN nro_documento DROP NOT NULL"))
    r = c.execute(text("""
        SELECT is_nullable FROM information_schema.columns
        WHERE table_name = 'cliente' AND column_name = 'nro_documento'
    """)).fetchone()
    print("nro_documento is_nullable ahora:", r[0])
