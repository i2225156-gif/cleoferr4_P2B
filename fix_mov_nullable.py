from dotenv import load_dotenv
load_dotenv()
from db_supabase import engine_tienda
from sqlalchemy import text
with engine_tienda.begin() as c:
    c.execute(text("ALTER TABLE inventario_movimiento ALTER COLUMN id_usuario DROP NOT NULL"))
    r = c.execute(text("""SELECT is_nullable FROM information_schema.columns
        WHERE table_name='inventario_movimiento' AND column_name='id_usuario'""")).fetchone()
    print("id_usuario nullable ahora:", r[0])
    # ¿quedó residuo de la venta fallida 43?
    print("venta 43 existe?:", c.execute(text("SELECT COUNT(*) FROM venta WHERE id_venta=43")).fetchone()[0])
