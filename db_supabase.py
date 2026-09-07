"""Módulo de acceso a datos unificado sobre Supabase (PostgreSQL).

Expone dos engines SQLAlchemy separados:

- ``engine_auth``: BD de autenticación (tablas: usuario, cliente, rol, sesion).
- ``engine_tienda``: BD de la tienda (tablas: producto, venta, detalle_venta,
  inventario_movimiento, categoria, marca, proveedor, caja, alertas, etc.).

Cada engine se construye a partir de su propia variable de entorno:
``DATABASE_URI_AUTH`` y ``DATABASE_URI_TIENDA``. No existe una DATABASE_URI
genérica: cada módulo de la aplicación debe usar el engine que corresponda.
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()

_ENGINE_OPTIONS = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_timeout": 30,
}


def _crear_engine(nombre_var):
    uri = os.environ.get(nombre_var)
    if not uri:
        raise RuntimeError(
            f"{nombre_var} no definida en el archivo .env. "
            "Esta aplicación requiere dos URIs de Supabase (Auth y Tienda) "
            "configuradas por separado."
        )
    return create_engine(uri, **_ENGINE_OPTIONS)


# Engine para la BD de autenticación (usuario, cliente, rol, sesion)
engine_auth = _crear_engine("DATABASE_URI_AUTH")

# Engine para la BD de la tienda (producto, venta, inventario, caja, etc.)
engine_tienda = _crear_engine("DATABASE_URI_TIENDA")


def get_connection_auth():
    """Devuelve una conexión DBAPI de la BD de autenticación."""
    return engine_auth.raw_connection()


def get_connection_tienda():
    """Devuelve una conexión DBAPI de la BD de la tienda."""
    return engine_tienda.raw_connection()
