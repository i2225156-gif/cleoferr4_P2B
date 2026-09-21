"""Prueba aislada de las credenciales SMTP, sin pasar por Flask.

Uso:
    python test_smtp.py

Lee SMTP_USER y SMTP_PASS del .env y trata de conectarse a Gmail.
Muestra el motivo exacto si falla.
"""
import os
import smtplib
import ssl
from dotenv import load_dotenv

load_dotenv()

smtp_user = os.environ.get('SMTP_USER', '').strip()
smtp_pass_raw = os.environ.get('SMTP_PASS', '')
smtp_pass = smtp_pass_raw.replace(' ', '').strip()

print("=" * 60)
print(f"SMTP_USER leído : {smtp_user!r}")
print(f"SMTP_PASS leído : {'*' * (len(smtp_pass) - 4)}{smtp_pass[-4:]!s}"
      if len(smtp_pass) >= 4 else f"SMTP_PASS leído : {smtp_pass!r}")
print(f"Longitud de SMTP_PASS (sin espacios): {len(smtp_pass)} caracteres")
if smtp_pass_raw != smtp_pass.replace('', smtp_pass):
    pass
print(f"¿Tenía espacios en el .env?: {' ' in smtp_pass_raw}")
print("=" * 60)

if len(smtp_pass) != 16:
    print(f"\n⚠️  AVISO: una contraseña de aplicación de Gmail debe tener "
          f"EXACTAMENTE 16 caracteres. La tuya tiene {len(smtp_pass)}.\n"
          f"   Revisa que la copiaste completa y sin cortar.\n")

if not smtp_user or not smtp_pass:
    print("❌ Falta SMTP_USER o SMTP_PASS en el .env. Revisa el archivo.")
    raise SystemExit(1)

print("\nIntentando conectar por SSL (puerto 465)...")
try:
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15,
                              context=ssl.create_default_context())
    server.login(smtp_user, smtp_pass)
    print("✅ ¡Login exitoso por SSL 465! Las credenciales están correctas.")
    server.quit()
except smtplib.SMTPAuthenticationError as e:
    print(f"❌ Gmail RECHAZÓ las credenciales.\n   Detalle: {e}\n")
    print("   Causas más comunes:")
    print("   1. La contraseña de aplicación no corresponde a esta cuenta")
    print("      (SMTP_USER debe ser la MISMA cuenta donde la generaste).")
    print("   2. La verificación en 2 pasos no está realmente activa.")
    print("   3. La contraseña de aplicación fue borrada/revocada después de generarla.")
    print("   4. Se copió mal (falta algún caracter, o incluye algo extra).")
except Exception as e:
    print(f"⚠️  No se pudo ni conectar (antes de intentar el login): {e}")
