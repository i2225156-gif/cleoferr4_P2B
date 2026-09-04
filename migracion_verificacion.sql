-- Migración: tabla para códigos de verificación de registro (opcional si usas sesión)
-- Si prefieres persistencia en DB en lugar de sesión Flask, usa esta tabla:

CREATE TABLE IF NOT EXISTS verificacion_registro (
    id INT AUTO_INCREMENT PRIMARY KEY,
    correo VARCHAR(255) NOT NULL,
    codigo CHAR(6) NOT NULL,
    nombre VARCHAR(200),
    apellido VARCHAR(100),
    telefono VARCHAR(20),
    hash_pw TEXT NOT NULL,
    creado_en DATETIME DEFAULT NOW(),
    INDEX idx_correo (correo)
);

-- Limpiar registros expirados (>10 min) - ejecutar periódicamente
-- DELETE FROM verificacion_registro WHERE creado_en < NOW() - INTERVAL 10 MINUTE;
