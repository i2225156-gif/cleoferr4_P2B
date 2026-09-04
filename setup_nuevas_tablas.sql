-- ============================================================
-- CLEOFERR - Script para nuevas tablas: cliente, proveedor, inventario
-- Ejecutar en PhpMyAdmin sobre la BD: tienda_online
-- ============================================================

-- 1. Asegurarse de que la tabla cliente tenga las columnas necesarias
ALTER TABLE `cliente`
  ADD COLUMN IF NOT EXISTS `telefono` varchar(20) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `direccion` varchar(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `contrasena` varchar(255) DEFAULT NULL;

-- 2. Tabla de proveedores
CREATE TABLE IF NOT EXISTS `proveedor` (
    `id_proveedor` INT AUTO_INCREMENT PRIMARY KEY,
    `nombre`       VARCHAR(150) NOT NULL,
    `contacto`     VARCHAR(100) DEFAULT NULL,
    `telefono`     VARCHAR(20)  DEFAULT NULL,
    `email`        VARCHAR(100) DEFAULT NULL,
    `direccion`    VARCHAR(255) DEFAULT NULL,
    `creado_en`    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Tabla de movimientos de inventario
CREATE TABLE IF NOT EXISTS `inventario_movimiento` (
    `id_movimiento`    INT AUTO_INCREMENT PRIMARY KEY,
    `tipo`             ENUM('entrada', 'salida') NOT NULL,
    `id_producto`      INT NOT NULL,
    `id_proveedor`     INT DEFAULT NULL,
    `cantidad`         INT NOT NULL,
    `precio_unitario`  DECIMAL(10,2) DEFAULT 0.00,
    `stock_resultante` INT NOT NULL,
    `observacion`      TEXT DEFAULT NULL,
    `id_usuario`       INT DEFAULT NULL,
    `fecha`            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`id_producto`) REFERENCES `producto`(`id_producto`) ON DELETE CASCADE,
    FOREIGN KEY (`id_proveedor`) REFERENCES `proveedor`(`id_proveedor`) ON DELETE SET NULL,
    FOREIGN KEY (`id_usuario`) REFERENCES `usuario`(`id_usuario`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Proveedores de ejemplo
INSERT INTO `proveedor` (nombre, contacto, telefono, email, direccion) VALUES
  ('Ferretería Central SAC', 'Juan Quispe', '987654321', 'jquispe@ferrcentral.pe', 'Av. Industrial 345, Lima'),
  ('Distribuidora El Constructor', 'María López', '976543210', 'mlopez@elconstructor.pe', 'Jr. Materiales 123, Lima'),
  ('Importaciones TecnoFerr', 'Carlos Ramos', '965432109', 'cramos@tecnoferr.pe', 'Calle Progreso 789, Lima');
