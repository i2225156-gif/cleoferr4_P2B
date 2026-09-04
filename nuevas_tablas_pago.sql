-- ============================================================
-- CLEOFERR – Tablas para flujo de pago completo
-- Ejecutar en phpMyAdmin sobre la BD: prueba-cleofer_tienda_online
-- ============================================================

-- 1. Agregar columnas a venta si no existen
ALTER TABLE `venta`
  ADD COLUMN IF NOT EXISTS `metodo_pago` ENUM('tarjeta','yape_plin','efectivo') DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `num_operacion` VARCHAR(60) DEFAULT NULL;

-- 2. Tabla comprobante (si no existe)
CREATE TABLE IF NOT EXISTS `comprobante` (
  `id_comprobante` int(11) NOT NULL AUTO_INCREMENT,
  `id_venta`       int(11) DEFAULT NULL,
  `tipo`           enum('boleta','factura') DEFAULT 'boleta',
  `tipo_boleta`    enum('simple','electronica') DEFAULT 'simple',
  `ruc_cliente`    varchar(11) DEFAULT NULL,
  `numero`         varchar(30) DEFAULT NULL,
  `enviado_correo` tinyint(1) DEFAULT 0,
  `fecha_emision`  datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id_comprobante`),
  KEY `fk_comp_venta` (`id_venta`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Agregar estado 'preparando' y 'listo' al ENUM de venta si no existen
-- (MariaDB / MySQL: modificar ENUM)
ALTER TABLE `venta`
  MODIFY COLUMN `estado` ENUM('pendiente','confirmado','preparando','listo','entregado','cancelado') DEFAULT 'pendiente';

