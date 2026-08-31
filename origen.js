/**
 * origen.js - Servidor Backend Receptor de Webhooks
 * Dominio: recopilidardeinformacion-maps-beta.vercel.app
 *
 * Este servidor se encarga de recibir notificaciones de webhook firmadas procedentes
 * de la pasarela externa (webpasarelahook-beta.vercel.app), validar su firma HMAC-SHA256,
 * garantizar la idempotencia de los eventos y almacenar la información en una base de datos local.
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Clave secreta compartida para validar las firmas HMAC del webhook
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'secreto_compartido_super_seguro';

/**
 * Base de datos local simulada en memoria.
 * - processedEvents: Set para almacenar los IDs de eventos procesados y garantizar la idempotencia.
 * - database: Array para almacenar los registros de datos validados.
 */
const processedEvents = new Set();
const database = [];

// Middleware de CORS para permitir solicitudes desde el frontend u orígenes cruzados
app.use(cors());

/**
 * Captura del Raw Body:
 * Configuración del middleware express.json() para preservar el búfer original (req.rawBody).
 * Conservar el Raw Body exacto es imprescindible para recalcular el digest HMAC-SHA256
 * de forma identica a la firmada por el emisor.
 */
app.use(
  express.json({
    verify: (req, res, buf, encoding) => {
      if (buf && buf.length) {
        req.rawBody = buf;
      } else {
        req.rawBody = Buffer.from('');
      }
    }
  })
);

// Servir archivos estáticos (incluyendo index.html) desde la raíz
app.use(express.static(__dirname));

/**
 * ENDPOINT DEL WEBHOOK
 * POST /api/v1/webhook
 *
 * Recibe y procesa las notificaciones enviadas por la pasarela externa.
 */
app.post('/api/v1/webhook', (req, res) => {
  try {
    // 1. Extraer cabecera de firma
    const signatureHeader = req.headers['x-signature'];

    if (!signatureHeader) {
      return res.status(401).json({
        success: false,
        error: 'Cabecera de firma X-Signature no proporcionada.'
      });
    }

    // Asegurar disponibilidad del cuerpo en formato raw
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));

    // 2. Seguridad: Recalcular firma HMAC-SHA256 con la clave secreta
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    hmac.update(rawBody);
    const computedSignature = hmac.digest('hex');

    // Normalizar firmas para comparación segura
    const sigBuffer = Buffer.from(signatureHeader, 'utf8');
    const computedBuffer = Buffer.from(computedSignature, 'utf8');

    // Comparación en tiempo constante usando crypto.timingSafeEqual para prevenir ataques de tiempo
    if (sigBuffer.length !== computedBuffer.length || !crypto.timingSafeEqual(sigBuffer, computedBuffer)) {
      return res.status(401).json({
        success: false,
        error: 'Firma X-Signature inválida. La petición no proviene de un emisor autorizado.'
      });
    }

    // 3. Extraer datos de la notificación
    const { event_id, transaction_id, texto1, texto2 } = req.body;

    if (!event_id) {
      return res.status(400).json({
        success: false,
        error: 'Falta el identificador único del evento (event_id).'
      });
    }

    // 4. Idempotencia: Verificar si el evento ya fue procesado previamente
    if (processedEvents.has(event_id)) {
      // Retornar 200 OK inmediatamente indicando que ya fue procesado sin duplicar registros
      return res.status(200).json({
        success: true,
        message: 'Evento duplicado detectado. Ya procesado anteriormente.',
        event_id: event_id,
        duplicate: true
      });
    }

    // Registrar el event_id para prevenir duplicados futuros
    processedEvents.add(event_id);

    // 5. Persistencia: Almacenar la información validada en la base de datos local
    const record = {
      event_id: event_id,
      transaction_id: transaction_id || `tx_${Date.now()}`,
      texto1: texto1 || '',
      texto2: texto2 || '',
      received_at: new Date().toISOString()
    };

    database.push(record);

    // 6. Respuesta HTTP 200 OK tras el procesamiento exitoso
    return res.status(200).json({
      success: true,
      message: 'Notificación de webhook procesada y almacenada correctamente.',
      data: record
    });

  } catch (error) {
    console.error('Error al procesar el webhook:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno al procesar la notificación de webhook.'
    });
  }
});

/**
 * ENDPOINT DE CONSULTA DE DATOS
 * GET /sistema/datos
 *
 * Permite consultar los registros almacenados en la base de datos local en formato JSON.
 */
app.get('/sistema/datos', (req, res) => {
  return res.status(200).json({
    success: true,
    total_records: database.length,
    records: database
  });
});

// Iniciar el servidor HTTP si no está siendo importado por pruebas
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor de Página Origen escuchando en http://localhost:${PORT}`);
  });
}

module.exports = app;
