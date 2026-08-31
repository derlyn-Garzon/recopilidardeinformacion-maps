const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const app = require('./origen');

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'secreto_compartido_super_seguro';

describe('Servidor Origen - Pruebas de Webhook e Idempotencia', () => {
  let server;
  let baseUrl;

  test('Iniciar servidor de pruebas', (t, done) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://localhost:${port}`;
      done();
    });
  });

  test('Rechazar peticiones sin cabecera X-Signature (401)', async () => {
    const response = await fetch(`${baseUrl}/api/v1/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_id: 'evt_1', texto1: 'hola', texto2: 'mundo' })
    });

    assert.equal(response.status, 401);
    const data = await response.json();
    assert.equal(data.success, false);
    assert.match(data.error, /X-Signature/);
  });

  test('Rechazar peticiones con firma X-Signature inválida (401)', async () => {
    const payload = JSON.stringify({ event_id: 'evt_2', texto1: 'invalid', texto2: 'sig' });
    const response = await fetch(`${baseUrl}/api/v1/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': 'firma_totalmente_incorrecta_1234567890abcdef1234567890abcdef1234567890abcdef'
      },
      body: payload
    });

    assert.equal(response.status, 401);
    const data = await response.json();
    assert.equal(data.success, false);
  });

  test('Aceptar y procesar petición con firma HMAC-SHA256 válida (200)', async () => {
    const payloadObj = {
      event_id: 'evt_100',
      transaction_id: 'tx_100',
      texto1: 'Ubicación Central',
      texto2: 'Punto de Interés A'
    };
    const payloadStr = JSON.stringify(payloadObj);

    const validSignature = crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(Buffer.from(payloadStr))
      .digest('hex');

    const response = await fetch(`${baseUrl}/api/v1/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': validSignature
      },
      body: payloadStr
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.success, true);
    assert.equal(data.data.event_id, 'evt_100');
    assert.equal(data.data.texto1, 'Ubicación Central');
    assert.equal(data.data.texto2, 'Punto de Interés A');
  });

  test('Manejar la idempotencia reconociendo event_id duplicado (200 sin duplicar)', async () => {
    const payloadObj = {
      event_id: 'evt_100', // Mismo event_id
      transaction_id: 'tx_100',
      texto1: 'Ubicación Central',
      texto2: 'Punto de Interés A'
    };
    const payloadStr = JSON.stringify(payloadObj);

    const validSignature = crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(Buffer.from(payloadStr))
      .digest('hex');

    const response = await fetch(`${baseUrl}/api/v1/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': validSignature
      },
      body: payloadStr
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.success, true);
    assert.equal(data.duplicate, true);
    assert.match(data.message, /duplicado/i);
  });

  test('Consultar registros mediante GET /sistema/datos', async () => {
    const response = await fetch(`${baseUrl}/sistema/datos`);
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.success, true);
    assert.equal(data.total_records, 1);
    assert.equal(data.records[0].event_id, 'evt_100');
  });

  test('Cerrar servidor de pruebas', (t, done) => {
    server.close(done);
  });
});
