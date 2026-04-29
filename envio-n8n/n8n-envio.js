/**
 * 
 */
require('dotenv').config();

const express = require('express');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const app = express();
app.use(express.json({ limit: '10mb'}));

/**
 * ===== Configurações =====
 */
const CLIENT_NAME = process.env.CLIENT_NAME;
const CLIENT_GROUP_ID = process.env.CLIENT_GROUP_ID;
const CLIENT_CHANNEL = process.env.CLIENT_CHANNEL;
const API_URL = process.env.API_URL;
const API_TOKEN = process.env.API_TOKEN;
const WAZUH_MIN_LVL = parseInt(process.env.WAZUH_MIN_LVL) || 3;

/**
 * ===== Utilitários =====
 */
function getLocalIP(){
    const interfaces = os.networkInterfaces();

    for (const name of Object.keys(interfaces)){
        for (const iface of interfaces[name]){
            if (iface.family === 'IPv4' && !iface.internal){
                return iface.address;
            }
        }
    }
    return '0.0.0.0';
}

/**
 * ===== Endpoints =====
 */
app.post('/alert', async (req, res)=> {
    const payload = createPayload(req.body);

    console.log('📦 Payload pronto', JSON.stringify(payload, null, 2));

    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');

    const signature = generateSignature(payload, timestamp, nonce);

    const headers = {
        'x-timestamp': timestamp,
        'x-nonce': nonce,
        'x-signature': signature,
    };
    try{
        const response = await sendToN8N(payload, headers);

        console.log('ℹ️ Resposta do n8n:', response.status, response.body);

        if (response.status >= 200 && response.status < 300){
            return res.status(200).json({
                ok:true,
                forwarded: true,
                n8nStatus: response.status
            });
        }

        console.error("⚠️ n8n respondeu com erro:", response.status);

        return res.status(502).json({
            ok:false,
            error: 'n8n_bad_response',
            n8nStatus: response.status 
        });

    }catch (err){
        console.error("ℹ️ Falha ao enviar para n8n:",err.message);

        return res.status(500).json({
            ok:false,
            error: "n8n_unreachable"
        });
    }
});

/**
 * ===== Validação de Input =====
 */
function validadeInput(body){
    if (!body) return{valid:false, reason:'empty_body'};

    if (!body.rule || typeof body.rule.level === 'undefined'){
        return {valid:false, reason: 'missing_rule_level'};
    }

    return {valid:true};
}

/**
 * ==== Regras de processamento =====
 */
function shouldProcess(alert){
    return alert.rule.level >= WAZUH_MIN_LVL;
}

/**
 * ==== Função payload =====
 */
function createPayload(alert){
    return{
        client:{
            name: CLIENT_NAME,
            group_id: CLIENT_GROUP_ID,
            channel: CLIENT_CHANNEL,
        },
        machine:{
            ip: getLocalIP(),
            hostname: os.hostname(),
        },
        alert: alert,
        meta:{
            receivedAt: new Date().toISOString(),
        }
    };
}

/**
 * ==== Assinatura =====
 */
function generateSignature(payload, timestamp, nonce){
    const data = JSON.stringify(payload) + timestamp + nonce;

    return crypto
        .createHmac('sha256', API_TOKEN)
        .update(data)
        .digest('hex');
}

/**
 * ==== Envio para n8n =====
 */
function sendToN8N(payload, headers){
    return new Promise((resolve,reject) =>{
        const url = new URL(API_URL);

        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers:{
                'Content-Type': 'application/json',
                ...headers,
            }
        };
        const client = url.protocol === 'https:' ? https : http;

        const req = client.request(options, (res) => {
            let data = '';

            res.on('data',chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    body:data
                });
            });
        });
        req.on('error', reject);

        req.write(JSON.stringify(payload));
        req.end();
    });
}

/**
 * ===== Inicialização =====
 */
app.listen(10080,() => {
    console.log('🖥️ Servidor rodando na porta 10080');
})