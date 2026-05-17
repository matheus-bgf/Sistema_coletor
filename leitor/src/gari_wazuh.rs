/*
 * Bibliotecas externas
 */
use dashmap::DashMap;

use lazy_static::lazy_static;

use serde_json::{
    Value,
    json
};

use reqwest::blocking::Client;

/*
 * Bibliotecas padrão
 */
use std::fs::OpenOptions;

use std::io::{
    BufRead,
    BufReader,
    Seek,
    SeekFrom,
    Read
};

use std::thread;

use std::time::{
    Duration,
    Instant
};

use std::sync::atomic::{
    AtomicBool,
    Ordering
};

use std::sync::{
    Arc,
    Mutex
};

/*
 * Controle de logs
 */
const DEBUG_LOGS: bool = false;

/*
 * Tempo de deduplicação
 * 1 hora
 */
const DEDUP_TTL_SECONDS: u64 = 3600;

macro_rules! log_info {
    ($($arg:tt)*) => {
        if DEBUG_LOGS {
            println!($($arg)*);
        }
    };
}

macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

/*
 * Estruturas globais
 */
lazy_static! {

    /*
     * Controle de execução
     */
    static ref RUNNING:
        Mutex<Option<Arc<AtomicBool>>> =
            Mutex::new(None);

    /*
     * Cache de deduplicação
     */
    static ref SENT_ALERTS:
        DashMap<String, Instant> =
            DashMap::new();

    /*
     * Controle da última limpeza
     */
    static ref LAST_CLEANUP:
        Mutex<Instant> =
            Mutex::new(Instant::now());

    /*
     * Cliente HTTP reutilizável
     */
    static ref HTTP_CLIENT: Client =
        Client::builder()
            .timeout(
                Duration::from_secs(5)
            )
            .pool_idle_timeout(
                Duration::from_secs(30)
            )
            .pool_max_idle_per_host(10)
            .build()
            .expect(
                "Falha ao criar HTTP Client"
            );
}

/*
 * Inicializa listener
 */
pub fn start() {

    let running =
        Arc::new(
            AtomicBool::new(true)
        );

    {
        let mut guard =
            RUNNING
                .lock()
                .unwrap();

        *guard =
            Some(
                running.clone()
            );
    }

    thread::spawn(move || {

        start_wazuh_listener(
            running
        );

        println!(
            "Gari Wazuh apostos"
        );
    });
}

/*
 * Finaliza listener
 */
pub fn stop() {

    let guard =
        RUNNING
            .lock()
            .unwrap();

    if let Some(running) =
        guard.as_ref()
    {

        running.store(
            false,
            Ordering::Relaxed
        );
    }
}

/*
 * Loop principal do listener
 */
pub fn start_wazuh_listener(
    running: Arc<AtomicBool>
) {

    let path =
        "/var/ossec/logs/alerts/alerts.json";

    while running.load(
        Ordering::Relaxed
    ) {

        match open_stream(path) {

            Ok(_) => {

                thread::sleep(
                    Duration::from_secs(5)
                );
            }

            Err(e) => {

                log_error!(
                    "[Wazuh] ERRO STREAM: {}",
                    e
                );

                thread::sleep(
                    Duration::from_secs(5)
                );
            }
        }
    }
}

/*
 * Abre stream contínuo do alerts.json
 * Tolerante a UTF-8 inválido
 * e linhas parcialmente escritas
 */
fn open_stream(
    path: &str
) -> std::io::Result<()> {

    let mut file =
        OpenOptions::new()
            .read(true)
            .open(path)?;

    file.seek(
        SeekFrom::End(0)
    )?;

    let mut reader =
        BufReader::new(file);

    loop {

        let mut buffer =
            Vec::new();

        match reader.read_until(
            b'\n',
            &mut buffer
        ) {

            Ok(0) => {

                thread::sleep(
                    Duration::from_millis(200)
                );
            }

            Ok(_) => {

                /*
                 * Conversão tolerante UTF-8
                 */
                let line =
                    String::from_utf8_lossy(
                        &buffer
                    );

                let line =
                    line.trim();

                /*
                 * Ignora linhas vazias
                 */
                if line.is_empty() {
                    continue;
                }

                /*
                 * Ignora JSON incompleto
                 * parcialmente escrito
                 */
                if !line.starts_with('{')
                    || !line.ends_with('}')
                {
                    log_info!(
                        "[Wazuh] JSON parcial ignorado"
                    );

                    continue;
                }

                /*
                 * Pequeno delay para
                 * evitar corrida de escrita
                 */
                thread::sleep(
                    Duration::from_millis(50)
                );

                handle_event(line);
            }

            Err(e) => {

                log_error!(
                    "[Wazuh] ERRO STREAM: {}",
                    e
                );

                break;
            }
        }
    }

    Ok(())
}

/*
 * Processa evento
 */
fn handle_event(line: &str) {

    let parsed: Value =
        match serde_json::from_str(line) {

            Ok(v) => v,

            Err(e) => {

                log_error!(
                    "[Wazuh] JSON inválido: {}",
                    e
                );

                return;
            }
        };

    let rule_id =
        parsed["rule"]["id"]
            .as_str()
            .unwrap_or("unknown");

    let agent_name =
        parsed["agent"]["name"]
            .as_str()
            .unwrap_or("unknown");

    let dedup_key =
        format!(
            "{}:{}",
            rule_id,
            agent_name
        );

    if is_duplicate(&dedup_key) {

        log_info!(
            "[Wazuh] ALERTA DUPLICADO IGNORADO: {}",
            dedup_key
        );

        return;
    }

    cleanup_old_entries();

    send_to_n8n(parsed);
}

/*
 * Verifica duplicidade
 */
fn is_duplicate(key: &str) -> bool {

    let now = Instant::now();

    if let Some(entry) = SENT_ALERTS.get(key) {

        /*
         * Ignora alertas repetidos
         * dentro de 1 hora
         */
        if now.duration_since(*entry.value())
            < Duration::from_secs(DEDUP_TTL_SECONDS)
        {
            return true;
        }
    }

    SENT_ALERTS.insert(
        key.to_string(),
        now
    );

    false
}

/*
 * Limpa cache antigo
 */
fn cleanup_old_entries() {

    let mut last_cleanup =
        LAST_CLEANUP
            .lock()
            .unwrap();

    /*
     * Executa limpeza
     * apenas a cada 1 hora
     */
    if last_cleanup.elapsed()
        < Duration::from_secs(DEDUP_TTL_SECONDS)
    {
        return;
    }

    let now = Instant::now();

    SENT_ALERTS.retain(|_, v| {

        /*
         * Mantém entradas
         * por até 1 hora
         */
        now.duration_since(*v)
            < Duration::from_secs(DEDUP_TTL_SECONDS)
    });

    *last_cleanup = Instant::now();
}

/*
 * Envia para n8n
 */
fn send_to_n8n(payload: Value) {

    let webhook_url =
        std::env::var("N8N_WEBHOOK")
            .unwrap_or_default();

    if webhook_url.is_empty() {

        log_error!(
            "[Wazuh] N8N_WEBHOOK não definido"
        );

        return;
    }

    match HTTP_CLIENT
        .post(&webhook_url)
        .json(&payload)
        .send()
    {

        Ok(response) => {

            log_info!(
                "[Wazuh] Evento enviado: {}",
                response.status()
            );
        }

        Err(e) => {

            log_error!(
                "[Wazuh] Falha envio n8n: {}",
                e
            );
        }
    }
}