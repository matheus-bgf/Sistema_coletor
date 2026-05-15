/*
 * Bibliotecas externas
 */
use dashmap::DashMap;

use lazy_static::lazy_static;

use serde_json::Value;

use reqwest::blocking::Client;

/*
 * Bibliotecas padrão
 */
use std::fs::OpenOptions;

use std::io::{
    BufRead,
    BufReader,
    Seek,
    SeekFrom
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

        let mut line =
            String::new();

        match reader.read_line(&mut line) {

            Ok(0) => {

                thread::sleep(
                    Duration::from_millis(200)
                );
            }

            Ok(_) => {

                let line =
                    line.trim();

                if !line.is_empty() {

                    handle_event(line);
                }
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
 * Processa eventos
 */
fn handle_event(
    line: &str
) {

    /*
     * Filtro rápido
     */
    if !line.contains("\"rule\"") {

        return;
    }

    /*
     * Parse JSON tolerante
     */
    let parsed: Value =
        match serde_json::from_str(line) {

            Ok(v) => v,

            Err(_) => {

                return;
            }
        };

    /*
     * Nível
     */
    let level =
        parsed["rule"]["level"]
            .as_i64()
            .unwrap_or(0);

    /*
     * Ignora alertas baixos
     */
    if level < 3 {

        return;
    }

    /*
     * Rule ID
     */
    let rule_id =
        parsed["rule"]["id"]
            .as_str()
            .unwrap_or("")
            .trim();

    /*
     * Agent name
     */
    let agent_name =
        parsed["agent"]["name"]
            .as_str()
            .unwrap_or("")
            .trim();

    /*
     * Ignora eventos inválidos
     */
    if rule_id.is_empty()
        || agent_name.is_empty()
    {

        return;
    }

    /*
     * Chave de dedupe
     */
    let dedupe_key =
        format!(
            "{}:{}",
            rule_id,
            agent_name
        );

    let now =
        Instant::now();

    /*
     * Verifica duplicação
     */
    if let Some(last_sent) =
        SENT_ALERTS.get(&dedupe_key)
    {

        if now.duration_since(
            *last_sent
        ) < Duration::from_secs(
            60 * 60 * 3
        ) {

            return;
        }
    }

    /*
     * Envia alerta
     */
    let res =
        HTTP_CLIENT
            .post(
                "http://localhost:10080/alert"
            )
            .header(
                "Content-Type",
                "application/json"
            )
            .body(
                String::from(line)
            )
            .send();

    match res {

        Ok(_) => {

            SENT_ALERTS.insert(
                dedupe_key,
                now
            );

            cleanup_cache(now);

            log_info!(
                "[Wazuh] ALERTA ENVIADO | Rule: {} | Agent: {}",
                rule_id,
                agent_name
            );
        }

        Err(e) => {

            log_error!(
                "[Wazuh] ERRO AO ENVIAR ALERTA: {}",
                e
            );
        }
    }
}

/*
 * Limpeza periódica do cache
 */
fn cleanup_cache(
    now: Instant
) {

    let mut cleanup =
        LAST_CLEANUP
            .lock()
            .unwrap();

    /*
     * Só limpa a cada 10 minutos
     */
    if now.duration_since(*cleanup)
        < Duration::from_secs(600)
    {

        return;
    }

    SENT_ALERTS.retain(
        |_, instant| {

            now.duration_since(*instant)
                < Duration::from_secs(
                    60 * 60 * 6
                )
        }
    );

    *cleanup = now;
}