/*
 * Bibliotecas necessárias
 */
use std::collections::HashMap;

use std::fs::OpenOptions;

use std::io::{
    BufRead,
    BufReader
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

use lazy_static::lazy_static;

use serde_json::Value;

use reqwest::blocking::Client;

/*
 * Controle do listener
 */
lazy_static! {

    /*
     * Controle de execução
     */
    static ref RUNNING:
        Mutex<Option<Arc<AtomicBool>>> =
            Mutex::new(None);

    /*
     * Cache:
     * rule.id -> último envio
     */
    static ref SENT_ALERTS:
        Mutex<HashMap<String, Instant>> =
            Mutex::new(HashMap::new());

    /*
     * HTTP client global
     */
    static ref HTTP_CLIENT: Client =
        Client::builder()
            .timeout(
                Duration::from_secs(5)
            )
            .build()
            .expect(
                "Falha ao criar HTTP client"
            );
}

/*
 * Função que busca erros ao localizar o arquivo
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

                eprintln!(
                    "[Wazuh] Stream encerrado inesperadamente. Reconectando..."
                );

                thread::sleep(
                    Duration::from_secs(1)
                );
            }

            Err(e) => {

                eprintln!(
                    "[Wazuh] Erro ao abrir stream: {}",
                    e
                );

                thread::sleep(
                    Duration::from_secs(2)
                );
            }
        }
    }
}

/*
 * Faz leitura contínua do alerts.json
 */
fn open_stream(
    path: &str
) -> std::io::Result<()> {

    let file =
        OpenOptions::new()
            .read(true)
            .open(path)?;

    let reader =
        BufReader::new(file);

    eprintln!(
        "[Wazuh] Escutando {}",
        path
    );

    for line in reader.lines() {

        match line {

            Ok(l) => {

                if !l.is_empty() {

                    handle_event(&l);
                }
            }

            Err(e) => {

                eprintln!(
                    "[Wazuh] Erro ao ler a linha: {}",
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
fn handle_event(
    line: &str
) {

    let parsed: Value =
        match serde_json::from_str(line) {

            Ok(v) => v,

            Err(_) => return,
        };

    /*
     * rule.level
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
     * rule.id
     */
    let rule_id =
        parsed["rule"]["id"]
            .as_str()
            .unwrap_or("unknown");

    /*
     * Controle anti-duplicação
     * baseado apenas em rule.id
     */
    let now =
        Instant::now();

    {
        let cache =
            SENT_ALERTS
                .lock()
                .unwrap();

        if let Some(last_sent) =
            cache.get(rule_id)
        {

            /*
             * 3 horas
             */
            if now.duration_since(
                *last_sent
            ) < Duration::from_secs(
                60 * 60 * 3
            ) {

                eprintln!(
                    "[Wazuh] Rule {} ignorada (menos de 3h)",
                    rule_id
                );

                return;
            }
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
                line.to_string()
            )
            .send();

    match res {

        Ok(_) => {

            /*
             * Atualiza cache
             */
            {
                let mut cache =
                    SENT_ALERTS
                        .lock()
                        .unwrap();

                cache.insert(
                    rule_id.to_string(),
                    now
                );

                /*
                 * Remove entradas antigas
                 */
                cache.retain(
                    |_, instant| {

                        now.duration_since(
                            *instant
                        ) < Duration::from_secs(
                            60 * 60 * 6
                        )
                    }
                );
            }

            eprintln!(
                "[Wazuh] Alerta enviado com sucesso"
            );
        }

        Err(e) => {

            eprintln!(
                "[Wazuh] Erro ao enviar alerta {}",
                e
            );
        }
    }
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

    eprintln!(
        "[Wazuh] Listener iniciado"
    );
}

/*
 * Para listener
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

        eprintln!(
            "[Wazuh] Sinal de parada enviado"
        );
    }
}