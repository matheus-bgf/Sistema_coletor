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

    /*
     * Flag de execução
     */
    let running =
        Arc::new(
            AtomicBool::new(true)
        );

    /*
     * Salva referência global
     */
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

    /*
     * Inicia thread do listener
     */
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

        /*
         * Envia sinal de parada
         */
        running.store(
            false,
            Ordering::Relaxed
        );

        eprintln!(
            "[Wazuh] Sinal de parada enviado"
        );
    }
}

/*
 * Loop principal do listener
 */
pub fn start_wazuh_listener(
    running: Arc<AtomicBool>
) {

    /*
     * Caminho do alerts.json
     */
    let path =
        "/var/ossec/logs/alerts/alerts.json";

    while running.load(
        Ordering::Relaxed
    ) {

        match open_stream(path) {

            Ok(_) => {

                eprintln!(
                    "[Wazuh] Stream encerrado. Reconectando..."
                );

                thread::sleep(
                    Duration::from_secs(5)
                );
            }

            Err(e) => {

                eprintln!(
                    "[Wazuh] Erro ao abrir stream: {}",
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

    /*
     * Abre arquivo
     */
    let mut file =
        OpenOptions::new()
            .read(true)
            .open(path)?;

    /*
     * Move cursor para o final
     * evitando releitura completa
     */
    file.seek(
        SeekFrom::End(0)
    )?;

    /*
     * Cria reader
     */
    let mut reader =
        BufReader::new(file);

    eprintln!(
        "[Wazuh] Escutando {}",
        path
    );

    loop {

        let mut line =
            String::new();

        match reader.read_line(&mut line) {

            /*
             * Sem novas linhas
             */
            Ok(0) => {

                thread::sleep(
                    Duration::from_millis(200)
                );
            }

            /*
             * Linha recebida
             */
            Ok(_) => {

                let line =
                    line.trim();

                if !line.is_empty() {

                    handle_event(line);
                }
            }

            /*
             * Erro de leitura
             */
            Err(e) => {

                eprintln!(
                    "[Wazuh] Erro ao ler linha: {}",
                    e
                );

                break;
            }
        }
    }

    Ok(())
}