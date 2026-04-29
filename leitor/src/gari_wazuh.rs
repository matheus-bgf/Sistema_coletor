/**
 *  Bibliotecas necessárias
 */
use std::fs::OpenOptions;
use std::io::{BufRead,BufReader};
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use serde_json::Value;
use std::sync::Mutex;
use reqwest::blocking::Client;

static RUNNING: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

/**
 * Função que busca erros ao localizar o arquivo
 */
pub fn start_wazuh_listener(running: Arc<AtomicBool>){
    let path = "/var/ossec/queue/alerts/alerts.json";

    while running.load(Ordering::Relaxed){
        match open_stream(path){
            Ok(_)=>{
                eprintln!("[Wazuh] Stream encerrado inesperadamente. Reconectando...");
                thread::sleep(Duration::from_secs(1));
            }
            Err(e)=>{
                eprintln!("[Wazuh] Erro ao abrir stream: {}", e);
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn open_stream(path:&str) -> std::io::Result<()>{
    let file = OpenOptions::new()
        .read(true)
        .open(path)?;
    let reader = BufReader::new(file);

    eprintln!("[Wazuh] Escutando {}", path);

    for line in reader.lines(){
        match line{
            Ok(l) => {
                if !l.is_empty(){
                    handle_event(&l);
                }
            }
            Err(e) => {
                eprintln!("[Wazuh] Erro ao ler a linha:{}", e);
                break;
            }
        }
    }
    Ok(())
}

fn handle_event(line: &str) {
    let parsed:Value = match serde_json::from_str(line){
        Ok(v) => v,
        Err(_) => return,
    };

    let level = parsed["rule"]["level"].as_i64().unwrap_or(0);

    if level < 3 {
        return;
    }

    let client = Client::new();

    let res = client
        .post("http://localhost:10080/alert")
        .header("Content-Type", "application/json")
        .body(line.to_string())
        .send();

    match res{
        Ok(_) => eprintln!("[Wazuh] Alerta enviado com sucesso"),
        Err(e) => eprintln!("[Wazuh] Erro ao enviar alerta {}", e),
    }
}

pub fn start(){
    let running = Arc::new(AtomicBool::new(true));
    
    let mut guard = RUNNING.lock().unwrap();
    *guard = Some(running.clone());

    thread::spawn(move||{
        start_wazuh_listener(running);
    });
}

pub fn stop(){
    let guard = RUNNING.lock().unwrap();

    if let Some(running) = guard.as_ref(){
        running.store(false, Ordering::Relaxed);
    }
}