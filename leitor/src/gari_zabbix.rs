/**
 *  Bibliotecas necessárias
 */
use std::thread;
use std::time::Duration;

static mut RUNNING: bool = false;

pub fn stop() {
    println!("zabbix parado");
}

pub fn start(){
    unsafe{
        if RUNNING{
            return;
        }
        RUNNING = true;
    }

    thread::spawn(|| {
        println!("Gari zabbix apostos");

        loop {
            println!("rodando...");
            thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}