use std::thread;
use std::time::Duration;
use std::path::Path;

use crate::gari_wazuh;
use crate::gari_zabbix;

#[derive(Debug, Clone)]
pub struct CollectorState {
    pub wazuh: bool,
    pub zabbix: bool,
}

// Detecta Wazuh
fn detect_wazuh() -> bool {
    Path::new("/var/ossec/logs/alerts/alerts.json").exists()
}

// Detecta Zabbix
fn detect_zabbix() -> bool {
    Path::new("/var/log/zabbix/zabbix_agentd.log").exists()
}

// Função central de detecção
fn detect() -> CollectorState {
    CollectorState {
        wazuh: detect_wazuh(),
        zabbix: detect_zabbix(),
    }
}

pub fn start() {
    let mut estado = detect();

    println!("Estado inicial: {:?}", estado);

    if estado.wazuh {
        gari_wazuh::start();
    }

    if estado.zabbix {
        gari_zabbix::start();
    }

    loop {
        if Path::new("/tmp/reload_collectors").exists() {
            println!("Reload detectado");

            let novo = detect();

            // WAZUH
            if estado.wazuh != novo.wazuh {
                if novo.wazuh {
                    println!("Iniciando coletor Wazuh");
                    gari_wazuh::start();
                } else {
                    println!("Parando coletor Wazuh");
                    gari_wazuh::stop();
                }
            }

            // ZABBIX
            if estado.zabbix != novo.zabbix {
                if novo.zabbix {
                    println!("Iniciando coletor Zabbix");
                    gari_zabbix::start();
                } else {
                    println!("Parando coletor Zabbix");
                    gari_zabbix::stop();
                }
            }

            estado = novo;
            std::fs::remove_file("/tmp/reload_collectors").ok();
        }

        thread::sleep(Duration::from_secs(5));
    }
}