/**
 * Importação de todos os arquivos do programa de coleta de alertas.
 */
mod central_coletores;
mod gari_wazuh;
mod gari_zabbix;

/**
 * Função principal do programa
 */

 fn main(){
    central_coletores::start();
 }
