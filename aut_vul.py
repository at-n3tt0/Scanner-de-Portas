import os
import nmap
import subprocess
import logging

# Configura o logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_with_nmap(target):
    logging.info(f"Iniciando varredura Nmap no endereço: {target}")
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV -p 1-65535')

    nmap_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                nmap_results.append({
                    'host': host,
                    'port': port,
                    'protocol': proto,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port]['product'],
                    'version': nm[host][proto][port]['version'],
                })
    return nmap_results

def scan_with_nikto(target):
    logging.info(f"Iniciando varredura Nikto no endereço: {target}")
    nikto_results_file = 'nikto_results.txt'
    nikto_command = f'perl [CAMINHO_PARA_NIKTO]\\nikto.pl -h {target} -output {nikto_results_file}'
    subprocess.run(nikto_command, shell=True, check=True)

    if not os.path.exists(nikto_results_file):
        logging.error(f"Arquivo de resultados do Nikto não encontrado: {nikto_results_file}")
        return ""

    with open(nikto_results_file, 'r', encoding='utf-8') as file:
        nikto_results = file.read()

    return nikto_results

def main():
    prefix = input("Digite o prefixo (primeiros três octetos) do intervalo de IP: ")
    start = int(input("Digite o início do intervalo do último octeto: "))
    end = int(input("Digite o fim do intervalo do último octeto: "))

    for i in range(start, end + 1):
        target = f"{prefix}.{i}"

        try:
            nmap_results = scan_with_nmap(target)
            logging.info(f"Resultados do Nmap para o alvo {target}:")
            if not nmap_results:
                logging.info(f"Sem resultados Nmap para o alvo {target}.")
            else:
                for result in nmap_results:
                    logging.info(f"Host: {result['host']}, Port: {result['port']}, Protocol: {result['protocol']}, "
                                 f"State: {result['state']}, Service: {result['name']}, Product: {result['product']}, "
                                 f"Version: {result['version']}")

            logging.info("Executando varredura com Nikto...")
            nikto_results = scan_with_nikto(target)
            logging.info(f"Resultados do Nikto para o alvo {target}:")
            logging.info(nikto_results)

        except Exception as e:
            logging.error(f"Ocorreu um erro ao processar o alvo {target}: {e}")

if __name__ == "__main__":
    main()
