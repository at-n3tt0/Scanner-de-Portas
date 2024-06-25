import os
import nmap
import subprocess

# Função de varredura com nmap


def scan_with_nmap(target):
    print(f"\nIniciando varredura Nmap no endereço: {target}")
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

# Função para varredura com nikto


def scan_with_nikto(target):
    print(f"\nIniciando varredura Nikto no endereço: {target}")
    nikto_results_file = 'nikto_results.txt'
    nikto_command = f'perl C:\\nikto\\program\\nikto.pl -h {
        target} -output {nikto_results_file}'
    subprocess.run(nikto_command, shell=True, check=True)

    with open(nikto_results_file, 'r', encoding='utf-8') as file:
        nikto_results = file.read()

    return nikto_results

# Função principal de execução de varredura


def main():
    prefix = input(
        "Digite o prefixo (primeiros três octetos) do intervalo de IP: ")
    start = int(input("Digite o início do intervalo do último octeto: "))
    end = int(input("Digite o fim do intervalo do último octeto: "))

    for i in range(start, end + 1):
        target = f"{prefix}.{i}"

        try:
            # Realizar a varredura com nmap
            nmap_results = scan_with_nmap(target)

            # Exibe resultado do Nmap
            print(f"\nResultados do Nmap para o alvo {target}:")
            if not nmap_results:
                print(f"Sem resultados Nmap para o alvo {target}.")
            else:
                for result in nmap_results:
                    print(f"Host: {result['host']}, Port: {result['port']}, Protocol: {result['protocol']}, "
                          f"State: {result['state']}, Service: {
                              result['name']}, Product: {result['product']}, "
                          f"Version: {result['version']}")

            # Realiza a varredura com Nikto
            print("\nExecutando varredura com Nikto...")
            nikto_results = scan_with_nikto(target)

            # Exibe resultado do Nikto
            print(f"\nResultados do Nikto para o alvo {target}:")
            print(nikto_results)

        except Exception as e:
            print(f"Ocorreu um erro ao processar o alvo {target}: {e}")


if __name__ == "__main__":
    main()
