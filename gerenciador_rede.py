import subprocess
import json
import os
import ctypes
import sys
import re
import ipaddress

# --- Bloco de Funções de Verificação e Coleta de Dados (sem alterações) ---

def verificar_admin():
    """Verifica se o script está sendo executado com privilégios de administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def obter_configuracoes_rede():
    """Executa o comando do PowerShell para obter as configurações de rede."""
    print("Obtendo informações dos adaptadores de rede...")
    command = """
    Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | 
    Select-Object InterfaceAlias, InterfaceIndex, InterfaceDescription, 
                  @{Name='NetProfileName';Expression={$_.NetProfile.Name}}, 
                  @{Name='IPv4Address';Expression={$_.IPv4Address.IPAddress}}, 
                  @{Name='IPv4DefaultGateway';Expression={$_.IPv4DefaultGateway.NextHop}}, 
                  @{Name='DNSServer';Expression={$_.DNSServer.ServerAddresses}} | 
    ConvertTo-Json
    """
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True, check=True, encoding='utf-8')
        data = json.loads(result.stdout)
        return [data] if isinstance(data, dict) else data
    except Exception as e:
        print(f"Ocorreu um erro ao obter as configurações de rede: {e}")
        return None

def exibir_adaptadores(adaptadores):
    """Exibe os adaptadores de rede formatados para o usuário."""
    if not adaptadores:
        print("Nenhum adaptador de rede com Gateway IPv4 encontrado.")
        return False
    print("\n--- 🔌 Adaptadores de Rede Disponíveis ---")
    for ad in adaptadores:
        print("-" * 40)
        print(f"Alias da Interface : {ad.get('InterfaceAlias')}")
        print(f"Índice da Interface: {ad.get('InterfaceIndex')}")
        print(f"Descrição          : {ad.get('InterfaceDescription')}")
        print(f"Perfil de Rede     : {ad.get('NetProfileName', 'N/A')}")
        ipv4 = ad.get('IPv4Address', [])
        ipv4_list = [ipv4] if not isinstance(ipv4, list) else ipv4
        if ipv4_list:
            print(f"Endereço(s) IPv4   : {ipv4_list[0]}")
            for ip in ipv4_list[1:]: print(f"                     {ip}")
        print(f"Gateway IPv4       : {ad.get('IPv4DefaultGateway')}")
        dns = ad.get('DNSServer', [])
        dns_list = [dns] if not isinstance(dns, list) else dns
        if dns_list:
            print(f"Servidor(es) DNS   : {dns_list[0]}")
            for s in dns_list[1:]: print(f"                     {s}")
    print("-" * 40)
    return True

def executar_comando_modificacao(comando, shell=True):
    """Executa um comando de modificação e imprime o resultado."""
    print(f"\n> Executando: {comando}")
    try:
        proc = subprocess.run(comando, check=True, capture_output=True, text=True, shell=shell, encoding='cp850')
        print("✅ Comando executado com sucesso!")
        if proc.stdout: print(f"\n--- Saída ---\n{proc.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"\n--- ❌ ERRO AO EXECUTAR O COMANDO ---\n{e.stderr or e.stdout}")

def fixar_ipv4(adaptador):
    """Configura um endereço IPv4 estático na interface selecionada."""
    ip_principal = (adaptador['IPv4Address'][0] if isinstance(adaptador['IPv4Address'], list) else adaptador['IPv4Address'])
    cmd_ip = f'netsh interface ipv4 set address name="{adaptador["InterfaceAlias"]}" static {ip_principal} 255.255.255.0 {adaptador["IPv4DefaultGateway"]}'
    cmd_dns = f'netsh interface ipv4 set dns name="{adaptador["InterfaceAlias"]}" static 1.1.1.1'
    executar_comando_modificacao(cmd_ip)
    executar_comando_modificacao(cmd_dns)

def adicionar_ip_proxy(adaptador):
    """Adiciona um segundo endereço IP (proxy) à interface."""
    ip_proxy = input("Digite o endereço IP 'proxy' que deseja adicionar (ex: 172.65.175.70): ").strip()
    if not ip_proxy:
        print("Nenhum IP inserido. Operação cancelada.")
        return
    cmd_ps = f'New-NetIPAddress -InterfaceIndex {adaptador["InterfaceIndex"]} -IPAddress {ip_proxy} -PrefixLength 32'
    executar_comando_modificacao(cmd_ps, shell=False)

# --- Bloco de Funções de Teste (Refatorado para Melhor Apresentação) ---

def is_cloudflare_ip(ip_str):
    """Verifica se um IP pertence aos ranges conhecidos da Cloudflare."""
    CLOUDFLARE_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '172.64.0.0/13', '131.0.72.0/22'
    ]
    try:
        ip = ipaddress.ip_address(ip_str)
        for net_range in CLOUDFLARE_RANGES:
            if ip in ipaddress.ip_network(net_range):
                return True
        return False
    except ValueError:
        return False

def analisar_e_exibir_ping(ip, output):
    """Analisa a saída do comando ping e a exibe de forma formatada."""
    stats = {
        'sent': 'N/A', 'received': 'N/A', 'loss': 'N/A',
        'min': 'N/A', 'max': 'N/A', 'avg': 'N/A'
    }
    
    # Regex para Português e Inglês
    stats_match = re.search(r"Pacotes: Enviados = (\d+), Recebidos = (\d+), Perdidos = \d+ \((\d+)% de perda\)|Packets: Sent = (\d+), Received = (\d+), Lost = \d+ \((\d+)% loss\)", output)
    times_match = re.search(r"Mínimo = (\d+)ms, Máximo = (\d+)ms, Média = (\d+)ms|Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
    
    if stats_match:
        groups = stats_match.groups()
        stats['sent'] = groups[0] or groups[3]
        stats['received'] = groups[1] or groups[4]
        stats['loss'] = groups[2] or groups[5]
    if times_match:
        groups = times_match.groups()
        stats['min'] = f"{float(groups[0] or groups[3]):.1f}ms"
        stats['max'] = f"{float(groups[1] or groups[4]):.1f}ms"
        stats['avg'] = f"{float(groups[2] or groups[5]):.1f}ms"

    print("\n📊 ANÁLISE DOS RESULTADOS DO PING:")
    print("-----------------------------------")
    print("📈 Estatísticas:")
    print(f"    • Pacotes enviados: {stats['sent']}")
    print(f"    • Pacotes recebidos: {stats['received']}")
    print(f"    • Taxa de perda: {stats['loss']}%")
    print(f"    • Tempo médio: {stats['avg']}")
    print(f"    • Tempo mínimo: {stats['min']}")
    print(f"    • Tempo máximo: {stats['max']}")
    
    avg_ms = float(stats['avg'].replace('ms', '')) if stats['avg'] != 'N/A' else 999
    if avg_ms >= 1.0:
        print("\n⚠️  ATENÇÃO:")
        print(f"    • Tempo de resposta ({stats['avg']}) ≥ 1ms")
    elif avg_ms < 1.0:
        print("\n✅ SUCESSO:")
        print(f"    • Tempo de resposta ({stats['avg']}) < 1ms")


def analisar_e_exibir_nslookup(hostname, output):
    """Analisa a saída do comando nslookup e a exibe de forma formatada."""
    server = (re.search(r"Servidor:\s*(.*?)\n|Server:\s*(.*?)\n", output) or [None, None, None])[1] or (re.search(r"Servidor:\s*(.*?)\n|Server:\s*(.*?)\n", output) or [None, None, None])[2]
    ips = re.findall(r"Address:\s*(\S+)|Endereço:\s*(\S+)", output)
    resolved_ips = [ip[0] or ip[1] for ip in ips]
    cname = (re.search(r"Nome:\s*(.*?)\n|Name:\s*(.*?)\n", output) or [None, None, None])[1] or (re.search(r"Nome:\s*(.*?)\n|Name:\s*(.*?)\n", output) or [None, None, None])[2]
    aliases = re.findall(r"Aliases:\s*(\S+)", output, re.MULTILINE)
    non_auth = re.search(r"Não é resposta autoritativa|Non-authoritative answer", output)

    print("\n📤 Resultado do NSLookup:")
    print(output)
    
    if non_auth:
        print("⚠️  Avisos/Erros:")
        print(f"    • {non_auth.group(0)}")

    print("\n📊 ANÁLISE DO NSLOOKUP:")
    print("------------------------------")
    if server: print(f"🌐 Servidor DNS: {server.strip()}")
    if resolved_ips:
        print("📍 IPs resolvidos:")
        # O primeiro IP geralmente é o do servidor DNS, podemos remover se for o caso
        server_ip = server and server.strip() in resolved_ips[0]
        display_ips = resolved_ips[1:] if server_ip else resolved_ips
        for ip in display_ips:
            print(f"    • {ip}")
            if is_cloudflare_ip(ip):
                print("      ✅ IP na faixa Cloudflare esperada")
    if cname and cname.strip() != hostname: print(f"🏷️  Nome canônico: {cname.strip()}")
    if aliases:
        print("🔗 Aliases encontrados:")
        for alias in aliases: print(f"    • {alias}")

    if len(display_ips) > 0:
        print("\n✅ RESOLUÇÃO DNS OK!")
        print(f"    • Hostname {hostname} resolvido com sucesso")
        print(f"    • {len(display_ips)} endereço(s) IP relevante(s) encontrado(s)")
    else:
        print("\n❌ FALHA NA RESOLUÇÃO DNS!")
        print("    • Não foi possível encontrar um endereço IP para o hostname.")


def realizar_testes_conexao():
    """Orquestra os testes de Ping e NSLookup com a nova apresentação."""
    print("\n--- 🛠️  Iniciando Testes de Conexão ---")
    
    # --- Teste de Ping ---
    ip_ping = input("Digite o IP para PING: ").strip()
    if ip_ping:
        print(f"\n🔍 Executando ping para {ip_ping}...")
        try:
            output = subprocess.run(['ping', '-n', '4', ip_ping], capture_output=True, text=True, timeout=10, encoding='cp850').stdout
            analisar_e_exibir_ping(ip_ping, output)
        except Exception as e:
            print(f"❌ Erro ao executar o PING: {e}")

    # --- Teste de NSLookup ---
    default_hostname = "lt-account-01.gnjoylatam.com"
    hostname_lookup = input(f"\nDigite o hostname para nslookup (padrão: {default_hostname}): ").strip() or default_hostname
    print(f"\n🔍 Executando nslookup para {hostname_lookup}...")
    try:
        output = subprocess.run(['nslookup', hostname_lookup], capture_output=True, text=True, timeout=10, encoding='cp850').stdout
        analisar_e_exibir_nslookup(hostname_lookup, output)
    except Exception as e:
        print(f"❌ Erro ao executar o NSLOOKUP: {e}")
    print("\n🎯 Operação concluída!")


# --- Bloco Principal de Execução ---

def main():
    if not verificar_admin():
        print("❌ Erro: Este script precisa ser executado com privilégios de Administrador.")
        input("Pressione Enter para sair...")
        sys.exit(1)

    configs = obter_configuracoes_rede()
    if not exibir_adaptadores(configs):
        input("\nPressione Enter para sair...")
        return

    adaptadores_dict = {str(c['InterfaceIndex']): c for c in configs}
    adaptador_selecionado = None
    while True:
        try:
            index_str = input("\n> Digite o Índice da Interface que deseja configurar: ")
            if index_str in adaptadores_dict:
                adaptador_selecionado = adaptadores_dict[index_str]
                break
            else:
                print("ERRO: Índice inválido. Tente novamente.")
        except (ValueError, KeyError):
            print("ERRO: Entrada inválida. Digite um número da lista.")

    print(f"\nVocê selecionou: '{adaptador_selecionado['InterfaceAlias']}' (Índice: {adaptador_selecionado['InterfaceIndex']})")

    while True:
        print("\n" + "="*15 + " 🛠️  MENU DE AÇÕES " + "="*15)
        print("1. Fixar IPv4 (IP, máscara, gateway e DNS estáticos)")
        print("2. Adicionar IP Proxy (com máscara 255.255.255.255)")
        print("3. Realizar Teste de Conexão (Ping e NSLookup)")
        print("4. Sair")
        print("="*49)
        
        escolha = input("> Digite sua escolha (1, 2, 3 ou 4): ").strip()

        if escolha == '1': fixar_ipv4(adaptador_selecionado)
        elif escolha == '2': adicionar_ip_proxy(adaptador_selecionado)
        elif escolha == '3': realizar_testes_conexao()
        elif escolha == '4':
            print("Saindo do script...")
            break
        else:
            print("ERRO: Opção inválida. Por favor, escolha uma das opções acima.")

    input("\nOperação finalizada. Pressione Enter para sair.")

if __name__ == "__main__":
    main()