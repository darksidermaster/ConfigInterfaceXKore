import subprocess
import json
import os
import ctypes
import sys
import re
import ipaddress
# --- Bloco de Funções de Verificação e Coleta de Dados ---

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

def executar_comando_modificacao(comando, shell=False):
    """Executa um comando de modificação e imprime o resultado."""
    comando_str = ' '.join(comando) if isinstance(comando, list) else comando
    print(f"\n> Executando: {comando_str}")
    
    try:
        proc = subprocess.run(
            comando, check=True, capture_output=True, text=True, shell=shell, encoding='cp850'
        )
        print("✅ Comando executado com sucesso!")
        if proc.stdout: print(f"\n--- Saída ---\n{proc.stdout}")
    except subprocess.CalledProcessError as e:
        erro_msg = e.stderr or e.stdout
        print(f"\n--- ❌ ERRO AO EXECUTAR O COMANDO ---\n{erro_msg}")

# --- Bloco de Funções de Configuração de Rede ---

def fixar_ipv4(adaptador):
    """Configura um endereço IPv4 estático na interface selecionada."""
    ip_principal = (adaptador['IPv4Address'][0] if isinstance(adaptador['IPv4Address'], list) else adaptador['IPv4Address'])
    cmd_ip = f'netsh interface ipv4 set address name="{adaptador["InterfaceAlias"]}" static {ip_principal} 255.255.255.0 {adaptador["IPv4DefaultGateway"]}'
    cmd_dns = f'netsh interface ipv4 set dns name="{adaptador["InterfaceAlias"]}" static 1.1.1.1'
    executar_comando_modificacao(cmd_ip, shell=True)
    executar_comando_modificacao(cmd_dns, shell=True)
    print("\nConfiguração de IP fixo concluída.")

def adicionar_ip_proxy(adaptador):
    """Adiciona um segundo endereço IP (proxy) à interface. 32"""
    default_ip_proxy = "172.65.175.70"
    ip_proxy = input("Digite o endereço IP 'proxy' que deseja adicionar (padrão: 172.65.175.70): ").strip() or default_ip_proxy
    default_prefixo = "24"
    opcoes = {
        "255.255.255.0": "24", 
        "255.255.255.255": "32",
        "1": "24",
        "2": "32"
    }
    prefixo = input("Difina a máscara do endereço IP 'proxy' (padrão: 255.255.255.0):\n1. 255.255.255.0\n2. 255.255.255.255\n> Digite sua escolha (1 a 2): ").strip() or default_prefixo
    prefixo = opcoes.get(prefixo, default_prefixo)
    comando_ps = [
        "powershell",
        "-Command",
        f'New-NetIPAddress -InterfaceIndex {adaptador["InterfaceIndex"]} -IPAddress {ip_proxy} -PrefixLength {prefixo}'
    ]
    executar_comando_modificacao(comando_ps, shell=False)

def configurar_dhcp(adaptador):
    """Restaura a configuração do adaptador para obter IP e DNS automaticamente (DHCP)."""
    alias = adaptador['InterfaceAlias']
    print(f"\n--- Revertendo '{alias}' para obter endereço IP e DNS automaticamente ---")
    
    cmd_ip_dhcp = f'netsh interface ipv4 set address name="{alias}" dhcp'
    cmd_dns_dhcp = f'netsh interface ipv4 set dns name="{alias}" dhcp'
    
    executar_comando_modificacao(cmd_ip_dhcp, shell=True)
    executar_comando_modificacao(cmd_dns_dhcp, shell=True)
    print("\n✅ Adaptador configurado para DHCP com sucesso.")

# --- Bloco de Funções de Teste (sem alterações) ---

def is_cloudflare_ip(ip_str):
    CLOUDFLARE_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '172.64.0.0/13', '131.0.72.0/22'
    ]
    try:
        ip = ipaddress.ip_address(ip_str)
        for net_range in CLOUDFLARE_RANGES:
            if ip in ipaddress.ip_network(net_range): return True
        return False
    except ValueError: return False

def analisar_e_exibir_ping(ip, output):
    stats = {'sent': 'N/A', 'received': 'N/A', 'loss': 'N/A', 'min': 'N/A', 'max': 'N/A', 'avg': 'N/A'}
    stats_match = re.search(r"Pacotes: Enviados = (\d+), Recebidos = (\d+), Perdidos = \d+ \((\d+)% de perda\)|Packets: Sent = (\d+), Received = (\d+), Lost = \d+ \((\d+)% loss\)", output)
    times_match = re.search(r"Mínimo = (\d+)ms, Máximo = (\d+)ms, Média = (\d+)ms|Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
    if stats_match:
        g = stats_match.groups()
        stats.update(sent=g[0] or g[3], received=g[1] or g[4], loss=g[2] or g[5])
    if times_match:
        g = times_match.groups()
        stats.update(min=f"{float(g[0] or g[3]):.1f}ms", max=f"{float(g[1] or g[4]):.1f}ms", avg=f"{float(g[2] or g[5]):.1f}ms")
    print("\n📊 ANÁLISE DOS RESULTADOS DO PING:\n" + "-"*35)
    print("📈 Estatísticas:")
    for key, value in {'Pacotes enviados': stats['sent'], 'Pacotes recebidos': stats['received'], 'Taxa de perda': f"{stats['loss']}%", 'Tempo médio': stats['avg'], 'Tempo mínimo': stats['min'], 'Tempo máximo': stats['max']}.items():
        print(f"    • {key}: {value}")
    avg_ms = float(stats['avg'].replace('ms', '')) if stats['avg'] != 'N/A' else 999
    if avg_ms < 1.0: print("\n✅ SUCESSO:\n    • Tempo de resposta < 1ms")
    else: print(f"\n⚠️  ATENÇÃO:\n    • Tempo de resposta ({stats['avg']}) ≥ 1ms")

def analisar_e_exibir_nslookup(hostname, output):
    """Analisa a saída do comando nslookup e a exibe de forma formatada (versão corrigida e robusta)."""
    
    # --- Extração de dados com Regex de forma segura ---
    server, cname_val, non_auth_msg = None, None, None
    aliases, resolved_ips = [], []

    # Extrai o servidor DNS
    server_match = re.search(r"Servidor:\s*(.*?)\n|Server:\s*(.*?)\n", output)
    if server_match:
        server = (server_match.group(1) or server_match.group(2) or "").strip()

    # Extrai todos os endereços IP
    ip_matches = re.findall(r"Address:\s*(\S+)|Endereço:\s*(\S+)", output)
    if ip_matches:
        resolved_ips = [match[0] or match[1] for match in ip_matches]

    # Extrai o Nome Canônico (CNAME)
    cname_match = re.search(r"Nome:\s*(.*?)\n|Name:\s*(.*?)\n", output)
    if cname_match:
        cname_val = (cname_match.group(1) or cname_match.group(2) or "").strip()

    # Extrai os Aliases
    aliases = re.findall(r"Aliases:\s*(.*)", output, re.MULTILINE)
    # Limpa os aliases caso venham em múltiplas linhas ou com o hostname
    if aliases:
        aliases = [a.strip() for a in aliases[0].split() if a.strip() != hostname]

    # Verifica se a resposta não é autoritativa
    non_auth_match = re.search(r"Não é resposta autoritativa|Non-authoritative answer", output)
    if non_auth_match:
        non_auth_msg = non_auth_match.group(0)

    # --- Exibição formatada dos resultados ---
    print("\n📤 Resultado Bruto do NSLookup:")
    print(output)
    
    if non_auth_msg:
        print("⚠️  Avisos/Erros:")
        print(f"    • {non_auth_msg}")

    print("\n📊 ANÁLISE DO NSLOOKUP:")
    print("------------------------------")
    
    if server:
        print(f"🌐 Servidor DNS: {server}")

    # Filtra o IP do servidor DNS da lista de IPs resolvidos para o host
    display_ips = [ip for ip in resolved_ips if ip != server]

    if display_ips:
        print("📍 IPs resolvidos para o host:")
        for ip in display_ips:
            print(f"    • {ip}", end="")
            if is_cloudflare_ip(ip):
                print(" (✅ IP na faixa Cloudflare)")
            else:
                print() # Apenas nova linha
    
    if cname_val and cname_val.lower() != hostname.lower():
        print(f"🏷️  Nome canônico: {cname_val}")

    if aliases:
        print("🔗 Aliases encontrados:")
        for alias in aliases:
            print(f"    • {alias}")

    if display_ips:
        print("\n✅ RESOLUÇÃO DNS OK!")
        print(f"    • Hostname {hostname} resolvido com sucesso.")
        print(f"    • {len(display_ips)} endereço(s) IP relevante(s) encontrado(s).")
    else:
        print("\n❌ FALHA NA RESOLUÇÃO DNS!")
        print("    • Não foi possível encontrar um endereço IP para o hostname solicitado.")

def realizar_testes_conexao():
    print("\n--- 🛠️  Iniciando Testes de Conexão ---")
    ip_ping = input("Digite o IP para PING: ").strip()
    if ip_ping:
        print(f"\n🔍 Executando ping para {ip_ping}...")
        try:
            output = subprocess.run(['ping', '-n', '4', ip_ping], capture_output=True, text=True, timeout=10, encoding='cp850').stdout
            analisar_e_exibir_ping(ip_ping, output)
        except Exception as e: print(f"❌ Erro ao executar o PING: {e}")
    default_hostname = "lt-account-01.gnjoylatam.com"
    hostname_lookup = input(f"\nDigite o hostname para nslookup (padrão: {default_hostname}): ").strip() or default_hostname
    print(f"\n🔍 Executando nslookup para {hostname_lookup}...")
    try:
        output = subprocess.run(['nslookup', hostname_lookup], capture_output=True, text=True, timeout=10, encoding='cp850').stdout
        analisar_e_exibir_nslookup(hostname_lookup, output)
    except Exception as e: print(f"❌ Erro ao executar o NSLOOKUP: {e}")
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
            else: print("ERRO: Índice inválido. Tente novamente.")
        except (ValueError, KeyError): print("ERRO: Entrada inválida. Digite um número da lista.")

    print(f"\nVocê selecionou: '{adaptador_selecionado['InterfaceAlias']}' (Índice: {adaptador_selecionado['InterfaceIndex']})")

    while True:
        print("\n" + "="*15 + " 🛠️  MENU DE AÇÕES " + "="*15)
        print("1. Fixar IPv4 (IP, máscara, gateway e DNS estáticos)")
        print("2. Adicionar IP Proxy (IP secundário na mesma interface)")
        print("3. Realizar Teste de Conexão (Ping e NSLookup)")
        print("4. Voltar para IP Automático (DHCP)")
        print("5. Sair")
        print("="*49)
        
        escolha = input("> Digite sua escolha (1 a 5): ").strip()

        if escolha == '1': fixar_ipv4(adaptador_selecionado)
        elif escolha == '2': adicionar_ip_proxy(adaptador_selecionado)
        elif escolha == '3': realizar_testes_conexao()
        elif escolha == '4': configurar_dhcp(adaptador_selecionado)
        elif escolha == '5':
            print("Saindo do script...")
            break
        else:
            print("ERRO: Opção inválida. Por favor, escolha uma das opções acima.")

    input("\nOperação finalizada. Pressione Enter para sair.")

if __name__ == "__main__":
    main()
