# 🚀 Gerenciador de Rede Avançado para Windows

Este é um script interativo em Python desenvolvido para simplificar e automatizar tarefas comuns e avançadas de configuração de rede no sistema operacional Windows. Ele oferece uma interface de linha de comando amigável que guia o usuário através da visualização, modificação e teste de adaptadores de rede.

## ✨ Funcionalidades

* **Listagem Inteligente de Adaptadores:** Exibe apenas os adaptadores de rede que estão ativamente em uso (com um Gateway IPv4 configurado).
* **Configuração de IP Fixo:** Altera um adaptador de DHCP para um endereço IPv4 estático, definindo IP, máscara de sub-rede, gateway e um DNS primário (Cloudflare `1.1.1.1`) com um único comando.
* **Adição de IP Adicional (Proxy/Virtual):** Adiciona um segundo endereço IPv4 a um adaptador com uma máscara de sub-rede específica de host (`255.255.255.255` ou `/32`).
* **Diagnóstico de Conexão Avançado:** Executa testes de `ping` e `nslookup`, apresentando os resultados de forma clara e analisada:
    * **Análise de Ping:** Extrai e exibe estatísticas detalhadas como pacotes enviados/recebidos, perda, e tempos de resposta mínimo, máximo e médio.
    * **Análise de NSLookup:** Resolve um hostname, exibe os IPs, identifica o servidor DNS, o nome canônico (CNAME) e verifica se o IP resolvido pertence à rede da Cloudflare.
* **Interface Interativa e em Loop:** Permite que o usuário execute múltiplas operações no mesmo adaptador sem precisar reiniciar o script.

## 📋 Pré-requisitos

Antes de executar o script, certifique-se de que seu sistema atende aos seguintes requisitos:

1.  **Sistema Operacional:** Windows 10 ou Windows 11.
2.  **Python 3:** É necessário ter o Python 3 instalado.
    * Você pode baixá-lo em [python.org](https://www.python.org/downloads/).
    * **Importante:** Durante a instalação, marque a caixa de seleção **"Add Python to PATH"** ou "Adicionar Python ao PATH".
3.  **Privilégios de Administrador:** O script precisa modificar configurações do sistema, portanto, deve ser executado em um terminal com privilégios de administrador.

## ⚙️ Como Utilizar

Siga estes passos para executar o script:

1.  **Salvar o Arquivo de Script:**
    Salve o código Python em um arquivo no seu computador com o nome `gerenciador_rede.py`.

2.  **Criar o Arquivo README:**
    Siga as instruções acima para criar o arquivo `README.md` na mesma pasta do script.

3.  **Abrir o Terminal como Administrador:**
    Você precisa de um terminal com permissões elevadas.
    * Clique no **Menu Iniciar**.
    * Digite `PowerShell` ou `CMD`.
    * Clique com o botão direito do mouse sobre o ícone do **Windows PowerShell** ou do **Prompt de Comando**.
    * Selecione a opção **"Executar como administrador"**.

4.  **Navegar até a Pasta do Script:**
    No terminal que você abriu, use o comando `cd` (change directory) para navegar até a pasta onde salvou os arquivos.
    ```bash
    # Exemplo, se você salvou na sua pasta de Documentos
    cd C:\Users\SeuUsuario\Documentos
    ```

5.  **Executar o Script:**
    Digite o seguinte comando e pressione Enter:
    ```bash
    python gerenciador_rede.py
    ```

6.  **Seguir as Instruções na Tela:**
    * O script irá listar todos os adaptadores de rede ativos.
    * Ele pedirá que você digite o **Índice da Interface** que deseja configurar.
    * Após selecionar uma interface, um menu de ações será exibido, permitindo que você escolha entre `Fixar IPv4`, `Adicionar IP Proxy`, `Realizar Teste de Conexão` ou `Sair`.
    * Siga as instruções para cada opção escolhida.

## 🛠️ Como o Código Funciona (Visão Técnica)

Este script atua como uma interface amigável para as poderosas ferramentas de rede nativas do Windows.

* **Coleta de Dados:** Utiliza um comando `Get-NetIPConfiguration` do **PowerShell**, com a saída convertida para JSON. O Python então interpreta (parse) este JSON para obter de forma estruturada todas as informações dos adaptadores.
* **Modificação de Configurações:**
    * Para **fixar o IPv4**, o script constrói e executa comandos `netsh interface ipv4`, uma ferramenta robusta do Windows para configuração de rede.
    * Para **adicionar um IP secundário**, ele utiliza o cmdlet `New-NetIPAddress` do PowerShell, que é a maneira moderna e recomendada para essa tarefa.
* **Análise de Testes:**
    * O script executa os comandos `ping` e `nslookup` usando o módulo `subprocess` do Python, capturando a saída de texto.
    * Utiliza **Expressões Regulares (módulo `re`)** para analisar essa saída e extrair dados específicos (estatísticas de ping, IPs, aliases, etc.).
    * Para a verificação de IPs da Cloudflare, ele usa o módulo `ipaddress` do Python, garantindo uma checagem precisa em vez de uma simples comparação de texto.

## ⚠️ Aviso

Este script realiza alterações diretas nas configurações de rede do seu sistema. Utilize-o com cuidado e apenas se tiver certeza das ações que está realizando. O uso incorreto pode resultar em perda de conectividade com a internet. Os autores não se responsabilizam por quaisquer problemas decorrentes do uso deste script.
