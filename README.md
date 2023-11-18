Descrição do Script de Escaneamento de Rede com ARP

Este script Python foi desenvolvido com o objetivo de fornecer uma ferramenta rápida e eficaz para a identificação de dispositivos numa rede local através dos seus endereços MAC. Utilizando a biblioteca Scapy, o script envia solicitações ARP e captura as respostas, coletando informações valiosas que podem ser usadas para gestão de redes, segurança e fins educativos.
Funcionalidades

    Detecção de Interfaces de Rede: O script começa detectando todas as interfaces de rede disponíveis na máquina onde é executado.
    Seleção de Interface: O usuário pode selecionar qual interface de rede deseja usar para a varredura ARP.
    Varredura ARP: A varredura ARP é realizada em cada endereço IP dentro da faixa da sub-rede selecionada.
    Coleta de Dados: Para cada resposta ARP recebida, o script coleta o endereço IP, o endereço MAC correspondente e, quando possível, o hostname do dispositivo.
    Multithreading: Para maximizar a eficiência, o script executa a varredura ARP em paralelo, usando multithreading.

Como Usar

    Garanta que o Python 3 e a biblioteca Scapy estão instalados no seu sistema.
    Execute o script num terminal ou prompt de comando.
    Selecione a interface de rede para a varredura quando solicitado.
    O script exibirá os resultados da varredura em tempo real no terminal.

Exemplo de Saída

Interfaces de rede disponíveis:
1: eth0
2: wlan0

Digite o número da rede para iniciar o scan: 2
Scaneando a rede: 192.168.1.0/24 na interface wlan0

Dispositivos encontrados:

Endereço IP         Endereço MAC             Hostname
192.168.1.10        aa:bb:cc:dd:ee:ff        dispositivo1
192.168.1.11        ff:ee:dd:cc:bb:aa        dispositivo2
...

Aplicação Prática

O script pode ser extremamente útil para profissionais de TI realizando diagnósticos de rede, estudantes de tecnologia aprendendo sobre protocolos de comunicação, ou entusiastas da tecnologia interessados em descobrir mais sobre a infraestrutura da sua própria rede doméstica.
Nota Importante

Este script é para fins educacionais e deve ser usado de forma responsável. Não é recomendado para uso em redes onde você não tem autorização explícita para realizar tais operações de escaneamento.

Esta descrição destaca as principais características e instruções de uso do script, juntamente com um aviso sobre o uso responsável. Isso deve fornecer aos usuários do GitHub todas as informações necessárias para entenderem e utilizarem o script de forma eficaz.
