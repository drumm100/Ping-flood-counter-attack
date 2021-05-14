#Ping flood counter attack

O trabalho consiste em desenvolver um programa usando socket raw que possa contra-atacar ataques do tipo ping flood usando técnicas como IP spoofing e DDoS (Distributed Denial of Service). O programa deve funcionar da seguinte forma:

1) A máquina vítima inicia monitorando as máquinas da rede que fazem ping (Echo Request) para a sua máquina e cria uma lista destas máquinas. O programa deve imprimir na tela o endereço MAC e IP de cada máquina identificada.

2) Quando o programa identifica que uma máquina (atacante) está enviando um ping flood para a sua máquina, ele usa a lista de máquinas armazenada para contra atacar (DDoS), enviando um ping flood para cada máquina da lista (excluindo a máquina atacante), mas trocando o campo IP origem pelo IP da máquina atacante (IP spoofing).

O trabalho deve ser validado na ferramenta Core usando uma topologia com no mínimo 5 máquinas.

## Execução:
`python3 ping_flood.py`

