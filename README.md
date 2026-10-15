# AD-attack-defense-lab

Dopo essermi confrontato con alcuni esperti che hanno valutato i miei precedenti progetti mi sono impegnato a svilupparne un nuovo più incentrato sulla sicurezza vera e propria al momento dell'attacco che sulle basi sistemistiche di network ecc come i precedentiLaboratorio di simulazione attacchi informatici da prospettiva offensiva e difensiva, con seguente hardening per studiare le tecniche di attacco e le relative contromisure, documentando per ogni debolezza il ciclo completo: configurazione vulnerabile, poi attacco, la traccia difensiva, l' hardening e il re-test.

L'ambiente è un piccolo dominio Active Directory virtualizzato su VMware, formato da un DC, una workstation di dominio e una macchina attaccante.
Ogni debolezza introdotta è volontaria.




ARCHITETTURA

| Host | Ruolo | OS | IP |
|------|-------|----|----|
| **DC01** | Domain Controller + DNS | Windows Server 2022 | `192.168.56.10` |
| **WS01** | Workstation di dominio | Windows 11 | `192.168.56.20` |
| **Kali** | Macchina attaccante | Kali Linux | `192.168.56.100` |

- Dominio: lab.local
- Rete: host-only 192.168.56.0/24 (VMware VMnet1), isolata da internet
- Hypervisor: VMware Workstation

Setup minimo (3 VM) perchè un DC, un client e un attaccante bastano a riprodurre la maggior parte delle tecniche AD, il secondo client lo aggiungerò quando passerò al movimento laterale.

METODOLOGIA

Per ogni debolezza seguo sempre lo stesso processo ripetibile:

1. **Introduco la debolezza** — configuro l'oggetto AD in modo volutamente vulnerabile e spiegando perché quella configurazione è realistica.
2. **Attacco e misuro l'impatto** — eseguo la tecnica dalla macchina attaccante e vedo cosa ottengo.
3. **Catturo la traccia difensiva** — identifico quali log e quali Event ID registrano l'attacco, e quale campo specifico lo tradisce.
4. **Applico l'hardening** — introduco la contromisura.
5. **Ripeto l'attacco identico confrontando risultati** — stesso comando, e confronto il risultato prima/dopo.


-----------


