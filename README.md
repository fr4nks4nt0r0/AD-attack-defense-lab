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


## CAPITOLO 1 — Kerberoasting

### La debolezza

Ho creato un account di servizio, `svc_sql`, con un **Service Principal Name (SPN)** registrato e una password debole.

```powershell
# Account di servizio con SPN (simula un servizio MSSQL)
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true

Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

Gli account di servizio con password statica sono fra le misconfigurazioni più diffuse, spesso la password è stata impostata anni prima, non scade mai, ed è più debole di quanto dovrebbe perché "tanto è solo un service account".

### L'attacco

Il Kerberoasting sfrutta un comportamento legittimo di Kerberos: qualsiasi utente di dominio autenticato può richiedere un ticket di servizio (TGS) per un account con SPN. Quel ticket è cifrato con l'hash della password dell'account di servizio, e può essere SCARICATO e craccato **offline**, dove nessun lockout, nessun alert di login fallito e nessun limite di tentativi può fermarlo.

Mi autentico come `m.rossi`, un utente SENZA PRIVILEGI, e richiedo i ticket di tutti gli account con SPN:

```bash
impacket-GetUserSPNs lab.local/m.rossi:'Autunno2026!' -dc-ip 192.168.56.10 -request -outputfile kerberoast.txt
```

Ottengo l'hash dell'account `svc_sql` (blob `$krb5tgs$23$...`).

![Hash kerberoastato estratto da GetUserSPNs](screenshots/01-getuserspns.png)

Come utente senza privilegi ho estratto dal Domain Controller il materiale crittografico di un account di servizio, niente exploit ma una funzione legittima di Kerberos.

### Il cracking

Con la password debole iniziale (`Password123`), il crack è immediato usando una wordlist pubblica standard:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
john --show --format=krb5tgs kerberoast.txt
# ?:Password123
```

![Password craccata con John the Ripper](screenshots/02-crack-password123.png)

Con pochi secondi  e un dizionario pubblico il gioco è fatto.

### La traccia difensiva

Subito dopo l'attacco, sul Domain Controller cerco l'**Event ID 4769** (richiesta di ticket di servizio Kerberos):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 20 | Format-List TimeCreated, Message
```

![Event ID 4769 che registra la richiesta di ticket](screenshots/03-event-4769.png)

L'evento contiene l'intera catena dell'attacco in una sola schermata:

| Campo | Valore | Cosa racconta |
|-------|--------|---------------|
| Nome account | `m.rossi@LAB.LOCAL` | L'utente non privilegiato che ha richiesto il ticket |
| Nome servizio | `svc_sql` | L'account di servizio preso di mira |
| Indirizzo client | `192.168.56.100` | La macchina attaccante (Kali) |
| **Tipo crittografia ticket** | **`0x17`** | **RC4 — il campo d'oro** |

**Perché `0x17` è l'indicatore chiave:** il Kerberoasting predilige ticket RC4 (`0x17`) perché sono molto più rapidi da craccare rispetto ad AES. In un ambiente sano la maggior parte dei ticket è AES; una richiesta improvvisa di un ticket **RC4 per un account di servizio** è un'anomalia su cui un analista costruisce una regola di detection. Non basta "c'è un 4769" — sono migliaia al giorno. È la combinazione *account di servizio + RC4 + provenienza inattesa* che fa scattare l'allarme.

### L'hardening e il re-test

La contromisura mira a ciò che rende l'attacco utile: la password craccabile, ho sostituito la password debole di `svc_sql` con una lunga e casuale:

```powershell
Set-ADAccountPassword -Identity svc_sql -Reset -NewPassword (ConvertTo-SecureString "<password lunga casuale di oltre 25 caratteri>" -AsPlainText -Force)
```

Poi ho rilanciato lo stesso identico attacco,  con:

```bash
impacket-GetUserSPNs lab.local/m.rossi:'Autunno2026!' -dc-ip 192.168.56.10 -request -outputfile kerberoast_hardened.txt
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hardened.txt
```

![Re-test: hash estratto ma 0 password craccate](screenshots/04-crack-hardened-0g.png)

PRIMA VS DOPO

| | Prima (password debole) | Dopo (password robusta) |
|---|---|---|
| Estrazione del ticket | riuscita | riuscita (identica) |
| Esito del cracking | craccata in secondi (`Password123`) | `0 cracked` su rockyou intera |

l'hardening non ha impedito l'attacco, l'ha reso **inefficace**. La superficie di attacco è invariata (qualunque utente può ancora estrarre il ticket); ciò che cambia è che una password robusta sposta il cracking da "secondi" a "computazionalmente non praticabile". Capire questa distinzione è la differenza tra ragionare da difensore e applicare una checklist.

### Conclusione del capitolo — cosa farebbe un difensore reale

- **Soluzione definitiva:** convertire gli account di servizio in **gMSA (Group Managed Service Account)**, dove la password è generata e ruotata dal sistema (120+ caratteri, rotazione automatica, mai nota a un umano). L'hash resta estraibile ma di fatto incraccabile. *(Da implementare come prossimo passo di questo lab.)*
- **Dove la rotazione automatica non è possibile:** password lunghe e casuali sugli account di servizio, trattate come segreti ad alto valore.
- **Detection:** monitorare gli Event ID 4769 con crittografia RC4 (`0x17`) richiesti per account di servizio, in particolare da endpoint anomali.
- **Riduzione della superficie:** disabilitare RC4 a livello di dominio dove compatibile, forzando AES.

---

## Problemi incontrati e risoluzione

Questa sezione raccoglie gli ostacoli reali incontrati durante la costruzione del lab. Li documento perché sono la parte più onesta del progetto: distinguono un ambiente costruito davvero da uno copiato da un tutorial.

### 1. Comandi in inglese che falliscono su Windows Server in italiano

Più volte comandi presi da guide anglofone hanno fallito perché i nomi di gruppi e categorie sono **localizzati** sul sistema in italiano:

- `Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"` → `ObjectNotFound`
- `auditpol /set /subcategory:"Kerberos Service Ticket Operations"` → `Errore 0x00000057: Parametro non corretto`
- `New-ADServiceAccount ... -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"` → *"Impossibile trovare un oggetto con identità: 'Domain Computers'"* (in italiano è **"Computer del dominio"**)

**Risoluzione:** usare identificatori indipendenti dalla lingua. Per l'auditing, i **GUID** delle sottocategorie (identici in tutte le lingue):

```powershell
# Kerberos Service Ticket Operations (Event ID 4769)
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

Per i gruppi, il **SID/RID** anziché il nome (es. `Domain Computers` ha sempre RID `515`). **Lezione:** su sistemi localizzati, affidarsi a GUID e SID invece che ai nomi è una pratica di robustezza, non un ripiego.

### 2. Workstation con indirizzo APIPA dopo il join

Dopo aver configurato la rete, WS01 restava con un indirizzo `169.254.x.x` (APIPA) e non raggiungeva il DC (`ping: errore generale`). Impostare solo il DNS non aveva assegnato un IP valido.

**Risoluzione:** assegnazione esplicita dell'indirizzo statico, con attenzione al nome esatto dell'interfaccia:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.56.10
```

Verifica collaterale importante: confermare nel Virtual Network Editor che **tutte** le VM fossero sullo stesso VMnet con subnet `192.168.56.0/24` — un mismatch di segmento virtuale è la causa più comune di VM che "non si vedono" pur avendo IP apparentemente corretti.

### 3. hashcat senza GPU in ambiente virtualizzato

```
clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR
ATTENTION! No OpenCL, HIP or CUDA compatible platform found.
```

Le VM non hanno accesso alla GPU, e hashcat cerca un runtime OpenCL/CUDA.

**Risoluzione:** usare **John the Ripper**, che gira su CPU senza configurazione ed è anzi la scelta più comune per il Kerberoasting. In alternativa, installare un runtime CPU (`pocl-opencl-icd`) e forzare hashcat sul device CPU con `-D 1`.

### 4. rockyou fallisce sulle password italiane

Primo tentativo di crack con una password italiana realistica (`Estate2024`): John ha girato **l'intera rockyou senza risultato**. La password era tecnicamente robusta rispetto a quel dizionario (10 caratteri, non presente in una wordlist anglofona del 2009), e nemmeno le regole di mutazione standard l'hanno generata.

**Perché è un risultato prezioso, non un fallimento:** l'efficacia del cracking dipende dal **contesto linguistico e culturale** del bersaglio. Un attaccante che colpisce un'organizzazione italiana non usa rockyou "liscia": costruisce wordlist localizzate (stagioni, mesi, città, nomi, pattern `Parola+Anno+Simbolo`) a partire da ricognizione reale. Per un test *onesto* ho poi ridotto la password di `svc_sql` a un pattern genuinamente presente in rockyou, in modo che il crack dimostrasse il concetto senza scorciatoie (nessuna password inserita a mano nella wordlist).

> Un buon test di sicurezza è onesto sulle proprie assunzioni. "L'attacco è riuscito" conta meno di "ecco cosa ho assunto, ecco cosa avrebbe potuto falsare il risultato, ecco perché le conclusioni reggono comunque".

---

## Capitolo 2 — AS-REP Roasting *(in corso)*

### La debolezza *(già configurata)*

Ho creato l'utente `j.doe` con la pre-autenticazione Kerberos disabilitata:

```powershell
Set-ADAccountControl -Identity "j.doe" -DoesNotRequirePreAuth $true
```

Senza pre-autenticazione, un attaccante può richiedere un AS-REP per l'utente **senza conoscerne la password**, ottenendo materiale craccabile offline — un Kerberoasting che non richiede nemmeno un account valido per partire.

**Attacco, traccia (Event ID 4768) e hardening:** da documentare nel prossimo ciclo.

---

## Setup riproducibile

Sequenza essenziale per ricostruire il lab (sintesi, non cronologia completa):

1. **DC01** — installazione Windows Server 2022, IP statico `192.168.56.10`, promozione a DC della foresta `lab.local` (`Install-ADDSForest`).
2. **WS01** — Windows 11, IP statico `192.168.56.20`, DNS verso il DC, join al dominio (`Add-Computer`).
3. **Debolezze volute** — OU `LabUsers`, utenti standard, `svc_sql` (SPN + password debole), `j.doe` (no preauth).
4. **Logging** — Sysmon con config su DC e WS01; auditing Kerberos/Logon via GUID su DC.
5. **Snapshot** dello stato "vulnerabile + loggato" prima di ogni attacco.
6. **Kali** — IP statico `192.168.56.100`, DNS verso il DC, Impacket + John the Ripper.

---

## Tecnologie usate

`Windows Server 2022` · `Windows 11` · `Kali Linux` · `Active Directory` · `Kerberos` · `Impacket` · `John the Ripper` · `Sysmon` · `Windows Security Auditing` · `VMware Workstation`

---

## Disclaimer

Ambiente di laboratorio isolato, costruito a scopo di studio difensivo. Tutte le tecniche sono eseguite su sistemi di mia proprietà, su una rete senza accesso a internet. Nessuna di queste attività va replicata su sistemi di terzi senza autorizzazione esplicita.
