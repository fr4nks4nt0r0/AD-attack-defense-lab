## CAPITOLO 1 — Kerberoasting

**PREMESSA:** originariamente questo attacco è stato fatto prima di implementare la baseline con wazuh, motivo per cui uso event id. 
Ripeterò la sezione di detection sfruttando il siem.

**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting


### La debolezza

Ho creato un account di servizio, 'svc_sql', con un **Service Principal Name (SPN)** registrato e una password debole nella variabile $pw.

```powershell
# Account di servizio con SPN (simula un servizio MSSQL)
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true

Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

Gli account di servizio con password statica sono fra le misconfigurazioni più diffuse, spesso la password è stata impostata anni prima, non scade mai, ed è più debole di quanto dovrebbe perché "tanto è solo un service account".

### L'attacco

Il Kerberoasting sfrutta un comportamento legittimo di Kerberos: qualsiasi utente di dominio autenticato può richiedere un ticket di servizio (TGS) per un account con SPN. Quel ticket è cifrato con l'hash della password dell'account di servizio, e può essere SCARICATO e craccato offline localmente, dove nessun alert di login fallito o limite di tentativi può fermarlo.

Mi autentico come 'm.rossi', un utente SENZA PRIVILEGI, e richiedo i ticket di tutti gli account con SPN:

```bash
impacket-GetUserSPNs lab.local/m.rossi:'Autunno2026!' -dc-ip 192.168.56.10 -request -outputfile kerberoast.txt
```

Ottengo l'hash dell'account 'svc_sql', vcme utente senza privilegi ho estratto dal Domain Controller il materiale crittografico di un account di servizio, niente exploit ma una funzione legittima di Kerberos.

### Il cracking

Con la password debole iniziale ('Password123' nel mio caso), il crack è immediato usando una wordlist pubblica standard:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
john --show --format=krb5tgs kerberoast.txt
```

Con pochi secondi e un dizionario pubblico è fatta.

### La traccia difensiva

Subito dopo l'attacco sul Domain Controller cerco l'Event ID 4769 (richiesta di ticket di servizio Kerberos):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 20 | Format-List TimeCreated, Message
```

L'evento contiene la richiesta del ticket:

| Campo | Valore | Cosa racconta |
|-------|--------|---------------|
| Nome account | 'm.rossi@LAB.LOCAL'| L'utente non privilegiato che ha richiesto il ticket |
| Nome servizio | 'svc_sql' | L'account di servizio preso di mira |
| Indirizzo client | '192.168.56.100' | La macchina attaccante (Kali) |
| **Tipo crittografia ticket** | '0x17' | RC4|

L'evento 4769 registra la richiesta di un ticket Kerberos per un servizio.
Nel mio test, il tipo di crittografia è '0x17' (RC4-HMAC), che da solo però, non conferma un Kerberoasting: può essere presente anche per motivi di compatibilità.
In un ambiente reale lo correlerei con l'account di servizio richiesto, il numero e la frequenza delle richieste, l'utente che le ha generate e l'indirizzo sorgente.

La detection si basa quindi su una combinazione di indicatori, non sulla semplice presenza di un evento 4769.

### L'hardening e il re-test

La contromisura mira a ciò che rende l'attacco utile: la password craccabile, ho sostituito la password debole di 'svc_sql' con una lunga e casuale:

```powershell
Set-ADAccountPassword -Identity svc_sql -Reset -NewPassword (ConvertTo-SecureString "<password lunga casuale di oltre 25 caratteri>" -AsPlainText -Force)
```

Poi ho rilanciato lo stesso identico attacco,  con:

```bash
impacket-GetUserSPNs lab.local/m.rossi:'Autunno2026!' -dc-ip 192.168.56.10 -request -outputfile kerberoast_hardened.txt
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hardened.txt
```

PRIMA VS DOPO

| | Prima (password debole) | Dopo (password robusta) |
|---|---|---|
| Estrazione del ticket | riuscita | riuscita (uguale) |
| Esito del cracking | craccata in secondi ('Password123') | '0 cracked' su rockyou intera |

l'hardening non ha impedito l'attacco nè la richiesta del ticket ma l'ha reso inefficace. La superficie di attacco è invariata (qualunque utente può ancora estrarre il ticket); ciò che cambia è che una password robusta sposta il cracking da "secondi" a "computazionalmente non praticabile".

### CONCLUSIONE

- **Soluzione definitiva:** convertire gli account di servizio in **gMSA (Group Managed Service Account)**, dove la password è generata e ruotata dal sistema (120+ caratteri, rotazione automatica, mai nota a un umano). L'hash resta estraibile ma di fatto incraccabile.
!!!!! *Da implementare come prossimo passo di questo lab.* !!!!!
- **Dove la rotazione automatica non è possibile:** password lunghe e casuali sugli account di servizio, trattate come segreti ad alto valore.
- **Detection:** monitorare gli Event ID 4769 con crittografia RC4 ('0x17') richiesti per account di servizio, in particolare da endpoint anomali.
!!!!! *Da implemtantare la detection con wazuh* !!!!!
- **Riduzione della superficie:** disabilitare RC4 a livello di dominio dove compatibile, forzando AES.



