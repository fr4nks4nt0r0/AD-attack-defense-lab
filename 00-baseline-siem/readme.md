# 00 — Baseline detection + SIEM

Prima di attaccare niente serve un SIEM, ho scelto Wazuh nel mio caso, con Sysmon e l'audit policy a produrre gli eventi giusti.

Premetto che in questa sezione non farò hardening, disattivare LLMNR, correggere le ACL ecc è una parte di ogni di ciascun capitolo, come contromisura specifica. 

STRUTTURA NELLA CARTELLA /topologia



### SETUP DEL SIEM

Due schede di rete: **NAT** (internet temporaneo per l'installazione) + **host-only VMnet1** (segmento del lab). IP statico `.50` sulla scheda host-only via netplan:

```yaml
network:
  version: 2
  ethernets:
    ens33:            # scheda NAT
      dhcp4: true
    ens37:            # scheda host-only
      dhcp4: false
      addresses:
        - 192.168.56.50/24
```

```bash
sudo netplan apply
```

setup effettivo di Wazuh:

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Lo script stampa a fine installazione la password dell'utente admin, la dashboard su "https://192.168.56.50".

Verifica servizi:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

### 2. Agente su DC01 e WS01

Download dell'MSI (con NAT temporaneo attivo) e installazione indicando ip del manager e il nome agente su DC01.

```powershell
msiexec.exe /i "C:\Users\Administrator\wazuh-agent-4.14.6-1.msi" `
  WAZUH_MANAGER="192.168.56.50" WAZUH_AGENT_NAME="DC01"
Start-Service WazuhSvc
Get-Service WazuhSvc      # deve risultare Running
```

Stessa procedura su WS01 cambiando ovviamente il nome agente con `WAZUH_AGENT_NAME="WS01"`.

### 3. Collezione dei log

L'agente di default non legge il canale Sysmonm in `C:\Program Files (x86)\ossec-agent\ossec.conf`, dentro `<ossec_config>` e prima della sua chiusura ho aggiunto ad entrambi gli agents:

```
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

E poi:
```powershell
Restart-Service WazuhSvc
```

### SYSMON

Config di riferimento (SwiftOnSecurity) su DC01 e WS01:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### AUDIT DI POLICY


```powershell
# Logon/Logoff → 4624, 4625
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Directory Service Access → 4662
auditpol /set /subcategory:"{0CCE923B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Directory Service Changes → 5136
auditpol /set /subcategory:"{0CCE923C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

auditpol /get /category:*   # verifica
```
--------------------

## PROBLEMI E SOLUZIONI

**`NET START WazuhSvc` → "Nome di servizio non valido"**
Il comando falliva perché il servizio non esisteva ancora / il nome non veniva risolto da `NET`.
→ Risoluzione: usare `Start-Service WazuhSvc`, più affidabile in PowerShell. In generale, verificare prima l'esistenza del servizio con `Get-Service WazuhSvc`.


**`msiexec` → "Impossibile aprire il pacchetto di installazione"**
Il comando veniva lanciato da `C:\WINDOWS\system32` mentre l'MSI era in `C:\Users\Administrator`. Con il nome file "nudo", msiexec cerca il pacchetto nella cartella corrente e non lo trova.
→ Risoluzione: usare il **percorso assoluto** dell'MSI, oppure `cd` nella cartella giusta prima di lanciare.


**La config Wazuh di default filtra Event ID che servono**
Il blocco `<localfile>` per il canale `Security` include una `<query>` che **esclude** diversi Event ID con `!=`, tra cui il **4662** e il **4670**.
→ Vedi *Debiti aperti*: il 4662 è l'evento chiave per la detection dell'ACL abuse (cap. 02). Con il filtro attivo, l'attacco non comparirebbe nel SIEM anche se l'evento viene generato sul DC.

---

## Cosa fa la baseline (oltre alla raccolta)

Appena attivo, Wazuh ha prodotto da solo materiale utile ai capitoli futuri:

- **Security Configuration Assessment** — scansione CIS *Microsoft Windows 11 Enterprise Benchmark v3.0.0* su WS01: **116 passed, 357 failed, score 24%**. Ogni check fallito è una potenziale contromisura documentabile nei capitoli di hardening.
- **Vulnerability Detection** — inventario pacchetti e vulnerabilità per agente.

[screenshot: dashboard WS01 — agente Active, versione 4.14.6, IP .20]
[screenshot: Events count evolution con i picchi dei logon di test]
[screenshot: Security Configuration Assessment — CIS benchmark score 24%]

---

## Verifica finale

La baseline è completa quando:

- [x] Dashboard Wazuh raggiungibile su `https://192.168.56.50`
- [x] DC01 e WS01 **Active** tra gli agenti
- [x] Evento di test (logout/login su WS01) visibile nella dashboard in tempo reale
- [x] NAT rimosso: lab isolato, log ancora in arrivo

---

## Debiti aperti

Da chiudere **prima** dei capitoli indicati:

1. **Filtro `<query>` sul canale Security** — rimuovere l'esclusione di **4662** (e valutare 4670) dalla config dell'agente sul DC, altrimenti la detection dell'ACL abuse non scatta. → Prima del **cap. 02 (ACL abuse)**.
