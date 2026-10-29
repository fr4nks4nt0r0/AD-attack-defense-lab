# AD Attack And Defense Lab

Dopo essermi confrontato con alcuni esperti che hanno valutato i miei progetti precedenti, ho sviluppato questo lab più incentrato sulla sicurezza al momento dell'attacco, che sulle basi sistemistiche di networking.

È un laboratorio di simulazione di attacchi Active Directory dalla doppia prospettiva offensiva e difensiva: per ogni falla volutamente introdotta documento il ciclo:
configurazione vulnerabile, attacco, traccia difensiva, hardening e infine il re-test.

L'ambiente è un piccolo dominio di active directory virtualizzato su VMware, con un DC, un client w11, una macchina attaccante con kali linux e wazuh che gira su ubuntu server.

## Stato del lab

| # | Capitolo | Tecnica MITRE | Stato |
|---|----------|---------------|-------|
| 00 | Baseline SIEM | - | Completato | 
| 01 | Kerberoasting | T1558.003 | Parziale |
| 02 | ACL Abuse/BloodHound/DCSync | T1069.002, T1003.006 | Completo |
----------

## Architettura

| Host | Ruolo | OS | IP |
|------|-------|----|----|
| DC01 | Domain Controller e DNS | Windows Server 2022 | '192.168.56.10' |
| WS01 | Client workstation | Windows 11 | '192.168.56.20' |
| WS02 | Seconda workstation (per movimento laterale) | Windows 11 | '192.168.56.21'| 
| KALI | Macchina attaccante | Kali Linux | '192.168.56.100' |
| WAZUH | SIEM/detection | Ubuntu Server 22.04 con Wazuh 4.14 | '192.168.56.50' |

- **Dominio:** 'lab.local'
- **Rete:** host-only '192.168.56.0/24' (VMware VMnet1)
- **Hypervisor:** VMware Workstation

---

## Metodologia

Per ciascuna vulnerabilità:

1. **Introduco la falla** — configuro il sistema in modo volutamente vulnerabile
2. **Faccio l'attacco e valuto l'impatto** — eseguo l'attacco effettivo e documento il risultato.
3. **Catturo la traccia difensiva** — identifico quali log/ID registrano l'attacco e come appaiono sul SIEM.
4. **hardening** — Applico le dovute contromisure.
5. **Ripeto l'attacco** — Faccio retest ripetendo la stessa tecnica e confrontando prima e dopo.
---

## Setup del lab di base

A differenza del mio altro lab su Active Directory, dove ho usato principalmente l'interfaccia grafica, qui ho voluto lavorare con PowerShell.

NOTA: la fondazione di detection (Wazuh + Sysmon + audit policy) è documentata a parte in [`/00-baseline-siem`](./00-baseline-siem).

### Domain Controller (DC01)

IP statico e DNS verso sé stesso:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1
Rename-Computer -NewName "DC01" -Restart
```

Installazione del ruolo AD DS e promozione a nuova foresta:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns -Force
```

Test di verifica: Get-ADDomain deve restituire il dominio lab.local. I servizi ADWS, KDC, Netlogon e DNS devono risultare avviati.

### Workstation (WS01)

IP statico, DNS verso il DC, join al dominio:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.56.10
Add-Computer -DomainName "lab.local" -Credential LAB\Administrator -Restart
```

Verifica dal Domain Controller: `Get-ADComputer -Filter * | Select Name` con tutto corretto qui elenca `WS01`.

### Utenti di base

OU dedicata e utenti standard. Gli account vulnerabili specifici verranno creati nel capitolo dell'attacco relativo.
```powershell
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"

$pw = Read-Host "Password per m.rossi" -AsSecureString

New-ADUser -Name "Mario Rossi" -SamAccountName "m.rossi" -UserPrincipalName "m.rossi@lab.local" -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pw -Enabled $true
```

### Attaccante (Kali)

IP statico sul segmento e DNS verso il DC:

```bash
sudo ip addr add 192.168.56.100/24 dev eth0
echo "nameserver 192.168.56.10" | sudo tee /etc/resolv.conf
```

Nota: la configurazione di rete qui sopra riportata è temporanea, L'indirizzo deve essere riconfigurato dopo un riavvio. 
Anche la modifica di /etc/resolv.conf può essere sovrascritta da NetworkManager.

---

## PROBLEMI E SOLUZIONI

Intoppi reali incontrati durante la costruzione del lab. (Gli intoppi del deploy SIEM sono documentati in `/00-baseline-siem`.)

### Comandi in inglese che falliscono su Windows in italiano
Nomi di gruppi e categorie sono localizzati, e stavolta avevo ben pensato di installar un ISO in italiano, di conseguenza alcuni cmd trovati online non hanno funzionato finchè non sono stati riadattati.
- `Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"` → `ObjectNotFound`
- `auditpol /set /subcategory:"Kerberos Service Ticket Operations"` → `Errore 0x57: Parametro non corretto`
- `New-ADServiceAccount ... -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"` → in italiano il gruppo è "Computer del dominio"

**Risoluzione:** usare identificatori indipendenti dalla lingua, i GUID delle sottocategorie di audit e i SID/RID dei gruppi ("Domain Computers" ha sempre RID `515`).

### Workstation con indirizzo APIPA dopo il join
WS01 restava con un `169.254.x.x` (APIPA) e non raggiungeva il DC. Impostare solo il DNS non aveva assegnato un IP valido.
**Risoluzione:** assegnato esplicitamente l'indirizzo statico, prestando attenzione al nome esatto dell'interfaccia.

### hashcat senza GPU in ambiente virtualizzato
Le VM non hanno accesso alla GPU e hashcat di default la richiede.

**Risoluzione:** ho usato John the Ripper, che gira su CPU senza configurazione.

---

## Stato del lab

In costruzione attiva. 
