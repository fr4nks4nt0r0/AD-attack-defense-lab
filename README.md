# AD-attack-defense-lab

Dopo essermi confrontato con alcuni esperti che hanno valutato i miei precedenti progetti mi sono impegnato a svilupparne un nuovo più incentrato sulla sicurezza vera e propria al momento dell'attacco che sulle basi sistemistiche di network ecc come i precedentiLaboratorio di simulazione attacchi informatici da prospettiva offensiva e difensiva, con seguente hardening per studiare le tecniche di attacco e le relative contromisure, documentando per ogni debolezza il ciclo completo: configurazione vulnerabile, poi attacco, la traccia difensiva, l' hardening e il re-test.

L'ambiente è un piccolo dominio Active Directory virtualizzato su VMware, formato da un DC, una workstation di dominio e una macchina attaccante.
Ogni vulnerabilità introdotta è volontaria.

INDICE ATTACCHI
| Attacco |	MITRE ATT&CK | Stato | Capitolo |
|------|-------|----|----|
| Kerberoasting |	T1558.003 |	IN CORSO | Completo |	/kerberoasting |
| DCSync |	T1003.006 |	Da cominciare | // |
| Pass-the-Hash / Movimento laterale |	T1550.002 |	Da cominciare | // |
| Abuso di delega |	T1558.001 |	Da cominciare | // |




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

1. **Introduco la falla** — configuro l'oggetto AD in modo volutamente vulnerabile e spiegando perché quella configurazione è realistica.
2. **Attacco e valuto l'impatto** — eseguo la tecnica dalla macchina attaccante e vedo cosa ottengo.
3. **Catturo la traccia difensiva** — identifico quali log e quali ID registrano l'attacco.
4. **Applico l'hardening** — introduco la contromisura.
5. **Ripeto l'attacco identico confrontando risultati** — stesso comando, e confronto il risultato prima/dopo.


-----------
## Setup del lab
Diversamente dalla mia altra esperienza con active directory dove ho usato molto l'interfaccia grafica ho voluto sperimentare powershell che di cui avevo cominciato a studiare le basi.

DOMAIN CONTROLLER (DC01)

IP statico e DNS verso sé stesso:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1
Rename-Computer -NewName "DC01" -Restart
```

Installazione del ruolo AD DS e la promozione a nuova foresta:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns -Force
```

Verifica: `Get-ADDomain` deve restituire `lab.local`, seguito da `Get-Service ADWS,KDC,Netlogon,DNS` che devono tutti essere in stato `Running`.

WORKSTATION CLIENT (WS01)

IP statico, DNS verso il DC, poi join al dominio:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.56.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.56.10
Add-Computer -DomainName "lab.local" -Credential LAB\Administrator -Restart
```

Verifiva del DC: `Get-ADComputer -Filter * | Select Name` dove deve esserci `WS01`.

UTENTI E FALLE VOLUTE

OU dedicata, utenti standard, e l'account di servizio vulnerabile al Kerberoasting:

```powershell
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"

$pwNormale = ConvertTo-SecureString "Autunno2026!" -AsPlainText -Force
New-ADUser -Name "Mario Rossi" -SamAccountName "m.rossi" -UserPrincipalName "m.rossi@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pwNormale -Enabled $true

# Account di servizio con SPN (debolezza del Capitolo 1)
$pwDebole = ConvertTo-SecureString "Password123" -AsPlainText -Force
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pwDebole -Enabled $true -PasswordNeverExpires $true
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

LOGGING 

Sysmon su DC01 e WS01, con una configurazione standard (es. SwiftOnSecurity):

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" | Select LogName,RecordCount
```

Auditing Kerberos/Logon sul DC, tramite GUID delle sottocategorie (butta un occhio su "PROBLEMI E SOLUZIONI"):

```powershell
# Kerberos Service Ticket Operations (Event ID 4769)
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Kerberos Authentication Service (Event ID 4768)
auditpol /set /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Logon (Event ID 4624/4625)
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

ATTACCANTE - KALI

IP statico sul segmento e DNS verso il DC:

```bash
sudo ip addr add 192.168.56.100/24 dev eth0
echo "nameserver 192.168.56.10" | sudo tee /etc/resolv.conf
```

Strumenti usati per kerberosting: Impacket e John the Ripper.

----------

## !!!!!!!!!!  PROBLEMI E SOLUZIONI  !!!!!!!!!!

### Comandi in inglese che falliscono su Windows Server in italiano

Più volte comandi presi da guide anglofone hanno fallito perché i nomi di gruppi e categorie sono localizzati a seconda del sistema, e stavolta ho scaricato una ISO in italiano:

- `Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"` → `ObjectNotFound`
- `auditpol /set /subcategory:"Kerberos Service Ticket Operations"` → `Errore 0x00000057: Parametro non corretto`
- `New-ADServiceAccount ... -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"` → in italiano il gruppo è----> Computer del dominio

**Risoluzione:** usare identificatori indipendenti dalla lingua, i GUID delle sottocategorie di audit e i SID/RID dei gruppi (Ad esempio "Domain Computers" ha sempre RID "515").

### Workstation con indirizzo APIPA dopo il join

WS01 restava con un indirizzo "169.254.x.x" (APIPA) e non raggiungeva il DC (dando sul ping un errore generale). Impostare solo il DNS non aveva assegnato un IP valido.

**Risoluzione:** ho assegnato esplicitamente l'indirizzo statico, prestando attenzione al nome esatto dell'interfaccia.

### hashcat senza GPU in ambiente virtualizzato

Le VM non hanno accesso alla GPU e hashcat di defaut la richiede

Risoluzione: uso di John the Ripper, che gira su CPU senza configurazione 
