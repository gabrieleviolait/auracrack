# Aura Security Suite

**Credits:** [Gabriele Viola](https://gabrieleviola.it/)

[![CI](https://github.com/gabrieleviolait/auracrack/actions/workflows/ci.yml/badge.svg)](https://github.com/gabrieleviolait/auracrack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

## Cos'è

Aura Security Suite è un'applicazione desktop open source che riunisce strumenti di base per l'audit di password, l'inventario dei servizi di rete e il monitoraggio del traffico TCP. È pensata per formazione, laboratori personali, amministrazione di rete e verifiche svolte con autorizzazione esplicita.

La suite offre un'unica interfaccia con tre schede:

- **Password Audit:** verifica hash tramite wordlist locale;
- **Network Scanner:** individua servizi TCP comuni su reti IPv4 private autorizzate;
- **Traffic Monitor:** mostra metadati TCP in tempo reale senza leggere payload o credenziali.

È uno strumento leggero di prima analisi: non certifica la sicurezza di un sistema, non sfrutta vulnerabilità e non sostituisce strumenti o procedure professionali.

## Installazione

Requisiti:

- Python 3.10 o successivo;
- Windows, macOS o Linux con ambiente grafico;
- Npcap e privilegi amministrativi su Windows per alcune funzioni Scapy.

```powershell
py -3 -m pip install -r requirements.txt
```

## Avvio

Su Windows fai doppio clic su **`Avvia Aura Suite.bat`**, oppure esegui:

```powershell
py -3 main.py
```

## Moduli

### Password Audit

Controlla se un hash corrisponde a una parola contenuta in una wordlist scelta dall'utente.

Algoritmi supportati:

- MD5;
- SHA-1;
- SHA-256;
- SHA-512.

L'elaborazione avviene localmente e può essere interrotta. I risultati sono mascherati nell'interfaccia; l'export CSV contiene invece la password in chiaro e deve essere trattato come dato sensibile.

MD5 e SHA-1 sono inclusi soltanto per audit di sistemi legacy. Per nuove applicazioni è preferibile usare Argon2id, scrypt o bcrypt con salt.

### Network Scanner

Esegue un controllo TCP limitato a una rete IPv4 privata non più grande di `/24`. La suite rifiuta reti pubbliche e intervalli più estesi.

La scansione veloce controlla le porte più comuni; l'audit completo include:

| Porta | Servizio indicativo |
|---:|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 80 / 8080 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 515 | LPD |
| 631 | IPP |
| 3389 | RDP |
| 9100 | JetDirect |

Il nome del servizio deriva dalla porta: non dimostra quale software sia realmente in esecuzione. Una porta aperta non equivale automaticamente a una vulnerabilità.

### Traffic Monitor

Usa Scapy per osservare metadati TCP:

- timestamp;
- IP e porta di origine;
- IP e porta di destinazione.

Il filtro BPF predefinito è `tcp` e può essere modificato. Il modulo integrato non legge il payload, non estrae password e non decritta traffico cifrato. I metadati possono essere esportati in JSON.

## Struttura del progetto

```text
main.py
aura_suite/
├── password_audit.py
├── network_scanner.py
└── traffic_monitor.py
```

Gli script `auracrack.py`, `auracrack2.py` e `auracrack3.py` restano disponibili come versioni legacy indipendenti. Per i nuovi utilizzi è consigliata la suite avviata tramite `main.py`.

## Limiti

- lo scanner controlla solo IPv4 private fino a `/24`;
- firewall e dispositivi che non rispondono possono produrre falsi negativi;
- lo scanner non esegue banner grabbing, scansioni UDP o verifica delle versioni;
- i nomi dei servizi sono dedotti dalle porte;
- il monitor richiede un backend di cattura compatibile con Scapy;
- risultati e segnalazioni richiedono sempre verifica manuale.

## Sicurezza e privacy

- limita ogni attività a dispositivi e reti inclusi nell'autorizzazione;
- usa filtri e intervalli più ristretti possibile;
- non analizzare reti pubbliche, condivise o appartenenti a terzi;
- proteggi e cancella tempestivamente CSV, JSON, wordlist e altri dati sensibili;
- interrompi l'attività se vengono raccolti dati estranei allo scopo concordato;
- non inserire hash o password di terzi senza consenso.

## Disclaimer

Aura Security Suite è fornita esclusivamente per formazione, amministrazione, recupero di credenziali proprie e test di sicurezza su sistemi, hash, dispositivi e reti propri o coperti da autorizzazione esplicita. La scansione o il monitoraggio non autorizzati possono violare leggi, contratti, norme sulla privacy, segreto delle comunicazioni e policy aziendali.

L'utente è l'unico responsabile della definizione dello scopo, dell'ottenimento dei permessi, della base giuridica e della gestione dei dati raccolti. Gli autori e i contributori non autorizzano attività illecite e non rispondono di danni, interruzioni, perdita di dati o conseguenze legali derivanti dall'utilizzo del software.

Il software è fornito “così com'è”, senza garanzie espresse o implicite. I risultati sono indicativi e devono essere confermati con strumenti e procedure professionali prima di prendere decisioni operative.

## Contributi e sicurezza

Leggi [CONTRIBUTING.md](CONTRIBUTING.md) prima di proporre modifiche. Le vulnerabilità non devono essere pubblicate nelle issue: segui la procedura descritta in [SECURITY.md](SECURITY.md).

## Licenza

Distribuito sotto licenza [MIT](LICENSE). Il disclaimer e i limiti d'uso descrivono lo scopo previsto del progetto; verifica sempre le leggi applicabili nella tua giurisdizione.
