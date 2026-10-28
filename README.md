# goldencheck – PowerShell-version (läsläge)

Jämför IOS-XE running-config mot golden-profiler och visar avvikande konfiguration.
Ändrar aldrig något på enheterna. Ett enda PowerShell-skript utan installation.

## Starta
    .\run.cmd                        # startmeny (se nedan)

    .\run.cmd -Group access          # en grupp ur hostlistan
    .\run.cmd -Group access,dc       # flera grupper
    .\run.cmd -All                   # alla enheter

    .\run.cmd -Target 10.0.0.55 -Template access-switch   # en specifik switch mot vald template
    .\run.cmd -Device CA03-01 -Template dc-switch         # inventory-enhet mot annan template än sin egen

    .\run.cmd -Offline samples -Group access              # testa utan enheter (samples\<enhet>.cfg)

`run.cmd` startar skriptet med `-ExecutionPolicy Bypass`. Utan `-Group/-Device/-Target/-All` visas menyn.
Exit-kod: 0 = rent, 1 = avvikelser/fel, 2 = felaktigt argument / inget val.

### Startmenyn
    1) Scanna hostlista (välj grupp, t.ex. access / DC)   -> välj en eller flera grupper, eller A = alla
    2) Scanna en specifik switch (välj template)          -> ange enhetsnamn ur inventory eller en ny IP/host,
                                                             välj sedan template (Enter = enhetens standard)

## Enkelt läge: `switches.csv` + `golden\` (rekommenderas)

Istället för att skriva `inventory.psd1`/`profiles.psd1` i PowerShell-syntax kan ni lägga switcharna i en
vanlig CSV-fil och golden config i vanliga textfiler med riktig IOS-syntax. Finns filerna/mappen bredvid
skriptet används de automatiskt – inga flaggor behövs. De två lägena kan också blandas (se "Hur de hänger ihop" nedan).

### `switches.csv` – listan över switchar
Rubrikrad krävs. Avgränsare `;` eller `,` (gissas automatiskt från rubrikraden – `;` rekommenderas, så Excel inte
tolkar om kolumner som tal).

```
name;host;group;template
CA03-01;10.70.0.10;access;access-switch
CB02-01;10.70.0.20;access;access-switch
DC-SW-01;10.70.0.5;dc;dc-switch
```
- `name` – namnet som visas i rapporten (fritt, bindestreck går bra utan citationstecken).
- `host` – IP eller hostnamn att ansluta till. **Krävs.**
- `group` – bara en etikett för startmenyns gruppval (`-Group access`). Valfri.
- `template` – vilken golden-fil (se nedan) switchen ska jämföras mot. **Krävs** (ingen gruppstandard i detta läge –
  ange template direkt på varje rad, så är det alltid tydligt vad en switch kontrolleras mot).

Valfria extrakolumner: `transport` (`plink` eller `ssh`), `key` (sökväg till nyckelfil), `port` (annan SSH-port än 22),
`plink_path` (egen plink.exe för just den enheten), `hostkey` (pinnad värdnyckel, t.ex. `SHA256:...`, istället för cache).

Filen läses med `-Switches <fil>` om den inte heter `switches.csv` och ligger bredvid skriptet.

### `golden\` – golden config i vanlig IOS-syntax
En textfil per template, t.ex. `golden\access-switch.txt`. Filnamnet (utan `.txt`) är templatets namn –
samma namn som i `template`-kolumnen i `switches.csv`. Skriv raderna precis som de står i `show running-config`,
med indrag för rader som hör till en rad ovanför (exakt som en riktig konfig):

```
# extra: on
# extra_ignore: ^vlan \d+$

hostname <ANY>
service password-encryption
~ ip http server

aaa group server tacacs+ TACACS-GRP
 server name TACACS01
 server name TACACS02
 ip tacacs source-interface Vlan1700

line vty 0 4
 access-class ALLOW-SSH in
 logging synchronous
 transport input ssh
 ~re:transport input .*telnet
```

Syntax:
| skrivsätt | betyder |
|---|---|
| en vanlig rad | måste finnas exakt (**required**) |
| `~` framför en rad | raden får **inte** finnas (**forbidden**) |
| `?` framför en rad | raden krävs inte, men flaggas heller **aldrig** som extra/avvikande om den finns. Skiljer sig från att bara utelämna raden – det spelar bara roll när `# extra: on` är satt (annars är allt som inte står i filen redan tyst). På en rad med indragna rader under sig (t.ex. `? aaa server radius dynamic-author`) ignoreras hela avsnittet – inget krav, ingen kontroll av barnen, och det visas aldrig som en extra toppnivårad. |
| indrag under en rad | hör till den raden (ett "avsnitt", t.ex. `aaa group server ...`, `line vty 0 4`). Hela avsnittet flaggas som saknat om förälderraden inte finns alls; annars kontrolleras bara de indragna raderna. |
| `<ANY>` | ett godtyckligt ord/värde på den platsen (hostnamn, IP, tid, …) – blir automatiskt ett regex |
| `<re:eget uttryck>` | eget regex när `<ANY>` inte räcker (t.ex. `<re:\d+ \d+>` för två tal) |
| `re:eget uttryck` i början av en rad | hela raden är ett eget regex (fri kontroll, samma konvention som i `profiles.psd1`) |
| `~re:eget uttryck` | förbjuden rad som ett eget (icke-ankrat) regex – t.ex. `~re:transport input .*telnet` flaggar oavsett vad som står före `telnet` |
| `# kommentar` | ignoreras |
| `# extra: on` | flaggar rader på enheten som inte finns i golden alls (toppnivå + rader i kända avsnitt) – motsvarande `extra = $true` i `profiles.psd1` |
| `# extra_ignore: mönster` | undantag från extra-kontrollen (kan upprepas) |
| `# port_check: off` | hoppa över all portkontroll (`NO_PROFILE`) för denna template tills ni skrivit portprofiler (klient/uplink/SVI finns bara i `profiles.psd1` ännu, se "Begränsning" ovan). `on` slår på igen (standard). |

Mappen läses med `-GoldenDir <mapp>` om den inte heter `golden` och ligger bredvid skriptet.

**Begränsning:** det som styrs av golden-filerna är den **globala** konfigen (allt utanför interface). Vilken
profil varje porttyp (klientport, uplink, SVI osv.) ska ha styrs fortfarande av `interface_rules`/`interface_profiles`
i `profiles.psd1` (avancerat läge, se nedan) – det går bra att bara ha den biten kvar i `.psd1` och resten i `golden\`.
Säg till om ni vill att port-profilerna också ska gå att skriva i vanlig textform; det är en rimlig nästa utbyggnad.

### Hur de hänger ihop med `.psd1`-filerna
- `switches.csv` **ersätter helt** `devices`-listan i `inventory.psd1` när filen finns. `templates`/`groups`/`defaults`
  i `inventory.psd1` fortsätter gälla om filen finns (t.ex. för att behålla `interface_rules` på en template);
  annars används bara det `golden\`-filerna ger.
- `golden\<namn>.txt` skriver in sig som den globala profilen för templaten `<namn>` (skapar templaten om den
  inte redan finns i `inventory.psd1`, annars behåller den `interface_rules`/`description` men byter ut `global`).
- Finns varken `switches.csv` eller `golden\` används `inventory.psd1`/`profiles.psd1` precis som förut (avancerat läge,
  se "Templates, grupper och enheter" och "Att tänka på i .psd1-filerna" nedan) – inget av detta är ett krav.
- Ni kan alltså ha `switches.csv` men fortfarande skriva golden config i `profiles.psd1`, eller tvärtom.

## CSV: bara avvikande konfiguration
Varje körning skriver `reports\goldencheck_<datum_tid>.csv` (stäng av med `-NoCsv`, eget namn med `-Csv fil.csv`).
UTF-8 med BOM och semikolon, så den öppnas direkt i Excel. En rad per avvikelse:

| kolumn | innehåll |
|---|---|
| device, host, group, template, profile | enhet, vilken template den jämfördes mot och vilken global profil som användes (t.ex. `global:baseline-access`) |
| scope | `global`, port (`GigabitEthernet1/0/2`), eller avsnitt (`line vty 0 4`, `vlan 999`) |
| kind | `MISSING` = raden saknas, `EXTRA` = raden finns men ingår inte i golden, `FORBIDDEN` = förbjuden rad (se "Vad flaggas") |
| severity | hög (förbjuden) / medel (saknas) / låg (extra) |
| line | konfigraden. Regex-krav visas som "Saknar rad som matchar: ...". För `FEL`: felmeddelandet |

Rena enheter ger inga rader. **Enheter som inte kunde skannas kommer med som `FEL`-rader** så att en saknad enhet aldrig kan misstas
för en ren enhet, och skriptet skriver en OBS-rad med namnen. Portar utan profil (`NO_PROFILE`) visas bara på skärmen.
Hela konsolutskriften (inklusive tabellen "Per enhet") sparas också som `.txt` bredvid CSV:n.

**`-WithActions`** ger den utökade åtgärdsfilen: alla ovanstående plus `context`, `profile`, `action`, `command`, `ordning`,
samt rader för `NO_PROFILE` och `FEL`. Kommandona är förslag och körs aldrig automatiskt. `ordning` 1 = ta bort (gör först),
2 = lägg till, 0 = inget kommando. Där en rad bara byter värde (t.ex. VLAN 10 -> 666, IP-adress på Vlan1700) står
"Åtgärdas av att raden ... läggs till/ändras" i stället för ett `no`-kommando. Läs igenom innan något klistras in på en enhet.

**`-Xlsx`** skriver samma innehåll som CSV:n även som en riktig `.xlsx`-fil bredvid (`goldencheck_<datum_tid>.xlsx`), med
kolumnbredd anpassad efter innehållets längd. En CSV-fil har ingen formatering alls förrän den öppnas, så "lämplig bredd" går
bara att få i ett riktigt Excel-format – `.xlsx`-filen byggs direkt med .NET:s inbyggda zip/XML-stöd, ingen modul behövs.

## Vad flaggas, och vad flaggas inte?
| typ | betyder | gäller |
|---|---|---|
| `MISSING` | en rad i golden finns inte på enheten (även om värdet är annorlunda) | global config, avsnitt (`line vty`, `vlan`), interface |
| `EXTRA` | en rad på enheten som golden inte känner till | interface (alltid), global config och underrader under kända avsnitt (när profilen har `extra = $true`) |
| `FORBIDDEN` | en rad som matchar ett förbjudet mönster | överallt |

Ändras ett värde på en switch (t.ex. `spanning-tree ... priority 4096` i stället för `61440`) får du **både** `MISSING` (vad golden vill ha)
och `EXTRA` (vad switchen har). Tas en rad bort ur golden får switchen `EXTRA` för den.

**Globala EXTRA** styrs av `extra = $true` i den globala profilen (påslaget i `baseline-access`). Rader som alltid ignoreras är
IOS-XE-boilerplate (`Building configuration`, `version`, `end`, `!`-kommentarer, CPP-standardpolicys, `switch N provision`, `crypto pki ...`, `vrf definition Mgmt-vrf`, `call-home`). Fler undantag läggs i
`extra_ignore` (regex) i profilen. `interface`-rader hanteras av interface-profilerna, inte här.
Första körningen mot riktiga switchar ger troligen en del "extra" som är legitim konfiguration: tabellen
**"Vanligaste extra-rader utanför interface"** i slutet visar vad som finns på flest enheter, så att du snabbt kan lägga dem i golden eller `extra_ignore`.

**Kontrolleras bara att något finns, inte värdet** (regex `re:` i profilen): hostname, klockzon/sommartid, domännamn, VTP-domän,
SNMP-community och -location, enable secret, minnesgräns, lokal `username` (antal och namn jämförs inte) samt att en banner finns (inte texten).
Ändras ett sådant värde på en switch flaggas det inte. Vill ni låsa ett värde, byt regexet mot den exakta raden (som redan gjorts för
`ntp server`, `logging host` och `ip default-gateway`).

**Per enhet-tabellen** i slutet av varje körning med flera enheter visar status för varje enhet (OK / AVVIKER / FEL) och antal konfigrader som lästes,
så att man ser att alla enheter faktiskt skannades.

## Felsökning: en enhet saknas eller något ser fel ut
1. Titta i tabellen **"Per enhet"** sist i utskriften (eller `FEL`-raderna i CSV:n). Varje enhet ska stå där som OK, AVVIKER eller FEL.
2. **`FEL: ... Host key is not cached`** är vanligast vid första körningen mot nya switchar: plink kör med `-batch` och kan inte fråga om värdnyckeln.
   Kör `.\run.cmd -Group access -CacheHostKeys`. Verktyget visar varje switchs fingeravtryck och frågar innan nyckeln sparas
   (`j` = ja, `n` = hoppa över, `a` = ja för alla återstående, `q` = avbryt). Ingen konfig hämtas. Fingeravtrycken sparas i
   `reports\hostkeys_<tid>.txt`. Jämför gärna med en känd lista; svarar du `a` litar du på den nyckel varje switch visar första gången
   (trust on first use). Kör sedan skanningen igen. Gäller plink; ssh.exe sköter sina värdnycklar själv (`known_hosts`).
   Lösenord efterfrågas automatiskt om någon enhet saknar nyckelinloggning (`key` i inventory/`switches.csv`) - annars hänger plink på
   lösenordsprompten efter att nyckeln godkänts och timar ut. En enhet som strular (fel lösenord, nätfel, trasig `plink_path` m.m.)
   loggas som `fel: ...` och stoppar inte resten av listan. Vill du slippa svara `j`/`a` helt (t.ex. ett obevakat jobb), lägg till
   `-AcceptAllHostKeys` - alla nycklar cachas direkt utan fråga (fortfarande loggat i `hostkeys_<tid>.txt`), vilket är samma
   tillit som SSH normalt bygger på (trust on first use), bara utan den manuella granskningen av fingeravtrycket.
3. **Sparade konfigurationer:** kör med `-SaveConfigs` så sparas varje hämtad konfig i `reports\configs_<tid>\`. Sedan kan du iterera på golden och
   `extra_ignore` utan att röra switcharna: `.\run.cmd -Offline reports\configs_<tid> -Group access` (filnamnen är enhetsnamnen). Filerna innehåller
   lösenordshashar och nycklar: behandla dem som känsliga och ta bort dem när du är klar.
4. **Profilerna `baseline` och `baseline-access`** i `profiles.psd1` innehåller delvis samma rader. Access-templaten använder `baseline-access`:
   ändra där (kolumnen `profile` i CSV:n visar vilken som användes). Sök efter raden i hela filen (t.ex. `login on-failure`) så att du hittar alla förekomster.
5. Bannertext läses som en enda rad (`banner ...`) även om slutavgränsaren (`^C`) saknas i utskriften: bannern avslutas då vid nästa `!`-rad.

## Filer
- `goldencheck.ps1`      – verktyget (Windows PowerShell 5.1 eller PowerShell 7)
- `switches.csv`         – exempel på enkel switchlista (påhittade enheter – ersätt med era egna)
- `golden\`              – exempel på golden config i enkel textform (påhittade värden – ersätt med er egen)
- `profiles.psd1`        – golden-profiler, avancerat läge (regex, port-profiler, mallvariabler; skapas själv, medföljer inte i repot)
- `inventory.psd1`       – templates, grupper och enheter, avancerat läge (skapas själv, medföljer inte i repot)
- `reports\`            – rapporter från körningar; ignoreras av `.gitignore` så att riktiga konfigar inte råkar publiceras
- `samples\`             – egna exempelkonfigar för offlinetest (medföljer inte i repot)
- `plink.exe`            – lägg PuTTYs plink bredvid skriptet (eller i PATH) om ni använder plink

## Avancerat läge: templates, grupper och enheter (inventory.psd1)
(Används bara om ni inte kör enkla läget ovan, eller för delar ni vill ha kvar i `.psd1` – t.ex. `interface_rules`.)
- **templates** = vad en enhet jämförs mot: `global` (profil i profiles.psd1) + `interface_rules` + `report_unmatched`.
- **groups** = grupper i hostlistan (access, dc, ...) med en standardtemplate.
- **devices** = `host` + `group` (och valfri egen `template`). Namn med bindestreck (`CA03-01`) går bra.
- Template som används: `-Template`/menyval > enhetens egen `template` > gruppens `template`.
  Valt `-Template` ersätter enhetens egna `global/interface_rules/vars`; host, transport och nyckel behålls.

## Template `access-switch` (byggd ur golden config för access-switch)
Global profil `baseline-access` (≈80 rader + 17 avsnitt: AAA/TACACS/RADIUS, VLAN 666/999/1700/1710, STP, errdisable,
SSH/HTTP-härdning, SNMP, VTY/console m.m.) och interface-profiler:
- `access-client` – klientportar `GigabitEthernet<n>/0/<n>`: exakt golden (VLAN 666, 802.1X/MAB m.m.). Nedstängda portar
  (`shutdown`) räknas inte som avvikelse. Övriga oväntade rader på en klientport visas som `EXTRA`.
- `uplink-access` – `Port-channel<n>`,  `svi-default` – `Vlan1`,  `svi-mgmt` – `Vlan1700`.

**IP-adressen på Vlan1700** är enhetsspecifik. Som standard kontrolleras bara att adressen ligger i `10.70.0.x/24`
(`re:^ip address 10\.70\.0\.\d{1,3} 255\.255\.255\.0$` i profilen `svi-mgmt`). Vill ni i stället kräva att den är samma som
enhetens `host` i inventory, byt raden mot `'ip address {{ host }} 255.255.255.0'` (då måste `host` vara IP-adressen).

Värden som skiljer sig per enhet kontrolleras med mönster (`re:`), se ovan. `ntp server`, `logging host` och `ip default-gateway`
är låsta till golden-värdena (alla switchar i `10.70.0.x`) – ändra i `profiles.psd1` om något varierar.

**Inte kontrollerat**: innehållet i ACL:erna `ALLOW-SSH`/`ALLOW-SNMP` (bara att de finns), underrader två nivåer ner
(t.ex. `archive` → `log config` → `logging enable`), bannertexten, samt okända interfaces som inte är fysiska portar (t.ex. `Vlan1710`, `Loopback0`).
Portar som inte matchar någon regel (t.ex. `TenGigabitEthernet1/1/x`) visas som `NO_PROFILE` på skärmen.

## Hämta konfig live
- **plink (standard):** `plink -ssh -batch -T ... "show running-config"`. Föredra `key = 'C:\keys\net.ppk'` (inget lösenord).
  Med lösenord (`NET_PASS`/prompt) skickas det via `-pw` och syns kort i processlistan lokalt.
  Värdnyckeln måste vara cachad (anslut en gång manuellt) eller anges som `hostkey = 'SHA256:...'`.
- **ssh:** `transport = 'ssh'` använder Windows OpenSSH (`ssh.exe`); kräver nyckelinloggning. Extra flaggor: `ssh_options`.
- Användare: miljövariabeln `NET_USER` eller prompt. Enheterna skannas en i taget.

## Är det säkert att köra under drift?
Det enda som skickas till en enhet är det fasta kommandot `show running-config`, som en enda exec-sats (`-T`, `-batch`).
Skriptet har ingen kodväg som går in i konfigläge eller skickar något annat. Men "bara show" är inte samma som "utan spår":
- `show running-config` belastar CPU en kort stund på stora konfigar. Enheter tas en i taget, inte parallellt.
- Varje inloggning och kommando syns i era loggar (TACACS accounting, `login on-success log`, syslog). Meddela säkerhets-/driftteamet.
- Kontot avgör vad som *kan* hända. Använd ett dedikerat konto, helst med TACACS-kommandoauktorisering som bara tillåter
  `show running-config`. Kontot behöver privilege 15 för det kommandot.
- Testa första gången mot EN enhet (`-Device`/`-Target`), och kontrollera med `show users` att sessionen stängs.

## Att tänka på i .psd1-filerna
- Namn med bindestreck (t.ex. `CA03-01`) går bra: skriptet lägger själv till citationstecknen om de saknas.
  Vid andra syntaxfel visas radnummer och vad parsern klagar på.
- Strängar i enkla citationstecken; ett enkelt tecken inuti skrivs två gånger (`''`). Bara data, inga variabler/uttryck.
- Mallar stöder enkla `{{ variabel }}` (`vlan`, `host`, `interface`, `description` samt egna `vars`).
- `required` på toppnivå ska även innehålla föräldrarader som `vlan 666` och `line vty 0 4`; annars upptäcks det inte om hela avsnittet saknas.
- Filerna är sparade med BOM (krävs av Windows PowerShell 5.1 för å/ä/ö). Spara inte om dem i en editor som tar bort den.
- `profiles.yaml` (Python-versionen) är inte synkad med `profiles.psd1`.

## Om servern är låst
- **Execution policy:** använd `run.cmd`. Blockerade filer: `Get-ChildItem -Recurse | Unblock-File`.
- **Constrained Language Mode (AppLocker/WDAC):** skriptet använder .NET-anrop som då blockeras. Använd i så fall Python-varianten som .exe.

## Verifiering
Skärmrapporten är jämförd rad för rad mot Python-versionen (identisk) med de ursprungliga profilerna; körd av användaren på Windows PowerShell 5.1.
Access-templaten är testad mot den inskickade golden config (0 avvikelser) och en variant med inlagda fel, på PowerShell 7.
Inte körd mot riktig IOS-XE.
