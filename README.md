# Hoong-systemScope

Ein lokales, transparentes und standardmäßig schreibgeschütztes Diagnosewerkzeug
für Windows 10 und Windows 11, nach dem Vorbild von HijackThis.

Hoong-systemScope erfasst Autostartpunkte, Dienste, Treiber, geplante Aufgaben
und laufende Prozesse, prüft digitale Signaturen und SHA-256-Hashes, bewertet
auffällige Konfigurationen **nachvollziehbar** und exportiert das Ergebnis als
JSON, Text oder CSV. Zwei Scans lassen sich miteinander vergleichen.

> **Hoong-systemScope ist ein Diagnosewerkzeug und kein Virenscanner.**
> Es sagt dir, was auf deinem System konfiguriert ist und warum ein Eintrag
> ungewöhnlich aussieht. Es kann dir nicht sagen, dass etwas bösartig ist.

## Was das Werkzeug nicht tut

Diese Zusagen sind nicht nur dokumentiert, sondern technisch durchgesetzt:

* Es löscht **keine** Dateien und entfernt **keine** Registry-Einträge.
* Es beendet **keine** Programme und stoppt **keine** Dienste.
* Es deaktiviert **keine** Sicherheitsfunktionen.
* Es führt **nichts** aus, was es gefunden hat.
* Es überträgt **keine** Daten. Es funktioniert vollständig ohne Internet.
* Es sammelt **keine** Passwörter, Cookies, Tokens oder Zugangsdaten.

Die Durchsetzung sitzt an drei Stellen:

1. `IRegistryReader` besitzt **keine einzige Schreiboperation**. Schreibzugriff
   ist nicht abgeschaltet — er existiert im Typsystem nicht.
2. Dateien werden ausschließlich mit `FileAccess.Read` geöffnet und für Lesen,
   Schreiben und Löschen freigegeben, damit die Prüfung nie ein fremdes Programm
   blockiert.
3. Ein Architekturtest (`ReadOnlyGuaranteeTests`) durchsucht den Quelltext jedes
   Projekts nach Prozessstarts, Netzwerktypen und verändernden Datei- oder
   Registry-Aufrufen. Wer einen einbaut, bricht den Build.

Details in [`docs/safety.md`](docs/safety.md).

## Verwendung

```
Hoong-systemScope scan              [--categories …] [--all-users]
                                    [--no-hash] [--no-signature]
                                    [--min-risk Medium]
                                    [--format Json|Text|Csv] [--output datei]
                                    [--baseline vorher.json] [--quiet]
Hoong-systemScope compare           --left a.json --right b.json
Hoong-systemScope report            --input scan.json [--format …]
Hoong-systemScope list-collectors
```

Typischer Ablauf:

```powershell
# Basisaufnahme eines Systems, dem du vertraust
Hoong-systemScope scan --format Json --output baseline.json

# ... später, nach einer Installation oder einem Verdacht ...
Hoong-systemScope scan --baseline baseline.json
```

Der Vergleich meldet einen ausgetauschten Autostart-Eintrag als **eine
Änderung mit den betroffenen Feldern**, nicht als eine Entfernung plus eine
unabhängige Neuaufnahme. Genau dafür ist die Eintragsidentität so gebaut, dass
sie die dahinterliegende Datei nicht einbezieht.

### Rechte

Ohne administrative Rechte sind Teile von `HKEY_LOCAL_MACHINE`, der
Dienstdatenbank und fremde Benutzerprofile nicht lesbar. Der Scan bricht
deswegen **nicht** ab: er vermerkt die Lücke, und der Textbericht führt sie
**vor** den Funden auf. Wer nicht weiß, dass ein Bericht unvollständig ist,
liest das Fehlen eines Fundes als Beweis.

Registry-Hives nicht angemeldeter Benutzer werden **nicht** eingehängt — das
wäre eine Systemänderung. Sie erscheinen stattdessen als ausgewiesene Lücke.

### Exit Codes

| Code | Bedeutung |
|-----:|-----------|
| 0 | Scan vollständig, nichts oberhalb der Schwelle |
| 1 | Scan vollständig, Funde oberhalb der Schwelle (bzw. Änderungen beim Vergleich) |
| 2 | Scan gelaufen, aber mindestens ein Collector ist gescheitert |
| 3 | Fehler im Aufruf |
| 4 | Scan konnte nicht laufen |
| 5 | Abgebrochen |

Der Unterschied zwischen `1` und `2` ist Absicht: „etwas gefunden" und „nicht
alles gesehen" sind verschiedene Lagen, und ein Skript, das sie vermengt,
reagiert auf die falsche.

## Was untersucht wird

| Collector | Bereich |
|---|---|
| `registry-run` | `Run`, `RunOnce`, `RunOnceEx`, `RunServices` unter HKLM und den Benutzerhives |
| `startup-folder` | Autostart-Ordner, Verknüpfungen auf ihr Ziel aufgelöst |
| `services` | Win32-Dienste mit Starttyp, Konto und Imagepfad |
| `drivers` | Kernel- und Dateisystemtreiber |
| `scheduled-tasks` | Geplante Aufgaben **inklusive versteckter**, mit Aktionen und Principal |
| `winlogon` | `Userinit`, `Shell`, `Taskman`, `GinaDLL`, `Notify` |
| `appinit-dlls` | `AppInit_DLLs` und `AppCertDlls` |
| `ifeo` | Debugger-Hijacks und Silent-Process-Exit-Monitore |
| `shell-extensions` | Shell-Erweiterungen, Kontextmenü-Handler, Browser Helper Objects |
| `winsock` | Layered Service Provider und Namespace-Provider |
| `hosts` | Nicht-Standard-Einträge der `hosts`-Datei |
| `processes` | Laufende Prozesse mit Pfad, Kommandozeile und Elternprozess |

Registry-Orte werden in **beiden** Ansichten gelesen, 64- und 32-Bit. Ein
32-Bit-Installer schreibt nach `WOW6432Node`, und wer nur eine Ansicht liest,
übersieht einen erheblichen Teil eines typischen Systems.

## Risikobewertung

Jeder Punkt im Risikoscore stammt aus genau einer benannten Regel, und die
Begründungen hängen am Eintrag. Der Textbericht schreibt sie aus:

```
[Medium/37] RegistryRun: Updater
  Location   : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  File       : C:\Users\alice\AppData\Local\Temp\updater.exe
  Signature  : Unsigned
  Why this was rated:
    +25   The program runs from a temporary directory, which is unusual for
          something that persists.
    +12   The file carries no digital signature.
```

Die Gewichte sind bewusst zurückhaltend. Eine gewöhnliche signierte Anwendung
erreicht 0 Punkte, eine Microsoft-Binärdatei unter `System32` wird vor dem
Abschneiden negativ bewertet. Für ein `High` braucht es normalerweise zwei bis
drei unabhängige Indikatoren — ein Werkzeug, das das halbe System rot färbt,
erzieht seine Benutzer dazu, es zu ignorieren.

Alle Regeln und Schwellen: [`docs/risk-rules.md`](docs/risk-rules.md).

## Bauen

```bash
dotnet build Hoong-systemScope.sln -c Release
dotnet test  Hoong-systemScope.sln -c Release
dotnet publish src/Hoong-systemScope.Cli -c Release -r win-x64 --self-contained false
```

Benötigt das .NET 8 SDK. `Core`, `Collectors`, `Analysis` und `Export` zielen auf
plattformneutrales `net8.0`; nur `Windows` und `Cli` auf `net8.0-windows`. Alle
Tests laufen deshalb auf jedem Buildagenten, auch unter Linux.

## Architektur

```
                       Core (net8.0)
             Modelle · Enums · Abstraktionen
              ↑        ↑        ↑        ↑
    Collectors    Analysis   Export   Windows (net8.0-windows)
     (net8.0)     (net8.0)  (net8.0)      │
          ↑            ↑        ↑         │
          └────────────┴────────┴─────────┴── Cli (net8.0-windows)
```

Der entscheidende Schnitt: **die Collectors enthalten die Scan-Logik, aber
keinen Windows-Code.** Sie sprechen ausschließlich `Core`-Abstraktionen an.
`Hoong-systemScope.Windows` liefert die echten Implementierungen, Tests liefern
In-Memory-Fakes. Das macht die gesamte Sammel- und Bewertungslogik
plattformunabhängig testbar — und es ist die Naht, an der eine spätere WPF- oder
WinUI-Oberfläche andockt: sie ersetzt `Cli` als Kompositionswurzel und sonst
nichts.

Mehr dazu in [`docs/architecture.md`](docs/architecture.md).

## Namensregel

`Hoong-systemScope` enthält einen Bindestrich, der in C#-Bezeichnern nicht
erlaubt ist. Solution, Verzeichnisse, Projektdateien und Assemblynamen
verwenden ihn trotzdem (`Hoong-systemScope.Core`); Namespaces benutzen
`HoongSystemScope.Core` über ein explizites `RootNamespace`. Die Namensregel
gilt überall dort, wo sie technisch möglich ist.
