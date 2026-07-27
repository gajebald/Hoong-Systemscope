# Architektur

## Schichten

```
                       Core (net8.0)
             Modelle · Enums · Abstraktionen
              ↑        ↑        ↑        ↑
    Collectors    Analysis   Export   Windows (net8.0-windows)
     (net8.0)     (net8.0)  (net8.0)      │
          ↑            ↑        ↑         │
          └────────────┴────────┴─────────┴── Cli (net8.0-windows)
```

`Core` kennt niemanden. `Cli` ist die einzige Kompositionswurzel.

## Der entscheidende Schnitt

Die Collectors enthalten die vollständige Scan-Logik und **keinen einzigen
Windows-Aufruf**. Sie sprechen ausschließlich die Abstraktionen aus
`Core/Abstractions` an:

| Abstraktion | Windows-Implementierung |
|---|---|
| `IRegistryReader` | `WindowsRegistryReader` über `Microsoft.Win32` |
| `IFileSystemProbe` | `WindowsFileSystemProbe` |
| `IFileMetadataProvider` | `WindowsFileMetadataProvider` über `FileVersionInfo` |
| `IHashProvider` | `Sha256HashProvider` |
| `ISignatureVerifier` | `AuthenticodeSignatureVerifier` über WinTrust und CryptCAT |
| `IServiceCatalog` | `RegistryServiceCatalog` |
| `IScheduledTaskProvider` | `TaskSchedulerProvider` über `ITaskService` |
| `IProcessProvider` | `WindowsProcessProvider` |
| `IShortcutResolver` | `WindowsShortcutResolver` über `IShellLinkW` |
| `IEnvironmentProbe` | `WindowsEnvironmentProbe` |
| `ISystemClock` | `SystemClock` |

Das hat drei Folgen:

1. **Testbarkeit.** In-Memory-Fakes ersetzen jede Abstraktion, die gesamte
   Sammel- und Bewertungslogik läuft auf jedem Buildagenten.
2. **Auditierbarkeit.** Ein Collector bekommt keinen Umgebungszugriff außer über
   den `ScanContext`. Was nicht daran hängt, existiert für ihn nicht.
3. **Erweiterbarkeit.** Eine WPF- oder WinUI-Oberfläche ersetzt `Cli` als
   Kompositionswurzel und sonst nichts.

## Ablauf eines Scans

```
Cli
 └─ ScanRunner
     ├─ baut ScanContext (Optionen + Abstraktionen + Diagnose-Senke)
     ├─ baut FileFactsCache
     └─ ScanOrchestrator.RunAsync
         ├─ pro Collector: CollectAsync → rohe Einträge
         ├─ EntryEnricher: Pfad → Metadaten → SHA-256 → Signatur
         └─ ScanResult (Einträge + Lücken + Collector-Bilanz)
     └─ RiskEngine.Evaluate → Score, Stufe und Begründungen
     └─ IReportWriter → JSON, Text oder CSV
```

### Warum die Collectors nacheinander laufen

Sie sind auf Registry und COM I/O-gebunden, wo Parallelität wenig bringt und
Determinismus kostet. Die Zeit geht in die Dateiarbeit dahinter — und die läuft
parallel.

### Warum das Enrichment ausgelagert ist

Ein Collector hört bei „hier ist ein Pfad" auf. Damit bleibt er ein kleines,
prüfbares Stück Registry- oder API-Durchlauf, und die teure Arbeit passiert
einmal pro Datei statt einmal pro Nennung dieser Datei.

`FileFactsCache` dedupliziert über den aufgelösten Pfad. Auf einem typischen
System steht hinter Dutzenden Diensten dieselbe `svchost.exe`; sie einmal pro
Dienst zu prüfen machte aus einem Scan von fünfzehn Sekunden mehrere Minuten.

Der Cache speichert ein `Lazy<Task<FileFacts>>`, nicht den Task selbst.
`ConcurrentDictionary.GetOrAdd` darf seine Factory unter Last mehrfach aufrufen
und garantiert nur, dass ein Ergebnis gespeichert wird — den Task direkt
abzulegen würde also weiterhin mehrere Hashes derselben Datei starten und die
Deduplizierung stillschweigend aushebeln.

## Identität eines Eintrags

`ScanEntry.Id` ist ein gekürzter SHA-256 über Kategorie, Ort und Name — in
Normalform, ohne Groß-Klein-Unterschiede und ohne abschließende Trennzeichen.

Die dahinterliegende Datei geht **nicht** ein. Genau deshalb kann der
Baseline-Vergleich „dieser Autostart-Eintrag zeigt jetzt auf eine andere
Binärdatei" als **eine Änderung mit den betroffenen Feldern** melden statt als
eine Entfernung plus eine unabhängige Neuaufnahme. Der erste Fall ist der
interessante; der zweite wäre Rauschen, in dem er untergeht.

Aus demselben Grund vergleicht `BaselineComparer` keine Risikoscores: das
Nachjustieren eines Regelgewichts darf nicht jeden Eintrag des Systems als
verändert erscheinen lassen.

## Fehlerverhalten

Ein Diagnosewerkzeug, das bei fehlenden Rechten abbricht, ist für den
Standardbenutzer nutzlos — und das ist der Fall, in dem man es am ehesten
braucht.

* Ein scheiternder Collector wird zu einem `ScanError`; die übrigen laufen weiter.
* Ein nicht lesbarer Registry-Schlüssel wird zu einer Warnung mit Ortsangabe.
* Ein Abbruch liefert das bisher Gesammelte.
* Der Textbericht führt die Lücken **vor** den Funden auf.

## Neuen Collector hinzufügen

1. Von `CollectorBase` ableiten, `Id`, `Description` und `Category` angeben.
2. `CollectAsync` implementieren, ausschließlich über den `ScanContext`.
3. Einträge mit `CreateEntry` bauen — das erledigt Identität, Kommandozeilen-
   Zerlegung, Redaktion und rundll32-Erkennung einheitlich.
4. Nicht lesbare Orte über `TryOpenKey` und `TryGetSubKeyNames` behandeln, damit
   fehlende Rechte zu einer Lücke werden statt zu einer Ausnahme.
5. In `ScanServices.AddHoongSystemScope` registrieren.
6. Tests gegen `ScanHarness` schreiben, einschließlich des Falls ohne Rechte.
