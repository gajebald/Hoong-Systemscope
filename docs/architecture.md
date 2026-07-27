# Architektur

## Schichten

```
                       Core (net8.0)
             Modelle · Enums · Abstraktionen
        ↑         ↑        ↑        ↑         ↑
 Collectors  Analysis  Export  ViewModels  Windows (net8.0-windows)
  (net8.0)   (net8.0) (net8.0)  (net8.0)      │
        └─────────┴────────┴────────┬─────────┘
                                    │
                          App (net8.0-windows)
                     Kompositionswurzel · ScanRunner
                              ↑          ↑
                    Cli (Konsole)   Wpf (Desktop)
```

`Core` kennt niemanden. `App` ist die einzige Kompositionswurzel; beide
Oberflächen bauen darauf auf und enthalten selbst keine Verdrahtung.

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


## Die Oberfläche

Der Schnitt, der die Collectors testbar macht, trägt auch die Oberfläche.

`Hoong-systemScope.ViewModels` zielt auf plattformneutrales `net8.0` und
referenziert **kein** UI-Framework. Es enthält die vollständige
Darstellungslogik — Scan-Ablauf, Fortschritt, Abbruch, Filterung, Auswahl,
Baseline-Vergleich und Export — und arbeitet gegen `IScanService`. Deshalb
liegen 34 Tests darauf, die auf jedem Buildagenten laufen.

`Hoong-systemScope.Wpf` ist entsprechend dünn: XAML, drei Konverter und die
Dateidialoge. Dialoge sind das Einzige, was sich nicht sinnvoll aus einem
ViewModel heraus machen lässt, ohne ein UI-Framework hineinzuziehen; was sie
auslösen, delegieren sie sofort zurück ins ViewModel.

### Warum das so geschnitten ist

Kein Linux-SDK liefert die Windows-Desktop-Targets mit, die WPF braucht. Ein
Buildagent ohne Windows kann `UseWPF` also nicht übersetzen. Läge die
Darstellungslogik im WPF-Projekt, wäre sie damit auch nicht prüfbar. So bleibt
nur XAML unverifizierbar — und XAML ist der Teil, bei dem ein Fehler beim ersten
Start sofort auffällt, während ein Filterfehler still das Falsche anzeigt.

Für den Linux-Build gibt es deshalb `Hoong-systemScope.Linux.slnf`, einen
Solution-Filter ohne das WPF-Projekt. Der Windows-CI-Job baut die vollständige
Solution.

### Was die Oberfläche nicht kann

`IScanService` kennt fünf Operationen: scannen, rendern, laden, speichern. Keine
davon verändert das untersuchte System. Eine Schaltfläche zum Entfernen oder
Deaktivieren ließe sich nicht ergänzen, ohne zuerst diesen Vertrag zu erweitern
— und ein Test in `ViewModels.Tests` prüft, dass kein Mitglied des ViewModels
oder des Vertrags nach `delete`, `remove`, `disable`, `kill`, `terminate`,
`quarantine`, `fix` oder `repair` benannt ist.

### Zwei Fallen, die hier vermieden sind

**Fortschritt.** `System.Progress<T>` stellt seine Rückrufe an den bei der
Konstruktion erfassten Synchronisationskontext zu. Im Test bedeutet das, dass
Fortschrittsmeldungen erst eintreffen, wenn der Scan längst fertig ist. Für eine
rein kosmetische Fortschrittszeile bringt diese Asynchronität nichts und kostet
Prüfbarkeit, deshalb `SynchronousProgress<T>`.

**Thread-Affinität.** Die Fortsetzung nach `await` im Scan ruft `Load`, und das
verändert `ObservableCollection`. WPF verbietet das außerhalb des Dispatchers.
Genau dort steht deshalb bewusst **kein** `ConfigureAwait(false)` — anders als im
Rest der Codebasis, wo es überall gesetzt ist.
